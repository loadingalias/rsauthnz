//! The stored form of a journal entry: the canonical CBOR array
//! `["rsauthnz.journal.1", sequence, link, operation, body]`. The body is `[0, facts, consumption or null]` for an
//! end entry, `[1, anchors]` for a creation entry, `[2, sequence]` for a void, and `[3, kind, value]` for a floor.

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use super::{Anchor, Body, Consumption, End, Entry, Fact, Floor, Link, Role};
use crate::cbor::{self, Value};
use crate::id::{AuthorityVersion, Id};
use crate::limits::Limits;
use crate::store::{Kind, Sequence};
use crate::transition::{Key, OperationId};

/// The first item of the stored form. Its number changes with the form.
const FORM: &str = "rsauthnz.journal.1";

/// The stored form of the entry `body` of `operation` with `sequence`, after the entry with the link `link`, within
/// `limits`. A form within `limits` decodes within them, so [`decode`] reads it back.
pub(super) fn encode(
    sequence: Sequence,
    link: &Link,
    operation: &OperationId,
    body: &Body,
    limits: Limits,
) -> Result<Vec<u8>, cbor::Error> {
    let body = match body {
        Body::End(end) => Value::Array(vec![
            Value::Unsigned(0),
            list(&end.facts, fact),
            end.consumption.as_ref().map_or(Value::Null, |consumption| {
                Value::Array(vec![
                    Value::Bytes(&consumption.binding),
                    fact(&consumption.value),
                    Value::Array(
                        consumption
                            .dependencies
                            .iter()
                            .map(|key| Value::Bytes(key.as_bytes()))
                            .collect(),
                    ),
                    list(&consumption.anchors, anchor),
                ])
            }),
        ]),
        Body::Creation(anchors) => Value::Array(vec![Value::Unsigned(1), list(anchors, anchor)]),
        Body::Void(target) => Value::Array(vec![Value::Unsigned(2), Value::Unsigned(target.0)]),
        Body::Floor(floor) => Value::Array(vec![
            Value::Unsigned(3),
            Value::Unsigned(u64::from(floor.kind as u8)),
            Value::Unsigned(floor.value),
        ]),
    };
    let entry = Value::Array(vec![
        Value::Text(FORM),
        Value::Unsigned(sequence.0),
        Value::Bytes(&link.0),
        Value::Bytes(operation.as_bytes()),
        body,
    ]);
    cbor::encode(&entry, limits)
}

/// Reads the stored form `bytes` of an entry: the link that it holds, and the entry. `None` for bytes that are not the
/// form of [`encode`] within `limits`.
pub(super) fn decode(bytes: &[u8], limits: Limits) -> Option<(Link, Entry)> {
    let Value::Array(items) = cbor::decode(bytes, limits).ok()? else {
        return None;
    };
    let [
        Value::Text(FORM),
        Value::Unsigned(sequence),
        Value::Bytes(link),
        Value::Bytes(operation),
        Value::Array(body),
    ] = items.as_slice()
    else {
        return None;
    };
    let body = match body.as_slice() {
        [Value::Unsigned(0), facts, consumption] => Body::End(End {
            facts: read_list(facts, read_fact)?,
            consumption: match consumption {
                Value::Null => None,
                Value::Array(items) => {
                    let [Value::Bytes(binding), value, Value::Array(dependencies), anchors] = items.as_slice() else {
                        return None;
                    };
                    Some(Consumption {
                        binding: <[u8; 32]>::try_from(*binding).ok()?,
                        value: read_fact(value)?,
                        dependencies: dependencies.iter().map(read_key).collect::<Option<_>>()?,
                        anchors: read_list(anchors, read_anchor)?,
                    })
                }
                _ => return None,
            },
        }),
        [Value::Unsigned(1), anchors] => Body::Creation(read_list(anchors, read_anchor)?),
        [Value::Unsigned(2), Value::Unsigned(target)] => Body::Void(Sequence(*target)),
        [Value::Unsigned(3), Value::Unsigned(kind), Value::Unsigned(value)] => Body::Floor(Floor {
            kind: Kind::ALL
                .into_iter()
                .find(|candidate| u64::from(*candidate as u8) == *kind)?,
            value: *value,
        }),
        _ => return None,
    };
    let entry = Entry {
        sequence: Sequence(*sequence),
        operation: OperationId::new(operation).ok()?,
        body,
    };
    Some((Link(<[u8; 32]>::try_from(*link).ok()?), entry))
}

/// The CBOR form of `anchors` within `limits`: the payload of an intent of `Effect::Journal`.
pub(super) fn encode_anchors(anchors: &[Anchor], limits: Limits) -> Result<Vec<u8>, cbor::Error> {
    cbor::encode(&list(anchors, anchor), limits)
}

/// The anchors of the CBOR form `bytes` of [`encode_anchors`], or `None` for another form within `limits`.
pub(super) fn decode_anchors(bytes: &[u8], limits: Limits) -> Option<Vec<Anchor>> {
    read_list(&cbor::decode(bytes, limits).ok()?, read_anchor)
}

fn list<'a, T>(items: &'a [T], form: fn(&'a T) -> Value<'a>) -> Value<'a> {
    Value::Array(items.iter().map(form).collect())
}

fn read_list<T>(value: &Value<'_>, read: fn(&Value<'_>) -> Option<T>) -> Option<Vec<T>> {
    let Value::Array(items) = value else {
        return None;
    };
    items.iter().map(read).collect()
}

fn fact(fact: &Fact) -> Value<'_> {
    Value::Array(vec![Value::Bytes(fact.key.as_bytes()), fact.version.to_cbor()])
}

fn read_fact(value: &Value<'_>) -> Option<Fact> {
    let Value::Array(items) = value else {
        return None;
    };
    let [key, version] = items.as_slice() else {
        return None;
    };
    Some(Fact {
        key: read_key(key)?,
        version: AuthorityVersion::from_cbor(version).ok()?,
    })
}

fn read_key(value: &Value<'_>) -> Option<Key> {
    let Value::Bytes(bytes) = value else {
        return None;
    };
    Key::new(bytes).ok()
}

fn anchor(anchor: &Anchor) -> Value<'_> {
    let (class, owner) = match &anchor.role {
        Role::SignIn(account) => (1, account.to_cbor()),
        Role::Cli(account) => (2, account.to_cbor()),
        Role::Recovery(account) => (3, account.to_cbor()),
        Role::Administrator(authority) => (4, authority.to_cbor()),
        Role::AccountState(account) => (5, account.to_cbor()),
    };
    let end = anchor.end.map_or(Value::Null, |end| {
        Value::Array(vec![
            Value::Unsigned(end.as_secs()),
            Value::Unsigned(u64::from(end.subsec_nanos())),
        ])
    });
    Value::Array(vec![
        Value::Bytes(anchor.key.as_bytes()),
        Value::Array(vec![Value::Unsigned(class), owner]),
        anchor.version.to_cbor(),
        end,
        Value::Bytes(&anchor.data),
    ])
}

fn read_anchor(value: &Value<'_>) -> Option<Anchor> {
    let Value::Array(items) = value else {
        return None;
    };
    let [key, Value::Array(role), version, end, Value::Bytes(data)] = items.as_slice() else {
        return None;
    };
    let role = match role.as_slice() {
        [Value::Unsigned(1), owner] => Role::SignIn(Id::from_cbor(owner).ok()?),
        [Value::Unsigned(2), owner] => Role::Cli(Id::from_cbor(owner).ok()?),
        [Value::Unsigned(3), owner] => Role::Recovery(Id::from_cbor(owner).ok()?),
        [Value::Unsigned(4), owner] => Role::Administrator(Id::from_cbor(owner).ok()?),
        [Value::Unsigned(5), owner] => Role::AccountState(Id::from_cbor(owner).ok()?),
        _ => return None,
    };
    let end = match end {
        Value::Null => None,
        Value::Array(parts) => {
            let [Value::Unsigned(seconds), Value::Unsigned(nanos)] = parts.as_slice() else {
                return None;
            };
            let nanos = u32::try_from(*nanos).ok().filter(|nanos| *nanos < 1_000_000_000)?;
            Some(Duration::new(*seconds, nanos))
        }
        _ => return None,
    };
    Some(Anchor {
        key: read_key(key)?,
        role,
        version: AuthorityVersion::from_cbor(version).ok()?,
        end,
        data: (*data).into(),
    })
}
