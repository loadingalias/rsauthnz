//! The journal rules: functions from a proposal, journal entries, and store reads to decisions.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::{
    Anchor, Body, Consumption, End, Entry, Error, Fact, Floor, History, Mark, Owner, Reads, Role, State, replay, voids,
};
use crate::store::{Kind, Pays, Sequence};
use crate::transition::{Change, Dependency, Key, OperationId, Proposal};

/// The journal entries of a proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entries {
    /// The end entry, durable before the commit, or `None` for a proposal that removes no authority.
    pub end: Option<End>,
    /// The anchors of the creation entry, which follows the commit, or none for a proposal that creates no anchor.
    pub creation: Vec<Anchor>,
}

/// The entries of `proposal`: its facts, its consumption, and the anchors that it creates.
///
/// Each end of a record gives a fact at the version that the proposal read. The kinds that are no authority give no
/// fact: [`Kind::Replay`], [`Kind::ReplayFloor`], [`Kind::Audit`], [`Kind::Outcome`], [`Kind::Intent`],
/// [`Kind::Policy`], and [`Kind::Mark`]. A kind whose consumption pays for nothing ([`Pays::Nothing`]) gives no fact either, because a
/// restore ends each pending record of it. A write gives a fact only when `replaced` names its key: the version that
/// it replaces is dead, as for a session renewal or a grant change. A write whose key `anchors` names creates an anchor with that role. A
/// proposal that creates an anchor and ends one value whose consumption pays for an anchor is a consumption. Its end
/// entry records its transition.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
///
/// # Errors
///
/// [`Error::Proposal`] when `replaced` names no write of a record that the proposal read at a version, `anchors`
/// names no write, a new record of kind [`Kind::ProviderLink`], [`Kind::Recovery`], or [`Kind::Administrator`] has no
/// role, a key of a change names no record kind, or the proposal creates an anchor and ends two values whose
/// consumption pays for an anchor.
pub fn entries(proposal: &Proposal, replaced: &[Key], anchors: &[(Key, Role)]) -> Result<Entries, Error> {
    let read = |key: &Key| {
        proposal.dependencies().iter().find_map(|dependency| match dependency {
            Dependency::Version(read, version) if read == key => Some(version),
            _ => None,
        })
    };
    let writes = |key: &Key| {
        proposal
            .changes()
            .iter()
            .any(|change| matches!(change, Change::Write { key: written, .. } if written == key))
    };
    let declared =
        replaced.iter().all(|key| writes(key) && read(key).is_some()) && anchors.iter().all(|(key, _)| writes(key));
    declared.ok_or(Error::Proposal)?;
    let mut facts = Vec::new();
    let mut values = Vec::new();
    let mut created = Vec::new();
    for change in proposal.changes() {
        let kind = Kind::of(match change {
            Change::Write { key, .. } | Change::End(key) => key,
        })
        .ok_or(Error::Proposal)?;
        match change {
            Change::End(key) => {
                if matches!(
                    kind,
                    Kind::Replay
                        | Kind::ReplayFloor
                        | Kind::Audit
                        | Kind::Outcome
                        | Kind::Intent
                        | Kind::Policy
                        | Kind::Mark
                ) || kind.consumption() == Some(Pays::Nothing)
                {
                    continue;
                }
                let fact = Fact {
                    key: key.clone(),
                    version: read(key).ok_or(Error::Proposal)?.clone(),
                };
                if kind.consumption() == Some(Pays::Anchor) {
                    values.push(fact.clone());
                }
                facts.push(fact);
            }
            Change::Write {
                key,
                version,
                end,
                data,
            } => {
                if replaced.contains(key) {
                    facts.push(Fact {
                        key: key.clone(),
                        version: read(key).ok_or(Error::Proposal)?.clone(),
                    });
                }
                match anchors.iter().find(|(anchor, _)| anchor == key) {
                    Some((_, role)) => created.push(Anchor {
                        key: key.clone(),
                        role: role.clone(),
                        version: version.clone(),
                        end: *end,
                        data: data.clone(),
                    }),
                    None => {
                        let anchor_kind = matches!(
                            kind,
                            Kind::ProviderLink | Kind::Recovery | Kind::Administrator | Kind::AccountState
                        );
                        (!anchor_kind || read(key).is_some()).ok_or(Error::Proposal)?;
                    }
                }
            }
        }
    }
    let consumption = match (created.is_empty(), values.as_slice()) {
        (true, _) | (false, []) => None,
        (false, [value]) => Some(Consumption {
            binding: proposal.operation().binding,
            value: value.clone(),
            dependencies: proposal
                .dependencies()
                .iter()
                .filter_map(|dependency| match dependency {
                    Dependency::Version(key, _) | Dependency::Absent(key) => Some(key.clone()),
                    Dependency::Policy(_) => None,
                })
                .collect(),
            anchors: created.clone(),
        }),
        (false, _) => return Err(Error::Proposal),
    };
    Ok(Entries {
        end: (!facts.is_empty()).then_some(End { facts, consumption }),
        creation: created,
    })
}

/// The last-anchor check of `change`: whether each owner whose anchor the change ends keeps a sign-in method, or the
/// authority an administrator binding.
///
/// It counts the anchors that the journal records as live and that the change does not end: each one of `held`, and
/// each one of a creation entry of `state`, that no fact of `state` ends. It also counts each anchor that the change
/// creates when the change consumes the value that pays for it. A recovery value and a CLI credential do not count.
/// `held` is each anchor of the owners that the store holds, except an anchor whose commit has no creation entry yet.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
///
/// # Errors
///
/// [`Error::Versions`] when a fact and an anchor of one key have versions of two owners.
pub fn keeps_anchor(change: &Entries, held: &[Anchor], state: &State) -> Result<bool, Error> {
    let Some(end) = &change.end else {
        return Ok(true);
    };
    let ends = |key: &Key| end.facts.iter().any(|fact| &fact.key == key);
    let mut journaled: BTreeMap<&Key, &Role> = BTreeMap::new();
    let mut owners: Vec<Owner<'_>> = Vec::new();
    for anchor in held.iter().chain(state.anchors.values()) {
        if !state.ends(&anchor.key, &anchor.version)? {
            journaled.insert(&anchor.key, &anchor.role);
        }
        if ends(&anchor.key) && !owners.contains(&anchor.role.owner()) {
            owners.push(anchor.role.owner());
        }
    }
    let made = |owner: Owner<'_>| {
        end.consumption.is_some()
            && change
                .creation
                .iter()
                .any(|anchor| anchor.role.protects() && anchor.role.owner() == owner)
    };
    Ok(owners.into_iter().all(|owner| {
        made(owner)
            || journaled
                .iter()
                .any(|(key, role)| role.protects() && role.owner() == owner && !ends(key))
    }))
}

/// The reconciliation decision at a start, before the store serves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// The missing creation entries: each commit that created anchors and has no creation entry, with its anchors.
    pub creations: Vec<(OperationId, Vec<Anchor>)>,
    /// A void for each end entry whose fact does not hold in the store: its operation did not commit after the entry.
    /// Append [`Body::Void`] of the sequence under the operation.
    pub voids: Vec<(OperationId, Sequence)>,
}

/// The reconciliation decision for the entries of `history` after its mark, with the reads of the current store.
///
/// A fact does not hold only when its operation did not commit after its entry: facts are monotone, a commit makes
/// its fact hold, and a restore applies each entry that no void cancels. A missing outcome record gives no void: after
/// a restore, or after its retention, it is unknown. A creation entry is missing for a commit that created anchors
/// when the store has its outcome record and `history` has no creation entry of it. The candidates are the
/// consumptions of `history` and each commit of `candidates`, which created anchors with no end entry before it.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse). It is linear in the entries.
///
/// # Errors
///
/// [`Error::Unread`] when `store` lacks a read of a fact key or of the outcome of a candidate, and [`Error::Versions`]
/// for a version of another owner.
pub fn reconcile(
    history: &History,
    store: &Reads,
    candidates: &[(OperationId, Vec<Anchor>)],
) -> Result<Reconciliation, Error> {
    let entries = history.entries();
    let voided = voids(entries);
    let state = replay(entries)?;
    let mut decision = Reconciliation::default();
    let consumptions = entries.iter().filter_map(|entry| match &entry.body {
        Body::End(End {
            consumption: Some(consumption),
            ..
        }) if !voided.contains(&entry.sequence) => Some((&entry.operation, &consumption.anchors)),
        _ => None,
    });
    let mut seen = BTreeSet::new();
    for (operation, anchors) in consumptions.chain(candidates.iter().map(|(operation, anchors)| (operation, anchors))) {
        if seen.insert(operation) && !state.created.contains(operation) && store.outcome(operation)? {
            decision.creations.push((operation.clone(), anchors.clone()));
        }
    }
    for entry in entries {
        if let Body::End(end) = &entry.body
            && !voided.contains(&entry.sequence)
            && !all(&end.facts, |fact| store.holds(fact))?
        {
            decision.voids.push((entry.operation.clone(), entry.sequence));
        }
    }
    Ok(decision)
}

/// Whether `test` holds for each item, or its first error.
fn all<T>(items: &[T], mut test: impl FnMut(&T) -> Result<bool, Error>) -> Result<bool, Error> {
    for item in items {
        if !test(item)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The low-water mark of a snapshot: the mark of the highest entry at or below which the captured state reflects each
/// entry, across all owners. `history` reads the journal after an earlier mark of the same store, and `captured` has
/// the reads of the captured state. The snapshot keeps the mark with its link.
///
/// An end entry is reflected when each of its facts holds, and a creation entry when the state holds each of its
/// anchors, or a fact of `history` ends it, or it has an end and expiry removed it. A void, and an entry that a void cancels, need nothing. A floor is
/// reflected when a later floor of its counter is at least as high, so a restore reads the highest floor of each
/// counter after the mark.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse). It is linear in the entries.
///
/// # Errors
///
/// [`Error::Unread`] when `captured` lacks a read of a key of [`History::keys`], and [`Error::Versions`] for a version
/// of another owner.
pub fn low_water(history: &History, captured: &Reads) -> Result<Mark, Error> {
    let entries = history.entries();
    let voided = voids(entries);
    let state = replay(entries)?;
    // The floors that no later floor of their counter covers, from the last entry back.
    let mut newest = BTreeSet::new();
    let mut later: BTreeMap<Kind, u64> = BTreeMap::new();
    for entry in entries.iter().rev() {
        if let Body::Floor(floor) = entry.body
            && later.get(&floor.kind).is_none_or(|value| *value < floor.value)
        {
            newest.insert(entry.sequence);
            later.insert(floor.kind, floor.value);
        }
    }
    for (index, entry) in entries.iter().enumerate() {
        let reflected = match &entry.body {
            Body::End(end) => voided.contains(&entry.sequence) || all(&end.facts, |fact| captured.holds(fact))?,
            Body::Creation(anchors) => {
                voided.contains(&entry.sequence)
                    || all(anchors, |anchor| {
                        Ok(captured.version(&anchor.key)?.is_some()
                            || anchor.end.is_some()
                            || state.ends(&anchor.key, &anchor.version)?)
                    })?
            }
            Body::Floor(_) => !newest.contains(&entry.sequence),
            Body::Void(_) => true,
        };
        if !reflected {
            return Ok(history.before(index));
        }
    }
    Ok(history.head)
}

/// What a restored store applies before it serves, from the entries after the low-water mark of its snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activation {
    /// End each record whose version is at or below the version of its fact.
    pub facts: Vec<Fact>,
    /// Write each anchor that a creation entry created and that no fact ends.
    pub anchors: Vec<Anchor>,
    /// Raise the counter of each floor past its value.
    pub floors: Vec<Floor>,
    /// End each pending record of these kinds: a ceremony or a short-lived one-use value whose consumption pays for
    /// no anchor. Then set the replay floor as a start does.
    pub ends: Vec<Kind>,
    /// Commit each in-doubt consumption again under its operation identity, in this order, which is journal order.
    /// Each commit writes the outcome record, and reconciliation then writes its creation entry.
    pub completions: Vec<Completion>,
}

/// An in-doubt consumption that a restore commits again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The sequence of its consumption entry.
    pub sequence: Sequence,
    /// The operation identity.
    pub operation: OperationId,
    /// The transition of the consumption.
    pub consumption: Consumption,
}

/// The restore decision for `history`, which reads the journal from the low-water mark of a snapshot. `snapshot` has
/// the reads of the snapshot's state, before the restore applies an entry.
///
/// A consumption entry that no void cancels is in doubt when the snapshot has no outcome record of its operation and
/// `history` has no creation entry of it. A known commit of the same value, which such an outcome record or creation
/// entry shows, excludes it. In journal order, a candidate commits again when no earlier completion spent its value,
/// each anchor that it creates is absent from the restored state, and, for a bootstrap value, the snapshot holds the
/// value and no re-bootstrap entry ended it. A completion removes each other candidate of its value. When a condition
/// does not hold, the value stays consumed. A completion does not compare the versions or the policy that the first
/// attempt read.
///
/// The known commits are the outcome records of the snapshot and the creation entries after the mark. The model does
/// not check the expiry of an outcome record: it is a named limit of the authority-restore model.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse). It is linear in the entries.
///
/// # Errors
///
/// [`Error::Unread`] when `snapshot` lacks a read of [`History::keys`] or [`History::operations`], and
/// [`Error::Versions`] for a version of another owner.
pub fn restore(history: &History, snapshot: &Reads) -> Result<Activation, Error> {
    let entries = history.entries();
    let voided = voids(entries);
    let state = replay(entries)?;
    let mut candidates = Vec::new();
    for entry in entries {
        if let Body::End(End {
            consumption: Some(consumption),
            ..
        }) = &entry.body
            && !voided.contains(&entry.sequence)
        {
            let known = state.created.contains(&entry.operation) || snapshot.outcome(&entry.operation)?;
            candidates.push((entry, consumption, known));
        }
    }
    let mut spent: Vec<&Fact> = candidates
        .iter()
        .filter(|(_, _, known)| *known)
        .map(|(_, consumption, _)| &consumption.value)
        .collect();
    let mut made: Vec<&Key> = Vec::new();
    let mut completions = Vec::new();
    for (entry, consumption, known) in candidates {
        if known || spent.contains(&&consumption.value) {
            continue;
        }
        let absent = all(&consumption.anchors, |anchor| {
            Ok(snapshot.version(&anchor.key)?.is_none()
                && !state.anchors.contains_key(&anchor.key)
                && !state.ends(&anchor.key, &anchor.version)?
                && !made.contains(&&anchor.key))
        })?;
        let value = &consumption.value;
        let held = Kind::of(&value.key) != Some(Kind::Bootstrap)
            || (snapshot.version(&value.key)? == Some(&value.version) && !reboot_ended(entries, &voided, value)?);
        if absent && held {
            spent.push(value);
            made.extend(consumption.anchors.iter().map(|anchor| &anchor.key));
            completions.push(Completion {
                sequence: entry.sequence,
                operation: entry.operation.clone(),
                consumption: consumption.clone(),
            });
        }
    }
    let mut anchors = Vec::new();
    for anchor in state.anchors.values() {
        if !state.ends(&anchor.key, &anchor.version)? {
            anchors.push(anchor.clone());
        }
    }
    Ok(Activation {
        facts: state.facts().collect(),
        anchors,
        floors: state.floors().collect(),
        ends: Kind::ALL
            .into_iter()
            .filter(|kind| kind.consumption() == Some(Pays::Nothing))
            .collect(),
        completions,
    })
}

/// Whether an end entry that no void cancels, and that is no consumption of `value`, ends `value`: the end of the
/// bootstrap value by an owner re-bootstrap.
fn reboot_ended(entries: &[Entry], voided: &BTreeSet<Sequence>, value: &Fact) -> Result<bool, Error> {
    for entry in entries {
        if let Body::End(end) = &entry.body
            && !voided.contains(&entry.sequence)
            && end
                .consumption
                .as_ref()
                .is_none_or(|consumption| consumption.value != *value)
        {
            for fact in &end.facts {
                if fact.key == value.key
                    && super::compare(&value.version, &fact.version)? != core::cmp::Ordering::Greater
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
