//! Durable account revisions. A new key for each revision lets restore complete a second recovery from an older snapshot.

use alloc::{boxed::Box, vec};
use core::num::NonZeroUsize;

use crate::cbor::Value;
use crate::crypto;
use crate::id::{AuthorityVersion, Human, Id};
use crate::passkey::{CREDENTIAL_FORM, Error, Failure, RelyingParty, UserHandle};
use crate::recovery::Passkeys;
use crate::store::driver::{Driver, Plan};
use crate::store::journal::Role;
use crate::store::{Kind, Record, Store};
use crate::transition::{self, Change, Dependency, Key, Proposal};

/// The newest revision sorts first within the scope.
pub(crate) fn key(scope: &[u8; 32], number: u64) -> Key {
    Kind::AccountState
        .key(&[scope.as_slice(), &(!number).to_be_bytes()].concat())
        .expect("a revision key has 41 bytes")
}

fn number(key: &Key) -> Option<u64> {
    let suffix = key.as_bytes().get(33..)?;
    Some(!u64::from_be_bytes(suffix.try_into().ok()?))
}

async fn latest<S: Store>(store: &mut S, scope: &[u8; 32]) -> Result<Option<(Key, Record)>, S::Error> {
    let prefix = Kind::AccountState.key(scope).expect("a scope key has 33 bytes");
    Ok(store.range(&prefix, None, NonZeroUsize::MIN).await?.pop())
}

/// A change from one revision to its successor. A permanent marker preserves the first absence across later writes.
#[derive(Debug)]
pub(crate) struct Revision {
    previous: Key,
    version: Option<AuthorityVersion>,
    next: Key,
    number: u64,
}

impl Revision {
    fn after(scope: &[u8; 32], number: u64, version: Option<AuthorityVersion>) -> Option<Self> {
        let next = number.checked_add(1)?;
        Some(Self {
            previous: key(scope, number),
            version,
            next: key(scope, next),
            number: next,
        })
    }

    /// Read the revision before reading the members that it protects.
    pub(crate) async fn read<S: Store>(store: &mut S, scope: &[u8; 32]) -> Result<Option<Self>, S::Error> {
        let revision = match latest(store, scope).await? {
            None => Self::after(scope, 0, None),
            Some((key, record)) => number(&key)
                .filter(|number| *number != 0)
                .and_then(|number| Self::after(scope, number, Some(record.version))),
        };
        Ok(revision)
    }

    pub(crate) fn guard(&self) -> Dependency {
        match &self.version {
            Some(version) => Dependency::Version(self.previous.clone(), version.clone()),
            None => Dependency::Absent(self.previous.clone()),
        }
    }

    pub(crate) fn write(
        self,
        account: &Id<Human>,
        version: AuthorityVersion,
        data: Box<[u8]>,
        proposal: &mut Proposal,
        plan: &mut Plan,
    ) -> Result<(), transition::Error> {
        proposal.read(self.guard())?;
        if self.version.is_none() {
            proposal.change(Change::Write {
                key: self.previous.clone(),
                version: version.clone(),
                end: None,
                data: Box::default(),
            })?;
            plan.anchors.push((self.previous, Role::AccountState(account.clone())));
        } else {
            proposal.change(Change::End(self.previous))?;
        }
        proposal.read(Dependency::Absent(self.next.clone()))?;
        proposal.change(Change::Write {
            key: self.next.clone(),
            version,
            end: None,
            data,
        })?;
        plan.anchors.push((self.next, Role::AccountState(account.clone())));
        Ok(())
    }
}

/// The scope names one passkey site and user handle. The method generation changes only on full recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Epoch {
    pub(crate) scope: [u8; 32],
    pub(crate) number: u64,
    version: Option<AuthorityVersion>,
    methods: u64,
}

impl Epoch {
    pub(crate) fn key(&self) -> Key {
        key(&self.scope, self.number)
    }

    pub(crate) fn dependency(&self) -> Dependency {
        match &self.version {
            None => Dependency::Absent(self.key()),
            Some(version) => Dependency::Version(self.key(), version.clone()),
        }
    }

    pub(crate) fn holds(&self, record: Option<&Record>) -> bool {
        self.version.as_ref() == record.map(|record| &record.version)
    }

    pub(crate) fn form(&self) -> Value<'_> {
        Value::Array(vec![
            Value::Bytes(&self.scope),
            Value::Unsigned(self.number),
            self.version.as_ref().map_or(Value::Null, AuthorityVersion::to_cbor),
            Value::Unsigned(self.methods),
        ])
    }

    pub(crate) fn parse(value: &Value<'_>) -> Option<Self> {
        let Value::Array(fields) = value else { return None };
        let [
            Value::Bytes(scope),
            Value::Unsigned(number),
            version,
            Value::Unsigned(methods),
        ] = fields.as_slice()
        else {
            return None;
        };
        let version = match version {
            Value::Null if *number == 0 && *methods == 0 => None,
            version if *number != 0 => Some(AuthorityVersion::from_cbor(version).ok()?),
            _ => return None,
        };
        Some(Self {
            scope: (*scope).try_into().ok()?,
            number: *number,
            version,
            methods: *methods,
        })
    }

    pub(crate) fn passkey_prefix(&self) -> Key {
        let digest = if self.methods == 0 {
            self.scope
        } else {
            crypto::sha256_parts(&[b"rsauthnz.passkey.methods.1", &self.scope, &self.methods.to_be_bytes()])
        };
        Kind::Credential.key(&digest).expect("a passkey prefix has 33 bytes")
    }

    pub(crate) fn credential(&self, id: &[u8]) -> Key {
        Key::new(&[self.passkey_prefix().as_bytes(), &crypto::sha256(id)].concat())
            .expect("a credential key has 65 bytes")
    }

    pub(crate) async fn enrollments<S: Store>(&self, store: &mut S) -> Result<Revision, Failure<S::Error>> {
        let scope = crypto::sha256_parts(&[b"rsauthnz.passkey.enrollments.1", &self.scope]);
        Ok(Revision::read(store, &scope)
            .await
            .map_err(Failure::Store)?
            .ok_or(Error::Record)?)
    }

    pub(crate) fn advance(
        &self,
        rp: &RelyingParty,
        account: &Id<Human>,
        policy: Passkeys,
        proposal: &mut Proposal,
        plan: &mut Plan,
        driver: &mut Driver,
    ) -> Result<Self, Error> {
        let serial = driver.allocate(Kind::AccountState)?;
        let version = rp.version(serial);
        let revision = Revision::after(&self.scope, self.number, self.version.clone()).ok_or(Error::Full)?;
        let next = Self {
            scope: self.scope,
            number: revision.number,
            version: Some(version.clone()),
            methods: match policy {
                Passkeys::Keep => self.methods,
                Passkeys::End => serial,
            },
        };
        revision.write(account, version, next.methods.to_be_bytes().into(), proposal, plan)?;
        Ok(next)
    }
}

impl RelyingParty {
    pub(crate) fn scope(&self, handle: &UserHandle) -> [u8; 32] {
        self.digest(CREDENTIAL_FORM, &handle.to_bytes())
    }

    pub(crate) async fn epoch<S: Store>(&self, store: &mut S, handle: &UserHandle) -> Result<Epoch, Failure<S::Error>> {
        let scope = self.scope(handle);
        let Some((key, record)) = latest(store, &scope).await.map_err(Failure::Store)? else {
            return Ok(Epoch {
                scope,
                number: 0,
                version: None,
                methods: 0,
            });
        };
        let number = number(&key).filter(|number| *number != 0).ok_or(Error::Record)?;
        let methods = u64::from_be_bytes(record.data.as_ref().try_into().map_err(|_| Error::Record)?);
        Ok(Epoch {
            scope,
            number,
            version: Some(record.version),
            methods,
        })
    }
}
