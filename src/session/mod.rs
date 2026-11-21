//! Browser sessions: an opaque identifier in a cookie, a server-side record of each session family, renewal that
//! rotates the identifier, inspection, and revocation.
//!
//! A sign-in opens a session family ([`passkey::SignIn::open`](crate::passkey::SignIn::open)): the commit that
//! consumes the challenge also writes the record of the family. Only the accepted commit releases the identifier
//! ([`Opening::release`]). A sign-in that presents the current session of the browser ends that family in the same
//! commit, so the identifier changes at each sign-in and at each fresh user verification, and the old one refuses.
//!
//! An identifier is [`IDENTIFIER_BYTES`] bytes: a locator of the account, the number of the family, and a secret of 32
//! random bytes. The cookie holds it as [`IDENTIFIER_CHARS`] base64url characters, with no signed claim. The record
//! key holds the locator and a digest of the family number under the authority and the audience, and the record holds
//! the HMAC-SHA256 tag of the key under the secret. Thus the store keeps no usable identifier, and [`Sessions::check`]
//! finds the record with one keyed read and compares the tag in constant time.
//!
//! A [`Policy`] gives three times. A family ends at its lifetime after its sign-in, and no renewal extends it. Each
//! generation ends after the idle time, and a renewal is due after half of it ([`Access::renewal_due`]).
//! [`Sessions::renew`] consumes the generation and writes the next one in one commit. After a renewal, the replaced
//! identifier serves its requests for the grace time, so a request that raced the renewal does not fail, and it cannot
//! renew. A use after the grace time is a sign of a stolen identifier: [`Sessions::check`] gives the commit that ends
//! the family ([`Check::Reused`]).
//!
//! [`Sessions::list`] reads the sessions of an account from one range read, [`Sessions::revoke`] ends one, and
//! [`Sessions::confirm`] checks that a session still holds, for example before each part of a stream. A sign-out ends
//! the own session of a request. The end of another session of the account is a sensitive change, so it needs a
//! fresh user verification ([`Revoker`]).
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::Limits;
//! use rsauthnz::session::{Error, Failure, Identifier, Policy, Sessions};
//! use rsauthnz::store::driver::Driver;
//! use rsauthnz::store::{Profile, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz_conformance::memory::{Memory, Schedule};
//! use rsauthnz_conformance::suite::execute;
//!
//! /// The output of a future of the memory binding, which is ready at its first poll.
//! fn ready<T>(future: impl Future<Output = T>) -> T {
//!     let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
//!         unreachable!("the memory binding does no I/O");
//!     };
//!     output
//! }
//!
//! // A family ends 30 days after its sign-in, and a session with no request for 2 days ends.
//! let policy = Policy {
//!     lifetime: Duration::from_secs(30 * 24 * 60 * 60),
//!     idle: Duration::from_secs(2 * 24 * 60 * 60),
//!     grace: Duration::from_secs(30),
//! };
//! let sessions = Sessions::new(Id::new("acme", "auth")?, Id::new("acme", "app")?, policy, Limits::default())?;
//!
//! // A cookie that is not an identifier refuses before a read.
//! assert_eq!(Identifier::parse(b"c2Vzc2lvbg").err(), Some(Error::Identifier));
//!
//! // The store serves after the start of its commit driver.
//! let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! let mut memory = Memory::new(Schedule::None);
//! let mut driver = Driver::new(Profile::new(memory.declaration())?, Limits::default())?;
//! driver.start(now);
//! while let Some(effect) = driver.effect() {
//!     let output = ready(execute(&mut memory, effect));
//!     driver.give(output)?;
//! }
//!
//! // An identifier of no session refuses after one keyed read.
//! let stranger = Identifier::parse(&[b'A'; 86])?;
//! let refused = ready(sessions.check(&mut memory, &stranger, now)).unwrap_err();
//! assert_eq!(refused, Failure::Refused(Error::Unknown));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroUsize;
use core::time::Duration;

use rscodec::base64::Profile::Url;
use rscrypto::{ChaCha20Rng, SecretBytes};

use crate::account::Fresh;
use crate::cbor::{self, Value};
use crate::crypto;
use crate::evidence::Evidence;
use crate::id::{Action, Audience, Authority, AuthorityVersion, Human, Id, Principal};
use crate::limits::Limits;
use crate::store::driver::{self, Driver, Plan};
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{self, Audit, Change, Dependency, Key, OperationId, Outcome, Proposal, Recovery};

/// The bytes of an identifier: a locator of 16 bytes, a family number of 16 bytes, and a secret of 32 bytes.
pub const IDENTIFIER_BYTES: usize = 64;

/// The base64url characters of an identifier, with no padding.
pub const IDENTIFIER_CHARS: usize = 86;

/// The most records of one page of [`Sessions::list`].
pub const PAGE_MAX: usize = 64;

/// The records of one range read of [`Sessions::list`].
const PAGE: NonZeroUsize = NonZeroUsize::new(PAGE_MAX).expect("the bound is not zero");

/// The name of the record form, the domain of each digest, and the domain of the tags.
const FORM: &str = "rsauthnz.session.1";

/// The audit actions.
const RENEW: &str = "session.renew";
const REVOKE: &str = "session.revoke";
const REUSE: &str = "session.reuse";

/// The times of the sessions of a site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Policy {
    /// The time from the sign-in of a family to its end. No renewal extends it.
    pub lifetime: Duration,
    /// The time from the start of a generation to its end. A session with no renewal in this time ends, and a renewal
    /// is due after half of it.
    pub idle: Duration,
    /// The time after a renewal in which the replaced identifier serves its requests and cannot renew. After it, a use
    /// of that identifier ends the family. Zero ends the family at the first use after the renewal.
    pub grace: Duration,
}

/// The sessions of one audience, whose records one authority owns.
#[derive(Clone, Debug)]
pub struct Sessions {
    authority: Id<Authority>,
    audience: Id<Audience>,
    policy: Policy,
    limits: Limits,
}

impl Sessions {
    /// The sessions of `audience`, the service that accepts them, with records of `authority` and the times of
    /// `policy`. A session of another audience never serves this one, also in the same store. `limits` bound the CBOR
    /// of each record.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Policy`] if the idle time is zero or longer than the lifetime, or the grace time is not shorter than
    /// the idle time. [`Error::Dit`] if this build on this CPU cannot encode an identifier with data-independent
    /// timing, as on Windows aarch64 without `-C target-feature=+dit`.
    pub fn new(
        authority: Id<Authority>,
        audience: Id<Audience>,
        policy: Policy,
        limits: Limits,
    ) -> Result<Self, Error> {
        let valid = !policy.idle.is_zero() && policy.idle <= policy.lifetime && policy.grace < policy.idle;
        valid.ok_or(Error::Policy)?;
        rscodec::with_dit(|_| ()).map_err(|_| Error::Dit)?;
        Ok(Self {
            authority,
            audience,
            policy,
            limits,
        })
    }

    /// The session of `identifier` at `now`, after one keyed read of `store`: [`Check::Active`] for the current
    /// generation, and for the replaced generation within the grace time. [`Check::Reused`] for the replaced generation
    /// after the grace time: submit its proposal, which ends the family, and clear the cookie.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed read, one SHA-256 digest, and at most two
    /// HMAC-SHA256 tags.
    ///
    /// # Errors
    ///
    /// [`Error::Unknown`] if no session of this audience has the identifier, also after a revocation or a sign-in that
    /// replaced the family. [`Error::Ended`] if the idle time or the lifetime of the session passed. [`Error::Record`] if
    /// the record has no valid form, and [`Error::Time`] if `now` has no bound.
    /// [`Failure::Store`] if the read fails.
    pub async fn check<S: Store>(
        &self,
        store: &mut S,
        identifier: &Identifier,
        now: Reading,
    ) -> Result<Check, Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        let key = self.key(identifier.locator(), identifier.family());
        let record = store.read(&key).await.map_err(Failure::Store)?.ok_or(Error::Unknown)?;
        let (session, previous) = self.session(key, &record)?;
        let signed = tagged(&session.key);
        let current = crypto::hmac_sha256_verify(identifier.secret(), &signed, &session.tag);
        let replaced =
            !current && previous.is_some_and(|tag| crypto::hmac_sha256_verify(identifier.secret(), &signed, &tag));
        (current || replaced).ok_or(Error::Unknown)?;
        (latest < session.end).ok_or(Error::Ended)?;
        let generation = if current {
            Generation::Current
        } else if latest < add(session.issued, self.policy.grace)? {
            Generation::Replaced
        } else {
            let (proposal, plan) = self.reused(&session, now)?;
            return Ok(Check::Reused(proposal, plan));
        };
        Ok(Check::Active(Access {
            session,
            generation,
            family: *identifier.family(),
        }))
    }

    /// Proposes the renewal of the current generation of `access` at `now`: the commit consumes the generation and
    /// writes the next one, with a new identifier, in the same family. The family keeps its sign-in and its lifetime.
    /// Submit the proposal with the plan, and give its outcome to [`Renewal::release`]. Two renewals of one generation
    /// commit once: the other one conflicts, and its identifier is then the replaced one.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). One SHA-256 digest and one HMAC-SHA256 tag.
    ///
    /// # Errors
    ///
    /// [`Error::Replaced`] if `access` has the replaced generation, [`Error::Ended`] if the session ends at `now`,
    /// [`Error::Time`] if `now` has no bound, [`Error::Driver`] if the driver does not serve, and
    /// [`Error::Transition`] for the proposal.
    pub fn renew(
        &self,
        access: &Access,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan, Renewal), Error> {
        (access.generation == Generation::Current).ok_or(Error::Replaced)?;
        let session = &access.session;
        let earliest = now.earliest().map_err(Error::Time)?;
        (now.latest().map_err(Error::Time)? < session.end).ok_or(Error::Ended)?;
        let (identifier, tag) = Identifier::draw(session.locator(), &access.family, &session.key, random);
        let mut proposal = self.proposal(operation(random), &session.account, RENEW, &session.key, now)?;
        proposal.read(Dependency::Version(session.key.clone(), session.version.clone()))?;
        let end = add(earliest, self.policy.idle)?.min(session.expires);
        let data = self.record(
            &session.account,
            &session.evidence,
            session.started,
            earliest,
            &tag,
            Some(&session.tag),
        )?;
        let version = self.version(driver.allocate(Kind::Session)?);
        proposal.change(Change::Write {
            key: session.key.clone(),
            version,
            end: Some(end),
            data,
        })?;
        proposal.until(session.end);
        let plan = Plan {
            replaced: vec![session.key.clone()],
            ..Plan::default()
        };
        let renewal = Renewal {
            operation: proposal.operation().id.clone(),
            issued: Issued { identifier, end },
        };
        Ok((proposal, plan, renewal))
    }

    /// Proposes the end of `session` by `by`: the sign-out of the session of a request, the account of the session with
    /// a fresh user verification, or another principal, such as an administrator. `decision` holds the reads of the
    /// decision of the application that `by` can end the session, and the commit reads each one. A stream of the
    /// session stops at its next [`Self::confirm`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Fresh`] for a [`Revoker::Own`] of another session, a [`Revoker::Fresh`] of another account, and a
    /// [`Revoker::Other`] that is the account of the session: the end of another session of the account needs a fresh
    /// user verification. [`Error::Transition`] for the proposal, also for a `decision` that reads more records than
    /// the limits permit.
    pub fn revoke(
        &self,
        session: &Session,
        by: Revoker<'_>,
        decision: &[Dependency],
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan), Error> {
        let account = Principal::Human(session.account.clone());
        let (actor, fresh) = match by {
            Revoker::Own(access) => {
                (access.session.key == session.key).ok_or(Error::Fresh)?;
                (account, None)
            }
            Revoker::Fresh(fresh) => {
                (*fresh.account() == session.account).ok_or(Error::Fresh)?;
                (account, Some(fresh))
            }
            Revoker::Other(actor) => {
                (actor != account).ok_or(Error::Fresh)?;
                (actor, None)
            }
        };
        let audit = Audit {
            actor,
            action: action(REVOKE),
            time: now,
        };
        let request = self.request(&session.key);
        let mut proposal = Proposal::new(operation(random), audit, &request, self.limits)?;
        if let Some(fresh) = fresh {
            fresh.gate(&mut proposal)?;
        }
        decision.iter().try_for_each(|read| proposal.read(read.clone()))?;
        end(&mut proposal, session)?;
        Ok((proposal, Plan::default()))
    }

    /// The sessions of `account` at `now`: one page of the range read of `store` after the key `after`, or from the
    /// first key. A session that ended at `now` is not in the page.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One range read of at most [`PAGE_MAX`] records.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if a record has no valid form, and [`Error::Time`] if `now` has no bound. [`Failure::Store`]
    /// if the read fails.
    pub async fn list<S: Store>(
        &self,
        store: &mut S,
        account: &Id<Human>,
        after: Option<&Key>,
        now: Reading,
    ) -> Result<Page, Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        let prefix = Kind::Session
            .key(&self.locator(account))
            .expect("a key of 17 bytes is valid");
        let records = store.range(&prefix, after, PAGE).await.map_err(Failure::Store)?;
        let next = if records.len() == PAGE_MAX {
            records.last().map(|(key, _)| key.clone())
        } else {
            None
        };
        let mut sessions = Vec::with_capacity(records.len());
        for (key, record) in &records {
            let (session, _) = self.session(key.clone(), record)?;
            // Two accounts can share a locator only by a collision of 128 bits: the record names its account.
            if session.account == *account && latest < session.end {
                sessions.push(session);
            }
        }
        Ok(Page { sessions, next })
    }

    /// Checks that the family of `session` still holds at `now`: its record is in `store`, and it did not end. A renewal
    /// keeps the family, so a stream that started before it continues. Call it before each part of a stream and before
    /// queued output.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed read.
    ///
    /// # Errors
    ///
    /// [`Error::Ended`] if the family ended: a revocation, a sign-in that replaced it, the idle time, or the lifetime.
    /// [`Error::Record`] if the record has no valid form, and [`Error::Time`] if `now` has no bound. [`Failure::Store`]
    /// if the read fails.
    pub async fn confirm<S: Store>(
        &self,
        store: &mut S,
        session: &Session,
        now: Reading,
    ) -> Result<(), Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        let record = store
            .read(&session.key)
            .await
            .map_err(Failure::Store)?
            .ok_or(Error::Ended)?;
        let (current, _) = self.session(session.key.clone(), &record)?;
        (current.account == session.account && latest < current.end).ok_or(Error::Ended)?;
        Ok(())
    }

    /// Adds a new family of the subject of `evidence` to `proposal`, the proposal of a sign-in, and ends the family of
    /// `replaces`. The family starts at the time of the audit of `proposal`.
    pub(crate) fn open(
        &self,
        proposal: &mut Proposal,
        evidence: Evidence,
        replaces: Option<&Access>,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<Opening, Error> {
        let Principal::Human(account) = evidence.subject() else {
            return Err(Error::Principal);
        };
        let account = account.clone();
        if let Some(replaced) = replaces {
            let session = &replaced.session;
            (*session.locator() == self.locator(&session.account)).ok_or(Error::Unknown)?;
            proposal.read(Dependency::Version(session.key.clone(), session.version.clone()))?;
            proposal.change(Change::End(session.key.clone()))?;
        }
        let started = proposal.audit().time.earliest().map_err(Error::Time)?;
        let mut family = [0; 16];
        random.fill_bytes(&mut family);
        let locator = self.locator(&account);
        let key = self.key(&locator, &family);
        let (identifier, tag) = Identifier::draw(&locator, &family, &key, random);
        let end = add(started, self.policy.idle)?;
        let data = self.record(&account, &evidence, started, started, &tag, None)?;
        proposal.read(Dependency::Absent(key.clone()))?;
        let version = self.version(driver.allocate(Kind::Session)?);
        proposal.change(Change::Write {
            key,
            version,
            end: Some(end),
            data,
        })?;
        Ok(Opening {
            operation: proposal.operation().id.clone(),
            evidence,
            issued: Issued { identifier, end },
        })
    }

    /// The proposal that ends the family of `session`, whose replaced identifier came after the grace time. Its
    /// operation identity is a digest of the record at its version, so two checks of one use propose one commit.
    fn reused(&self, session: &Session, now: Reading) -> Result<(Proposal, Plan), Error> {
        let version = cbor::encode(&session.version.to_cbor(), Limits::FORM).map_err(|_| Error::Record)?;
        let id = crypto::sha256_parts(&[FORM.as_bytes(), REUSE.as_bytes(), session.key.as_bytes(), &version]);
        let operation = OperationId::new(&id).expect("32 bytes are a valid operation identity");
        let mut proposal = self.proposal(operation, &session.account, REUSE, &session.key, now)?;
        end(&mut proposal, session)?;
        Ok((proposal, Plan::default()))
    }

    /// A proposal of `account` for `action` on the session `key`.
    fn proposal(
        &self,
        operation: OperationId,
        account: &Id<Human>,
        action_name: &str,
        key: &Key,
        now: Reading,
    ) -> Result<Proposal, Error> {
        let audit = Audit {
            actor: Principal::Human(account.clone()),
            action: action(action_name),
            time: now,
        };
        Ok(Proposal::new(operation, audit, &self.request(key), self.limits)?)
    }

    /// The request of a transition of the session `key`: `[authority, audience, key]`.
    fn request<'k>(&'k self, key: &'k Key) -> Value<'k> {
        Value::Array(vec![
            self.authority.to_cbor(),
            self.audience.to_cbor(),
            Value::Bytes(key.as_bytes()),
        ])
    }

    /// The record form `["rsauthnz.session.1", account, evidence, started, issued, tag, previous tag or null]`, with each
    /// time in nanoseconds since the Unix epoch.
    fn record(
        &self,
        account: &Id<Human>,
        evidence: &Evidence,
        started: Duration,
        issued: Duration,
        tag: &[u8; 32],
        previous: Option<&[u8; 32]>,
    ) -> Result<Box<[u8]>, Error> {
        let nanos = |time: Duration| u64::try_from(time.as_nanos()).map_err(|_| Error::Time(TimeError::Overflow));
        let form = Value::Array(vec![
            Value::Text(FORM),
            account.to_cbor(),
            evidence.to_cbor(),
            Value::Unsigned(nanos(started)?),
            Value::Unsigned(nanos(issued)?),
            Value::Bytes(tag),
            previous.map_or(Value::Null, |tag| Value::Bytes(tag)),
        ]);
        let data = cbor::encode(&form, self.limits).map_err(|_| Error::Record)?;
        Ok(data.into_boxed_slice())
    }

    /// The session of the record `record` under `key`, and the tag of its replaced generation.
    fn session(&self, key: Key, record: &Record) -> Result<(Session, Option<[u8; 32]>), Error> {
        (key.as_bytes().len() == 33).ok_or(Error::Record)?;
        let form = cbor::decode(&record.data, self.limits).map_err(|_| Error::Record)?;
        let Value::Array(items) = &form else {
            return Err(Error::Record);
        };
        let [
            Value::Text(FORM),
            account,
            evidence,
            Value::Unsigned(started),
            Value::Unsigned(issued),
            Value::Bytes(tag),
            previous,
        ] = items.as_slice()
        else {
            return Err(Error::Record);
        };
        let previous = match previous {
            Value::Null => None,
            Value::Bytes(previous) => Some(<[u8; 32]>::try_from(*previous).map_err(|_| Error::Record)?),
            _ => return Err(Error::Record),
        };
        let (started, issued) = (Duration::from_nanos(*started), Duration::from_nanos(*issued));
        let expires = add(started, self.policy.lifetime)?;
        let session = Session {
            key,
            version: record.version.clone(),
            account: Id::from_cbor(account).map_err(|_| Error::Record)?,
            evidence: Evidence::from_cbor(evidence).map_err(|_| Error::Record)?,
            started,
            issued,
            end: add(issued, self.policy.idle)?.min(expires),
            renew: add(issued, self.policy.idle / 2)?,
            expires,
            tag: <[u8; 32]>::try_from(*tag).map_err(|_| Error::Record)?,
        };
        Ok((session, previous))
    }

    /// The locator of `account`: the first 16 bytes of the digest of `account` ([`Self::digest`]). The keys of the
    /// sessions of an account start with it.
    fn locator(&self, account: &Id<Human>) -> [u8; 16] {
        self.digest(account.to_cbor())
    }

    /// The key of a family: [`Kind::Session`], the locator, and the first 16 bytes of the digest of the family number.
    /// The check computes the digest with its own authority and audience, so an identifier of another audience finds
    /// no record, also with the locator that it holds.
    fn key(&self, locator: &[u8; 16], family: &[u8; 16]) -> Key {
        let family = self.digest(Value::Bytes(family));
        Kind::Session
            .key(&[&locator[..], &family].concat())
            .expect("a key of 33 bytes is valid")
    }

    /// The first 16 bytes of the SHA-256 digest of the CBOR form `["rsauthnz.session.1", authority, audience, value]`.
    fn digest(&self, value: Value<'_>) -> [u8; 16] {
        let form = Value::Array(vec![
            Value::Text(FORM),
            self.authority.to_cbor(),
            self.audience.to_cbor(),
            value,
        ]);
        let form = cbor::encode(&form, Limits::FORM).expect("the form of identifiers has no map and no simple value");
        *crypto::sha256(&form).first_chunk().expect("a digest has 32 bytes")
    }

    /// The version of a write: the authority and `value`, a new value of the session counter of the driver.
    fn version(&self, value: u64) -> AuthorityVersion {
        AuthorityVersion::new(self.authority.clone(), &value.to_be_bytes()).expect("an 8-byte coordinate is valid")
    }
}

/// Reads `session` at its version and ends it.
fn end(proposal: &mut Proposal, session: &Session) -> Result<(), Error> {
    proposal.read(Dependency::Version(session.key.clone(), session.version.clone()))?;
    proposal.change(Change::End(session.key.clone()))?;
    Ok(())
}

/// The bytes that the tag of a generation covers: the form and the key of the family. Thus a secret serves no other
/// family.
fn tagged(key: &Key) -> Vec<u8> {
    [FORM.as_bytes(), key.as_bytes()].concat()
}

/// `time` plus `duration`.
fn add(time: Duration, duration: Duration) -> Result<Duration, Error> {
    time.checked_add(duration).ok_or(Error::Time(TimeError::Overflow))
}

/// The audit action `name` of this module.
fn action(name: &str) -> Id<Action> {
    Id::new("rsauthnz", name).expect("each action of this module is a valid identifier")
}

/// A new operation identity: 32 bytes from `random`.
fn operation(random: &mut ChaCha20Rng) -> OperationId {
    let mut id = [0; 32];
    random.fill_bytes(&mut id);
    OperationId::new(&id).expect("32 bytes are a valid operation identity")
}

/// The identifier of a session: the value of its cookie. It is a bearer secret, so `Debug` shows nothing of it, and its
/// memory is cleared when it drops.
pub struct Identifier(SecretBytes<IDENTIFIER_BYTES>);

impl Identifier {
    /// The identifier of the cookie value `text`: [`IDENTIFIER_CHARS`] base64url characters, with no padding. The
    /// decoder has data-independent timing.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Identifier`] if `text` is not the base64url text of [`IDENTIFIER_BYTES`] bytes, and [`Error::Dit`] if
    /// this build on this CPU cannot decode with data-independent timing ([`Sessions::new`] refuses such a build).
    pub fn parse(text: &[u8]) -> Result<Self, Error> {
        (text.len() == IDENTIFIER_CHARS).ok_or(Error::Identifier)?;
        let bytes = SecretBytes::try_fill_with(|bytes: &mut [u8; IDENTIFIER_BYTES]| {
            match rscodec::with_dit(|dit| Url.decode_secret(dit, text, bytes).map(|_| ())) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(Error::Identifier),
                Err(_) => Err(Error::Dit),
            }
        })?;
        Ok(Self(bytes))
    }

    /// The cookie value: [`IDENTIFIER_CHARS`] base64url characters, in memory that is cleared when it drops. The encoder
    /// has data-independent timing.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Dit`] if this build on this CPU cannot encode with data-independent timing ([`Sessions::new`] refuses
    /// such a build).
    pub fn encode(&self) -> Result<SecretBytes<IDENTIFIER_CHARS>, Error> {
        SecretBytes::try_fill_with(|text: &mut [u8; IDENTIFIER_CHARS]| {
            rscodec::with_dit(|dit| {
                Url.encode_secret(dit, self.0.as_bytes(), text)
                    .map(|_| ())
                    .expect("86 characters hold the base64url text of 64 bytes");
            })
            .map_err(|_| Error::Dit)
        })
    }

    /// A new identifier of the family `family` of the locator `locator`, with a secret from `random`, and the tag of
    /// the key `key` under the secret.
    fn draw(locator: &[u8; 16], family: &[u8; 16], key: &Key, random: &mut ChaCha20Rng) -> (Self, [u8; 32]) {
        let Ok(bytes) = SecretBytes::try_fill_with(|bytes: &mut [u8; IDENTIFIER_BYTES]| -> Result<(), !> {
            bytes[..16].copy_from_slice(locator);
            bytes[16..32].copy_from_slice(family);
            random.fill_bytes(&mut bytes[32..]);
            Ok(())
        });
        let identifier = Self(bytes);
        let tag = crypto::hmac_sha256(identifier.secret(), &tagged(key));
        (identifier, tag)
    }

    fn locator(&self) -> &[u8; 16] {
        self.0.as_bytes().first_chunk().expect("an identifier has 64 bytes")
    }

    fn family(&self) -> &[u8; 16] {
        self.0.as_bytes()[16..32]
            .try_into()
            .expect("an identifier has 64 bytes")
    }

    fn secret(&self) -> &[u8; 32] {
        self.0.as_bytes().last_chunk().expect("an identifier has 64 bytes")
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identifier(..)")
    }
}

/// A session family as its record holds it: its account, the evidence of its sign-in, and its times.
#[derive(Clone, Debug)]
pub struct Session {
    key: Key,
    version: AuthorityVersion,
    account: Id<Human>,
    evidence: Evidence,
    started: Duration,
    issued: Duration,
    end: Duration,
    renew: Duration,
    expires: Duration,
    /// The tag of the current generation. It proves nothing without the secret, so it is no secret.
    tag: [u8; 32],
}

impl Session {
    /// The key of the record of the family. It is no secret: it names the family in a listing and in a revocation.
    #[must_use]
    pub const fn key(&self) -> &Key {
        &self.key
    }

    /// The account.
    #[must_use]
    pub const fn account(&self) -> &Id<Human> {
        &self.account
    }

    /// The evidence of the sign-in of the family, such as its method, its time, and its user verification.
    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The version of the record of the family. A renewal changes it.
    pub(crate) const fn version(&self) -> &AuthorityVersion {
        &self.version
    }

    /// The time of the sign-in, since the Unix epoch.
    #[must_use]
    pub const fn started(&self) -> Duration {
        self.started
    }

    /// The time of the start of the current generation: the sign-in, or the last renewal.
    #[must_use]
    pub const fn issued(&self) -> Duration {
        self.issued
    }

    /// The end of the session with no renewal: the end of the current generation, or the end of the family when that
    /// is earlier.
    #[must_use]
    pub const fn end(&self) -> Duration {
        self.end
    }

    /// The end of the family: its sign-in plus the lifetime. No renewal extends it.
    #[must_use]
    pub const fn expires(&self) -> Duration {
        self.expires
    }

    /// The locator in the key.
    fn locator(&self) -> &[u8; 16] {
        self.key.as_bytes()[1..17]
            .try_into()
            .expect("a session key has 33 bytes")
    }
}

/// Which generation of its family an identifier holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Generation {
    /// The current generation.
    Current,
    /// The generation that the last renewal replaced, within the grace time. It serves the request, and it cannot
    /// renew: the browser has the current identifier, or gets it from the response of the renewal.
    Replaced,
}

/// A checked session of one request.
#[derive(Clone)]
pub struct Access {
    session: Session,
    generation: Generation,
    /// The family number of the identifier, which the identifier of a renewal keeps. It is part of a bearer value, so
    /// `Debug` does not show it.
    family: [u8; 16],
}

impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Access")
            .field("session", &self.session)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Access {
    /// The session.
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// The generation of the identifier.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Whether a renewal is due at `now`: the identifier holds the current generation, and half of the idle time
    /// passed. Renew with [`Sessions::renew`], then send the new cookie with the response.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn renewal_due(&self, now: Reading) -> bool {
        self.generation == Generation::Current && now.estimate() >= self.session.renew
    }
}

/// Who ends a session ([`Sessions::revoke`]).
#[derive(Clone, Debug)]
pub enum Revoker<'a> {
    /// The sign-out of the session of the request: `access` is the session that ends.
    Own(&'a Access),
    /// The account of the session, with a fresh user verification, such as at the end of a session of another device.
    /// The commit reads the session of the verification at its version, and its deadline is the end of the
    /// verification.
    Fresh(&'a Fresh),
    /// Another principal, such as an administrator, under the decision of the application. It is never the account of
    /// the session.
    Other(Principal),
}

/// The result of [`Sessions::check`].
#[derive(Debug)]
pub enum Check {
    /// The session serves the request.
    Active(Access),
    /// The identifier is a replaced generation after the grace time: another holder renewed first, so the identifier
    /// can be stolen. Submit the proposal with the plan: it ends the family. Then clear the cookie, and refuse the
    /// request.
    Reused(Proposal, Plan),
}

/// One page of the sessions of an account.
#[derive(Clone, Debug)]
pub struct Page {
    /// The sessions that did not end.
    pub sessions: Vec<Session>,
    /// The key after which the next page starts, or `None` when no records remain.
    pub next: Option<Key>,
}

/// A new identifier and the end of its generation.
pub struct Issued {
    identifier: Identifier,
    end: Duration,
}

impl Issued {
    /// The identifier.
    #[must_use]
    pub const fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// The end of its generation, since the Unix epoch.
    #[must_use]
    pub const fn end(&self) -> Duration {
        self.end
    }

    /// The `Max-Age` of its cookie at `now`: the time from the estimate of `now` to the end of the generation.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn max_age(&self, now: Reading) -> Duration {
        self.end.saturating_sub(now.estimate())
    }
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued").field("end", &self.end).finish_non_exhaustive()
    }
}

/// The session of a proposed sign-in, which only the accepted commit of the proposal releases.
pub struct Opening {
    operation: OperationId,
    evidence: Evidence,
    issued: Issued,
}

impl Opening {
    /// The evidence of the sign-in and its session, if `outcome` is the accepted commit of the proposal, also the
    /// receipt of a lookup of its operation after a lost response. A conflict, a refusal, and an unknown outcome release
    /// nothing. Give the receipt of a lookup as [`Outcome::Accepted`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn release(self, outcome: &Outcome) -> Option<Opened> {
        match outcome {
            Outcome::Accepted(receipt) if *receipt.operation() == self.operation => Some(Opened {
                evidence: self.evidence,
                session: self.issued,
            }),
            _ => None,
        }
    }
}

impl fmt::Debug for Opening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opening")
            .field("operation", &self.operation)
            .field("issued", &self.issued)
            .finish_non_exhaustive()
    }
}

/// An accepted sign-in: its evidence, and the identifier of its session.
#[derive(Debug)]
pub struct Opened {
    /// The evidence of the sign-in.
    pub evidence: Evidence,
    /// The session. Send its identifier in the cookie of the response.
    pub session: Issued,
}

/// The next generation of a proposed renewal, which only the accepted commit of the proposal releases.
pub struct Renewal {
    operation: OperationId,
    issued: Issued,
}

impl Renewal {
    /// The next generation, if `outcome` is the accepted commit of the proposal, also the receipt of a lookup of its
    /// operation after a lost response. Otherwise nothing: after a conflict, check the identifier again.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn release(self, outcome: &Outcome) -> Option<Issued> {
        match outcome {
            Outcome::Accepted(receipt) if *receipt.operation() == self.operation => Some(self.issued),
            _ => None,
        }
    }
}

impl fmt::Debug for Renewal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Renewal")
            .field("operation", &self.operation)
            .field("issued", &self.issued)
            .finish()
    }
}

/// The cause of a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The idle time of the policy is zero or longer than the lifetime, or the grace time is not shorter than the idle
    /// time.
    Policy,
    /// This build on this CPU cannot encode or decode an identifier with data-independent timing. Build with
    /// `-C target-feature=+dit` on Windows aarch64.
    Dit,
    /// The cookie value is not the base64url text of an identifier.
    Identifier,
    /// No session of this audience has the identifier. Treat the request as signed out, and clear the cookie.
    Unknown,
    /// The session ended: its idle time or its lifetime passed, or, for [`Sessions::confirm`], a revocation or a sign-in
    /// ended its family. Treat the request as signed out, and clear the cookie.
    Ended,
    /// The identifier holds the replaced generation, so it cannot renew. Serve the request with no renewal.
    Replaced,
    /// The subject of the evidence of a sign-in is not a human.
    Principal,
    /// A record has no valid form.
    Record,
    /// The time reading has no bound, or a time overflows.
    Time(TimeError),
    /// The commit driver gave no value.
    Driver(driver::Error),
    /// The proposal refuses.
    Transition(transition::Error),
    /// The end of another session of the account needs a fresh user verification of the account ([`Revoker::Fresh`]).
    Fresh,
}

impl Error {
    /// The recovery of the caller: the recovery of the proposal after [`Error::Transition`], and a new user
    /// verification after [`Error::Fresh`]. Refuse each other request: after [`Error::Unknown`] and [`Error::Ended`], as
    /// a request that is signed out.
    #[must_use]
    pub const fn recovery(&self) -> Recovery {
        match self {
            Self::Transition(error) => error.recovery(),
            Self::Fresh => Recovery::Verify,
            _ => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy => f.write_str("the times of the session policy are not valid"),
            Self::Dit => f.write_str("this build cannot handle a session identifier with data-independent timing"),
            Self::Identifier => f.write_str("the cookie value is not a session identifier"),
            Self::Unknown => f.write_str("no session has the identifier"),
            Self::Ended => f.write_str("the session ended"),
            Self::Replaced => f.write_str("the identifier holds a replaced generation"),
            Self::Principal => f.write_str("the subject of a sign-in is not a human"),
            Self::Record => f.write_str("a record has no valid form"),
            Self::Time(error) => write!(f, "the time reading gave no value: {error}"),
            Self::Driver(error) => write!(f, "the commit driver gave no value: {error}"),
            Self::Transition(error) => write!(f, "the proposal refuses: {error}"),
            Self::Fresh => f.write_str("the end of another session of the account needs a fresh user verification"),
        }
    }
}

impl core::error::Error for Error {}

impl From<transition::Error> for Error {
    fn from(error: transition::Error) -> Self {
        Self::Transition(error)
    }
}

impl From<driver::Error> for Error {
    fn from(error: driver::Error) -> Self {
        Self::Driver(error)
    }
}

/// The failure of an operation that reads the store: a refusal, or a failed read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure<E> {
    /// The operation refused.
    Refused(Error),
    /// A read failed. It is a crash of the binding: start the driver again.
    Store(E),
}

impl<E> From<Error> for Failure<E> {
    fn from(error: Error) -> Self {
        Self::Refused(error)
    }
}

impl<E: fmt::Display> fmt::Display for Failure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => error.fmt(f),
            Self::Store(error) => write!(f, "a read of the store failed: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for Failure<E> {}
