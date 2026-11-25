//! Trust snapshots: the workload trust of an authority as one signed snapshot, which a remote verifier installs and
//! refreshes with no lookup for each request.
//!
//! The authority publishes a snapshot. [`Draft::read`] reads each issuer record and each registration record of the
//! store, custody signs [`Draft::to_be_signed`] with the trust root, and [`Draft::finish`] gives the snapshot: a
//! `COSE_Sign1` whose payload holds the authority, the time of the issue, each issuer with its current and previous
//! key, its audiences, and its ceiling, and the generation and the revoked credentials of each workload. The root is a
//! [`Handle`]: an SLH-DSA root or a composite key. The signed bytes start with the CBOR array `["Signature1", ...]`, so
//! they never parse as the DER `TBSCertificate` that the same root signs.
//!
//! A verifier holds a [`Trust`]. The host declares the [`Freshness`]: the maximum age of a snapshot, the largest
//! uncertainty of a time reading, the revocation propagation objective, and the least time between two fetches. The
//! freshness of a snapshot comes from its signed time of issue, not from the time of its fetch. [`Trust::refresh`]
//! says when to fetch, and it gives one [`Ticket`] at a time, so concurrent requests make one fetch. The host fetches
//! with its own I/O and gives the bytes to [`Trust::install`], or the failure to [`Trust::fail`]. The core starts no
//! task.
//!
//! [`Trust::view`] gives the installed snapshot while it is fresh. A [`View`] gives the issuer of a credential and
//! checks its registration ([`View::admits`]), as [`workload::admits`] does with the store. Its reuse ends at
//! [`View::end`]: the issue plus the maximum age. A verifier with no refresh accepts a revoked credential for at most
//! [`Profile::residual`] after the issue of its snapshot.
//!
//! Each install is monotonic: a snapshot older than the installed one refuses, and so does another snapshot with the
//! same time of issue. The trust keeps the latest time that it saw, from each reading and from each snapshot, so a
//! wall-clock rollback of the injected time does not make an ended snapshot serve again.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use crate::cbor::{self, Value};
use crate::cose::{self, Key, Sign1};
use crate::credential::{self, Serial, Subject};
use crate::crypto;
use crate::custody::Handle;
use crate::id::{Authority, Id, Workload};
use crate::limits::{Limit, Limits, SignatureBudget};
use crate::store::driver::PAGE;
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::workload::{self, Admitted, Issuer, Registration};

/// The name of the payload form of a snapshot.
const FORM: &str = "rsauthnz.trust.snapshot.1";

/// The tag of a `COSE_Sign1` (RFC 9052 section 2).
const SIGN1_TAG: u64 = 18;

/// The times that the host declares for its snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Freshness {
    /// The time after its issue at which a snapshot ends. A refresh is due after half of it.
    pub max_age: Duration,
    /// The largest uncertainty bound of a time reading. A reading with a larger bound, or with no bound, refuses.
    pub uncertainty: Duration,
    /// The revocation propagation objective: the longest time from the issue of a snapshot to the end of its reuse at
    /// each verifier. The maximum age plus the uncertainty must be within it.
    pub propagation: Duration,
    /// The least time from the start of a fetch to the start of the next one, after a failure or with no answer. At
    /// most half of the maximum age.
    pub retry: Duration,
}

/// The trust of a verifier: the authority of its snapshots, its root, its freshness, and the limits of each snapshot.
#[derive(Clone, Debug)]
pub struct Profile {
    authority: Id<Authority>,
    root: Handle,
    freshness: Freshness,
    limits: Limits,
}

impl Profile {
    /// The trust in the snapshots of `authority` that `root` signs, with `freshness`. `limits` bound the bytes, the
    /// items, and the issuer keys ([`Limits::keys`]) of each snapshot, and its signature checks.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Freshness`] if the maximum age or the retry time is zero, the retry time is more than half of the
    /// maximum age, or the maximum age plus the uncertainty is past the propagation objective.
    pub fn new(authority: Id<Authority>, root: Handle, freshness: Freshness, limits: Limits) -> Result<Self, Error> {
        let reach = freshness.max_age.checked_add(freshness.uncertainty);
        let valid = !freshness.max_age.is_zero()
            && !freshness.retry.is_zero()
            && freshness.retry <= freshness.max_age / 2
            && reach.is_some_and(|reach| reach <= freshness.propagation);
        valid.ok_or(Error::Freshness)?;
        Ok(Self {
            authority,
            root,
            freshness,
            limits,
        })
    }

    /// The residual window of offline use: the maximum age plus the uncertainty. A verifier that gets no new snapshot
    /// accepts a credential that a revocation ended for at most this time after the issue of its snapshot.
    #[must_use]
    pub const fn residual(&self) -> Duration {
        self.freshness.max_age.saturating_add(self.freshness.uncertainty)
    }
}

/// The installed trust of a verifier, and the state of its refresh. It is `Sync`: a server shares it in an `RwLock`, so
/// that each check takes [`Self::view`] under a read lock, and only [`Self::refresh`], [`Self::install`], and
/// [`Self::fail`] take the write lock.
#[derive(Debug)]
pub struct Trust {
    profile: Profile,
    installed: Option<Snapshot>,
    /// The latest time that the trust saw, in nanoseconds since the Unix epoch: the earliest time of each reading, and
    /// the issue of each snapshot. It only grows.
    floor: AtomicU64,
    /// The fetch in flight, and the time of its start.
    fetch: Option<(Ticket, Duration)>,
    /// The start of the last fetch that failed.
    failed: Option<Duration>,
    tickets: u64,
}

/// The identity of one fetch of a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ticket(u64);

/// What the host does after [`Trust::refresh`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refresh {
    /// Fetch a snapshot, and give its bytes to [`Trust::install`], or its failure to [`Trust::fail`], with the ticket.
    Fetch(Ticket),
    /// A fetch is in flight, or the last one failed less than the retry time ago. Fetch nothing.
    Pending,
    /// The installed snapshot is not due for a refresh.
    Fresh,
}

impl Trust {
    /// The trust of `profile`, with no snapshot. Each [`Self::view`] refuses until the first install.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn new(profile: Profile) -> Self {
        Self {
            profile,
            installed: None,
            floor: AtomicU64::new(0),
            fetch: None,
            failed: None,
            tickets: 0,
        }
    }

    /// Whether to fetch a snapshot at `now`. A refresh is due with no snapshot, and after half of the maximum age of
    /// the installed one. One fetch is in flight at a time: each other call gives [`Refresh::Pending`] until the
    /// install, the failure, or the retry time after its start.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Time`] and [`Error::Uncertain`] for a reading with no bound or a larger bound than the declared
    /// uncertainty.
    pub fn refresh(&mut self, now: Reading) -> Result<Refresh, Error> {
        let now = self.time(now)?;
        let retry = self.profile.freshness.retry;
        let waits = |start: Duration| start.checked_add(retry).is_none_or(|next| now < next);
        if self.fetch.is_some_and(|(_, start)| waits(start)) || self.failed.is_some_and(waits) {
            return Ok(Refresh::Pending);
        }
        let half = self.profile.freshness.max_age / 2;
        let due = self
            .installed
            .as_ref()
            .is_none_or(|snapshot| snapshot.issued.checked_add(half).is_none_or(|due| now >= due));
        if !due {
            return Ok(Refresh::Fresh);
        }
        self.tickets = self.tickets.checked_add(1).ok_or(Error::Time(TimeError::Overflow))?;
        let ticket = Ticket(self.tickets);
        self.fetch = Some((ticket, now));
        Ok(Refresh::Fetch(ticket))
    }

    /// Installs the snapshot `bytes` of the fetch `ticket` at `now`. The check verifies the signature of the root
    /// before it reads the payload. Then it refuses a snapshot of another authority, an older snapshot, another
    /// snapshot with the same time of issue, a snapshot from after `now`, and a snapshot past its maximum age. Only
    /// then does it make the issuer keys. A refusal keeps the installed snapshot, and it counts as a failed fetch.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One signature check of the root, and one trusted key for
    /// each issuer key.
    ///
    /// # Errors
    ///
    /// [`Error::Ticket`] if `ticket` is not the fetch in flight. [`Error::Cose`] if the snapshot is not a
    /// `COSE_Sign1` within the limits, [`Error::Signature`] if the root did not sign it, [`Error::Form`] if the payload
    /// is not the form of a snapshot, and [`Error::Authority`], [`Error::Rollback`], [`Error::Inconsistent`],
    /// [`Error::Future`], and [`Error::Stale`] as above. [`Error::Limit`] for more issuer keys than [`Limits::keys`],
    /// and [`Error::Time`] and [`Error::Uncertain`] for the reading.
    pub fn install(&mut self, ticket: Ticket, bytes: &[u8], now: Reading) -> Result<(), Error> {
        let (current, start) = self.fetch.ok_or(Error::Ticket)?;
        (current == ticket).ok_or(Error::Ticket)?;
        self.fetch = None;
        let installed = self.accept(bytes, now);
        self.failed = installed.is_err().then_some(start);
        installed
    }

    /// Ends the fetch `ticket`, which failed. The next fetch waits for the retry time after its start. Another ticket
    /// changes nothing.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    pub fn fail(&mut self, ticket: Ticket) {
        if let Some((current, start)) = self.fetch
            && current == ticket
        {
            self.fetch = None;
            self.failed = Some(start);
        }
    }

    /// The installed snapshot at `now`, while it is fresh.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] with no snapshot, [`Error::Stale`] at or after the end of the installed one, and
    /// [`Error::Time`] and [`Error::Uncertain`] for the reading.
    pub fn view(&self, now: Reading) -> Result<View<'_>, Error> {
        let now = self.time(now)?;
        let snapshot = self.installed.as_ref().ok_or(Error::Missing)?;
        let end = self.end(snapshot.issued)?;
        (now < end).ok_or(Error::Stale)?;
        Ok(View { snapshot, end })
    }

    /// The time of `now` for a check: the latest time that the reading permits, or the latest time that the trust saw
    /// when that is later. It keeps the earliest time of the reading.
    fn time(&self, now: Reading) -> Result<Duration, Error> {
        let bound = now.bound().ok_or(Error::Time(TimeError::UnknownBound))?;
        (bound <= self.profile.freshness.uncertainty).ok_or(Error::Uncertain)?;
        let earliest = now.earliest().map_err(Error::Time)?;
        let latest = now.latest().map_err(Error::Time)?;
        let floor = self.raise(earliest);
        Ok(latest.max(floor))
    }

    /// Raises the latest time that the trust saw to `time`, and gives it. The maximum needs no order with other memory.
    fn raise(&self, time: Duration) -> Duration {
        let time = u64::try_from(time.as_nanos()).unwrap_or(u64::MAX);
        let floor = self.floor.fetch_max(time, Ordering::Relaxed).max(time);
        Duration::from_nanos(floor)
    }

    /// The end of a snapshot issued at `issued`.
    fn end(&self, issued: Duration) -> Result<Duration, Error> {
        issued
            .checked_add(self.profile.freshness.max_age)
            .ok_or(Error::Time(TimeError::Overflow))
    }

    /// The checks of [`Self::install`].
    fn accept(&mut self, bytes: &[u8], now: Reading) -> Result<(), Error> {
        let now = self.time(now)?;
        let Profile {
            authority,
            root,
            limits,
            ..
        } = &self.profile;
        let sign1 = Sign1::decode(bytes, *limits).map_err(Error::Cose)?;
        // The protected `alg` only matches the algorithm of the root. An algorithm with no COSE identifier has none.
        (sign1.protected().get(1) == cose::alg(root.algorithm()).as_ref()).ok_or(Error::Signature)?;
        let message = cose::to_be_signed(sign1.protected_bytes(), sign1.payload());
        let signed = root
            .verify(&message, sign1.signature(), &mut SignatureBudget::new(limits))
            .map_err(Error::Limit)?;
        signed.ok_or(Error::Signature)?;
        let payload = cbor::decode(sign1.payload(), *limits).map_err(|error| Error::Cose(cose::Error::Cbor(error)))?;
        let Value::Array(items) = &payload else {
            return Err(Error::Form);
        };
        let [
            Value::Text(FORM),
            named,
            Value::Unsigned(issued),
            Value::Array(issuers),
            Value::Array(workloads),
        ] = items.as_slice()
        else {
            return Err(Error::Form);
        };
        (Id::from_cbor(named).map_err(|_| Error::Form)? == *authority).ok_or(Error::Authority)?;
        let issued = Duration::from_nanos(*issued);
        let digest = crypto::sha256(bytes);
        if let Some(installed) = &self.installed {
            (issued >= installed.issued).ok_or(Error::Rollback)?;
            if issued == installed.issued {
                return (digest == installed.digest).ok_or(Error::Inconsistent);
            }
        }
        (issued <= now).ok_or(Error::Future)?;
        (now < self.end(issued)?).ok_or(Error::Stale)?;
        let snapshot = Snapshot::read(issued, digest, issuers, workloads, *limits)?;
        self.raise(issued);
        self.installed = Some(snapshot);
        Ok(())
    }
}

/// An installed snapshot.
#[derive(Debug)]
struct Snapshot {
    issued: Duration,
    /// The SHA-256 digest of its bytes.
    digest: [u8; 32],
    issuers: BTreeMap<Id<Authority>, Issuer>,
    workloads: BTreeMap<Id<Workload>, Member>,
}

/// A workload of a snapshot.
#[derive(Debug)]
struct Member {
    issuer: Id<Authority>,
    thumbprint: [u8; 32],
    generation: Serial,
    revoked: Vec<(Serial, Duration)>,
}

impl Snapshot {
    /// The snapshot issued at `issued` with the members `issuers` and `workloads` of its payload.
    fn read(
        issued: Duration,
        digest: [u8; 32],
        issuers: &[Value<'_>],
        workloads: &[Value<'_>],
        limits: Limits,
    ) -> Result<Self, Error> {
        // Each issuer has one or two keys, so the count bounds the work before the first trusted key.
        (issuers.len() <= limits.keys).ok_or(Error::Limit(Limit::Keys))?;
        let mut keys = 0_usize;
        let mut by_authority = BTreeMap::new();
        for issuer in issuers {
            let Value::Bytes(record) = issuer else {
                return Err(Error::Form);
            };
            let issuer = Issuer::from_record(record, limits).map_err(|_| Error::Form)?;
            keys = keys.saturating_add(issuer.keys());
            (keys <= limits.keys).ok_or(Error::Limit(Limit::Keys))?;
            let authority = issuer.authority().clone();
            by_authority
                .insert(authority, issuer)
                .is_none()
                .ok_or(Error::Inconsistent)?;
        }
        let mut by_workload = BTreeMap::new();
        for workload in workloads {
            let (workload, member) = member(workload)?;
            by_authority.contains_key(&member.issuer).ok_or(Error::Inconsistent)?;
            by_workload
                .insert(workload, member)
                .is_none()
                .ok_or(Error::Inconsistent)?;
        }
        Ok(Self {
            issued,
            digest,
            issuers: by_authority,
            workloads: by_workload,
        })
    }
}

/// The workload and the member of the form `[workload, issuer, thumbprint, generation, revoked]`.
fn member(value: &Value<'_>) -> Result<(Id<Workload>, Member), Error> {
    let Value::Array(items) = value else {
        return Err(Error::Form);
    };
    let [
        workload,
        issuer,
        Value::Bytes(thumbprint),
        Value::Unsigned(generation),
        Value::Array(revoked),
    ] = items.as_slice()
    else {
        return Err(Error::Form);
    };
    (revoked.len() <= workload::REVOKED_MAX).ok_or(Error::Form)?;
    let revoked = revoked
        .iter()
        .map(|entry| match entry {
            Value::Array(pair) => match pair.as_slice() {
                [Value::Unsigned(serial), Value::Unsigned(expires)] => {
                    Ok((Serial(*serial), Duration::from_secs(*expires)))
                }
                _ => Err(Error::Form),
            },
            _ => Err(Error::Form),
        })
        .collect::<Result<_, _>>()?;
    let member = Member {
        issuer: Id::from_cbor(issuer).map_err(|_| Error::Form)?,
        thumbprint: (*thumbprint).try_into().map_err(|_| Error::Form)?,
        generation: Serial(*generation),
        revoked,
    };
    Ok((Id::from_cbor(workload).map_err(|_| Error::Form)?, member))
}

/// A fresh snapshot.
#[derive(Debug)]
pub struct View<'t> {
    snapshot: &'t Snapshot,
    end: Duration,
}

impl View<'_> {
    /// The issuer `authority` of the snapshot, or `None` when it has none. [`Issuer::profile`] gives the profile that
    /// verifies its credentials for an audience.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn issuer(&self, authority: &Id<Authority>) -> Option<&Issuer> {
        self.snapshot.issuers.get(authority)
    }

    /// Checks the verified workload credential `verified` against the registration of its workload in the snapshot, as
    /// [`workload::admits`] checks it against the store. Thus a credential that a rotation, a recovery, or a revocation
    /// before the issue of the snapshot ended refuses.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`workload::Error::Unregistered`] if the snapshot has no registration of the workload, and the errors of
    /// [`workload::admits`].
    pub fn admits(&self, verified: &credential::Verified<'_, '_>) -> Result<(), workload::Error> {
        let Subject::Workload(name) = &verified.claims().subject else {
            return Err(workload::Error::Possession);
        };
        let member = self.snapshot.workloads.get(name).ok_or(workload::Error::Unregistered)?;
        Admitted {
            issuer: &member.issuer,
            workload: name,
            thumbprint: &member.thumbprint,
            generation: member.generation,
            revoked: &member.revoked,
        }
        .admits(verified)
    }

    /// The time of the issue of the snapshot, since the Unix epoch.
    #[must_use]
    pub const fn issued(&self) -> Duration {
        self.snapshot.issued
    }

    /// The end of the reuse of the snapshot: its issue plus the maximum age. A check with it ends at this time, or at
    /// the end of its credential when that is earlier.
    #[must_use]
    pub const fn end(&self) -> Duration {
        self.end
    }
}

/// A snapshot that waits for the signature of the root.
pub struct Draft {
    root: Handle,
    protected: Vec<u8>,
    payload: Vec<u8>,
}

impl Draft {
    /// The draft of the snapshot of `authority` at `issued`, from the records of `store`: each issuer record and each
    /// registration record, in pages of range reads. `root` is the handle of the trust root that signs it. The time of
    /// the issue is the earliest time of `issued`, so a snapshot never claims a later issue than its true one.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One range read for each page of each kind, and one
    /// trusted key for each issuer key.
    ///
    /// # Errors
    ///
    /// [`Error::Limit`] with [`Limit::Keys`] for more issuer keys than [`Limits::keys`], and with [`Limit::Items`] for
    /// more registrations than [`Limits::items`]. [`Error::Form`] if a record is not the form of its kind, and
    /// [`Error::Inconsistent`] if a registration names an issuer that the store has no record of.
    /// [`Error::Time`] if `issued` has no bound. [`Failure::Store`] if a read fails.
    pub async fn read<S: Store>(
        store: &mut S,
        authority: &Id<Authority>,
        root: &Handle,
        issued: Reading,
        limits: Limits,
    ) -> Result<Self, Failure<S::Error>> {
        let earliest = issued.earliest().map_err(Error::Time)?;
        let issued = u64::try_from(earliest.as_nanos()).map_err(|_| Error::Time(TimeError::Overflow))?;
        let issuers = records(store, Kind::Issuer, limits.keys, Limit::Keys).await?;
        let registrations = records(store, Kind::Workload, limits.items, Limit::Items).await?;
        let mut keys = 0_usize;
        let mut authorities = Vec::with_capacity(issuers.len());
        for record in &issuers {
            let issuer = Issuer::from_record(&record.data, limits).map_err(|_| Error::Form)?;
            keys = keys.saturating_add(issuer.keys());
            (keys <= limits.keys).ok_or(Error::Limit(Limit::Keys))?;
            authorities.push(issuer.authority().clone());
        }
        let mut members = Vec::with_capacity(registrations.len());
        for record in &registrations {
            let (workload, key, generation, revoked) =
                Registration::fields(&record.data, limits).map_err(|_| Error::Form)?;
            let issuer = record.version.owner().clone();
            authorities.contains(&issuer).ok_or(Error::Inconsistent)?;
            let thumbprint = Key::decode(key, limits).map_err(|_| Error::Form)?.public.thumbprint();
            members.push((workload, issuer, thumbprint, generation, revoked));
        }
        let members = members
            .iter()
            .map(|(workload, issuer, thumbprint, generation, revoked)| {
                let revoked = revoked
                    .iter()
                    .map(|(serial, expires)| {
                        Value::Array(vec![Value::Unsigned(serial.0), Value::Unsigned(expires.as_secs())])
                    })
                    .collect();
                Value::Array(vec![
                    workload.to_cbor(),
                    issuer.to_cbor(),
                    Value::Bytes(thumbprint),
                    Value::Unsigned(generation.0),
                    Value::Array(revoked),
                ])
            })
            .collect();
        let payload = Value::Array(vec![
            Value::Text(FORM),
            authority.to_cbor(),
            Value::Unsigned(issued),
            Value::Array(issuers.iter().map(|record| Value::Bytes(&record.data)).collect()),
            Value::Array(members),
        ]);
        let payload = cbor::encode(&payload, limits).map_err(|error| Error::Cose(cose::Error::Cbor(error)))?;
        let protected = match cose::alg(root.algorithm()) {
            Some(alg) => cbor::encode(&Value::Map(vec![(Value::Unsigned(1), alg)]), Limits::FORM)
                .expect("a map of one label has no simple value"),
            None => Vec::new(),
        };
        Ok(Self {
            root: root.clone(),
            protected,
            payload,
        })
    }

    /// The bytes that the root signs: the `Sig_structure` of RFC 9052 section 4.4.
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        cose::to_be_signed(&self.protected, &self.payload)
    }

    /// Verifies `signature`, the signature of custody over [`Self::to_be_signed`], with the root. Then it gives the
    /// snapshot: a `COSE_Sign1` with the tag 18 and an empty unprotected bucket. The check charges `budget`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if the signature does not verify with the root, and [`Error::Limit`] if the check costs
    /// more than `budget` has.
    pub fn finish(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<Vec<u8>, Error> {
        let signed = self
            .root
            .verify(&self.to_be_signed(), signature, budget)
            .map_err(Error::Limit)?;
        signed.ok_or(Error::Signature)?;
        let snapshot = Value::Tag(
            SIGN1_TAG,
            Box::new(Value::Array(vec![
                Value::Bytes(&self.protected),
                Value::Map(Vec::new()),
                Value::Bytes(&self.payload),
                Value::Bytes(signature),
            ])),
        );
        Ok(cbor::encode(&snapshot, Limits::FORM).expect("a COSE_Sign1 has no map key and no simple value"))
    }
}

impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Draft")
            .field("root", &self.root)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Each record of `kind` in `store`, in pages, and at most `max` of them.
async fn records<S: Store>(
    store: &mut S,
    kind: Kind,
    max: usize,
    limit: Limit,
) -> Result<Vec<Record>, Failure<S::Error>> {
    let prefix = kind.key(&[]).expect("a key of one byte is valid");
    let mut records = Vec::new();
    let mut after = None;
    loop {
        let page = store
            .range(&prefix, after.as_ref(), PAGE)
            .await
            .map_err(Failure::Store)?;
        let full = page.len() == PAGE.get();
        after = page.last().map(|(key, _)| key.clone());
        records.extend(page.into_iter().map(|(_, record)| record));
        (records.len() <= max).ok_or(Error::Limit(limit))?;
        if !full {
            return Ok(records);
        }
    }
}

/// The cause of a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The declared times cannot keep their promises: a zero maximum age or retry time, a retry time of more than half
    /// of the maximum age, or a maximum age plus uncertainty past the propagation objective.
    Freshness,
    /// The reading has no bound, or a time overflows.
    Time(TimeError),
    /// The bound of the reading is larger than the declared uncertainty.
    Uncertain,
    /// No snapshot is installed. Refresh first.
    Missing,
    /// The snapshot is at or after the end of its maximum age. Refresh.
    Stale,
    /// The snapshot is older than the installed one.
    Rollback,
    /// The snapshot has the time of issue of the installed one and other bytes, or two members with one name, or a
    /// registration of an issuer that it does not hold.
    Inconsistent,
    /// The time of issue of the snapshot is after the time of the check.
    Future,
    /// The snapshot is of another authority.
    Authority,
    /// The root did not sign the snapshot, or its protected `alg` is not the algorithm of the root.
    Signature,
    /// The snapshot is not a `COSE_Sign1` within the limits.
    Cose(cose::Error),
    /// The payload or a record is not its form.
    Form,
    /// The snapshot or the store is larger than a bound of the limits.
    Limit(Limit),
    /// The ticket is not the fetch in flight.
    Ticket,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Freshness => f.write_str("the declared times of the trust are not valid"),
            Self::Time(error) => write!(f, "the time reading gave no value: {error}"),
            Self::Uncertain => f.write_str("the time reading is less certain than the declared uncertainty"),
            Self::Missing => f.write_str("no trust snapshot is installed"),
            Self::Stale => f.write_str("the trust snapshot is past its maximum age"),
            Self::Rollback => f.write_str("the trust snapshot is older than the installed one"),
            Self::Inconsistent => f.write_str("the trust snapshot is not consistent"),
            Self::Future => f.write_str("the trust snapshot is from after the time of the check"),
            Self::Authority => f.write_str("the trust snapshot is of another authority"),
            Self::Signature => f.write_str("the trust root did not sign the snapshot"),
            Self::Cose(error) => write!(f, "the trust snapshot is not a valid COSE_Sign1: {error}"),
            Self::Form => f.write_str("the trust snapshot or a record is not its form"),
            Self::Limit(limit) => write!(f, "the trust snapshot is larger than a bound: {limit:?}"),
            Self::Ticket => f.write_str("the ticket is not the fetch in flight"),
        }
    }
}

impl core::error::Error for Error {}

/// The failure of an operation that reads the store: a refusal, or a failed read.
pub type Failure<E> = crate::store::Failure<Error, E>;
