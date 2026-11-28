//! Local authority: the authority that the owner of an application opens on one host, with no hosted account and no
//! daemon.
//!
//! The host builds a [`HostGrant`] at its trusted boundary: the local owner and the origin of the application.
//! [`Authority::open`] binds the authority to the grant and to the issuer key in custody. The local owner then issues
//! a bootstrap value with [`Authority::issue`]. The value is one-use, names one administrator, and is valid for
//! [`LIFETIME`]. Each issue ends the earlier value that is not consumed, so at most one value is valid.
//!
//! A client, such as a headless CLI, stores its key in custody before it submits the value. [`Authority::bootstrap`]
//! makes the CLI credential of the administrator in two steps: custody signs the bytes of [`Pending::to_be_signed`],
//! and [`Pending::finish`] gives the proposal. Its commit consumes the value, writes the issuance record of the
//! credential, and binds the administrator. A remote call is admitted only for the credential of a live administrator
//! binding ([`Authority::admit`]). Thus remote access refuses before a separate identity enrolls. Each call proves the
//! possession of the key of the credential over a one-use challenge of the binding ([`Authority::challenge`]). An
//! unlink of a binding is a call of its own ([`Authority::unlink`]). The module [`crate::cli`] gives the call of the
//! client and its journey.
//!
//! A human can also approve the CLI of their own account in a browser, with a passkey ([`Authority::enroll`], the
//! module [`enroll`]). Its CLI credential names the account, and its binding is a CLI binding of the account, which
//! gives no administrator call: [`Admitted::holder`] says which binding a call came from.
//!
//! An administrator binding ends with its CLI credential, and expiry removes it ([`store::expire`](crate::store::expire)).
//! A binding whose credential ended is no administrator: it gets no challenge, and an unlink does not count it. The
//! owner issues a value for that administrator again.
//!
//! The store keeps no secret and no signed credential. A value record holds the administrator, the time of the issue,
//! and the end of the value, under a key that the SHA-256 digest of the authority, the issuer public key, and the secret
//! names. Thus a value of another authority, or of another issuer key, finds no record. The record of the authority
//! ([`Kind::Local`]) holds the grant, the issuer key, and the log of the last [`ISSUES_MAX`] issues. Each administrator
//! binding holds the issue of the value that its consumption spent, the grant and the issuer key that bound it, and its
//! CLI credential without the signature. Its key starts with the digest of the authority, then of the administrator,
//! and ends with the serial of the credential. Thus one range read ([`Store::range`]) gives each administrator. The
//! report ([`Authority::report`]) gives each issue of the log and each binding, also after a restore. After a lost
//! response, custody signs the credential of the binding again ([`Authority::credential`]).
//!
//! Each operation other than the report refuses a reading of `now` with no bound with [`Error::Time`] before its first
//! read: the end of a value, of a challenge, or of a credential comes from the reading.
//!
//! Each operation reads the store with [`Store::read`] and [`Store::range`], and gives a proposal and its plan. Submit
//! them to the commit driver ([`Driver::submit`](crate::store::driver::Driver::submit)). A proposal that depends on a
//! one-use value or a challenge carries its end as its deadline, so its commit refuses after it. Only the receipt of
//! the accepted commit gives the bootstrap value or the credential. After a lost response, the outcome lookup shows
//! the commit and no value: the owner issues again, and that issue ends the value of the lost commit.
//!
//! This example runs the journey on the memory binding of `rsauthnz-conformance`. rscrypto signs in place of custody,
//! so that the example holds its keys.
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::credential::Serial;
//! use rsauthnz::crypto::Algorithm;
//! use rsauthnz::custody::{Handle, KeyId};
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::Limits;
//! use rsauthnz::local::{self, Authority, Bootstrap, HostGrant};
//! use rsauthnz::store::driver::{Answer, Driver, Plan};
//! use rsauthnz::store::{self, Kind, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz::transition::{OperationId, Outcome, Proposal};
//! use rsauthnz_conformance::memory::{Memory, Schedule};
//! use rsauthnz_conformance::suite::execute;
//! use rscrypto::ChaCha20Rng;
//! use rscrypto::auth::MlDsa65Ed25519;
//!
//! type Failure = Box<dyn core::error::Error>;
//!
//! /// The output of a future of the memory binding, which is ready at its first poll.
//! fn ready<T>(future: impl Future<Output = T>) -> T {
//!     let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
//!         unreachable!("the memory binding does no I/O");
//!     };
//!     output
//! }
//!
//! /// Gives each effect of the driver to the binding, until the driver waits.
//! fn settle(memory: &mut Memory, driver: &mut Driver) -> Result<(), Failure> {
//!     while let Some(effect) = driver.effect() {
//!         let output = ready(execute(memory, effect));
//!         driver.give(output)?;
//!     }
//!     Ok(())
//! }
//!
//! /// The artifact that the receipt of the accepted commit of `proposal` gives.
//! fn commit(memory: &mut Memory, driver: &mut Driver, (proposal, plan): (Proposal, Plan)) -> Result<Vec<u8>, Failure> {
//!     let ticket = driver.submit(proposal, plan)?;
//!     settle(memory, driver)?;
//!     match driver.take(ticket) {
//!         Some(Answer::Outcome(Outcome::Accepted(receipt))) => Ok(receipt.artifact().ok_or("no artifact")?.to_vec()),
//!         answer => Err(format!("the commit did not land: {answer:?}").into()),
//!     }
//! }
//!
//! let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! // Only for this example: take the seed from the entropy source of the host, and keep each key in custody.
//! let mut random = ChaCha20Rng::from_seed([7; 32]);
//! let (issuer_public, issuer_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(1)))?;
//! let (holder_public, _) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(2)))?;
//! let (issuer_public, holder_public) = (issuer_public.to_bytes(), holder_public.to_bytes());
//! let issuer = Handle::new(KeyId::random(&mut random), Algorithm::MlDsa65Ed25519, &issuer_public)?;
//!
//! let mut memory = Memory::new(Schedule::None);
//! let mut driver = Driver::new(store::Profile::new(memory.declaration())?, Limits::default())?;
//! driver.start(now);
//! settle(&mut memory, &mut driver)?;
//!
//! // 1. The local owner opens the authority and issues a bootstrap value for the administrator `alice`.
//! let grant = HostGrant { owner: Id::new("acme", "owner")?, origin: Id::new("acme", "build-app")? };
//! let authority = ready(Authority::open(&mut memory, &grant, Id::new("acme", "auth")?, issuer, Limits::default()))?;
//! let alice = Id::new("acme", "alice")?;
//! let issue = ready(authority.issue(&mut memory, &grant, alice.clone(), now, &mut random, OperationId::new(b"i-1")?))?;
//! let text = String::from_utf8(commit(&mut memory, &mut driver, issue)?)?;
//!
//! // 2. The client stores its key, then submits the value and its public key. Custody signs the CLI credential.
//! let value = Bootstrap::parse(&text)?;
//! let serial = Serial(driver.allocate(Kind::Credential)?);
//! let pending = ready(authority.bootstrap(&mut memory, &value, &holder_public, serial, now))?;
//! let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
//! let bootstrap = pending.finish(signature.as_bytes(), OperationId::new(b"b-1")?)?;
//! let credential = commit(&mut memory, &mut driver, bootstrap)?;
//!
//! // After a lost response, the client gives its administrator and its public key, and custody signs the credential
//! // of the binding again.
//! let reissue = ready(authority.credential(&mut memory, &alice, &holder_public, now))?;
//! let signature = issuer_secret.sign_deterministic(&reissue.to_be_signed(), &[])?;
//! assert_eq!(reissue.finish(signature.as_bytes())?, credential);
//!
//! // The value is one-use. Each remote call of the administrator proves the possession of its key: see `rsauthnz::cli`.
//! let again = ready(authority.bootstrap(&mut memory, &value, &holder_public, serial, now));
//! assert!(matches!(again, Err(local::Failure::Refused(local::Error::Unknown))));
//! # Ok::<(), Failure>(())
//! ```
//!
//! Only the host grant issues a value. A remote caller, a session, or a grant has evidence, not the host grant, so it
//! cannot call [`Authority::issue`]:
//!
//! ```compile_fail,E0308
//! use rsauthnz::evidence::Evidence;
//! use rsauthnz::id::Id;
//! use rsauthnz::local::Authority;
//! use rsauthnz::store::Store;
//! use rsauthnz::time::Reading;
//! use rsauthnz::transition::OperationId;
//! use rscrypto::ChaCha20Rng;
//!
//! async fn from_a_session<S: Store>(
//!     authority: &Authority,
//!     store: &mut S,
//!     session: &Evidence,
//!     now: Reading,
//!     random: &mut ChaCha20Rng,
//! ) -> Result<(), Box<dyn core::error::Error>> {
//!     let mallory = Id::new("acme", "mallory")?;
//!     authority.issue(store, session, mallory, now, random, OperationId::new(b"issue-2")?).await;
//!     Ok(())
//! }
//! ```

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroUsize;
use core::time::Duration;

use rscodec::hex;
use rscrypto::{ChaCha20Rng, SecretBytes};

use crate::cbor::{self, Value};
use crate::cli::{self, Call, Challenge};
use crate::cose::{PublicKey, Sign1, TrustedKey};
use crate::credential::{self, Claims, Draft, Serial, Subject, Unsigned};
use crate::crypto;
use crate::custody::Handle;
use crate::evidence::Evidence;
use crate::id::{Audience, Authority as AuthorityKind, AuthorityVersion, Human, Id, Principal, Purpose};
use crate::limits::{Limits, SignatureBudget};
use crate::store::driver::Plan;
use crate::store::journal::{Anchor, Role};
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{
    self, Audit, Change, Dependency, Key, OperationId, Outcome, Prepared, Proposal, Recover, Recovery,
};

pub mod enroll;

/// The declared lifetime of a bootstrap value: the first value and each value of a re-bootstrap. A consumption at or
/// after the end refuses, and the local owner issues a new value.
pub const LIFETIME: Duration = Duration::from_secs(15 * 60);

/// The lifetime of the CLI credential that a bootstrap issues: 365 days.
pub const CLI_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The most issues in the log of an authority. An issue past it drops the oldest issue whose value bound no
/// administrator with a valid CLI credential.
pub const ISSUES_MAX: usize = 64;

/// The most administrator bindings of an authority, with a valid or an ended CLI credential. An issue for a new
/// administrator refuses at it, and a report or an unlink reads at most this many.
pub const ADMINISTRATORS_MAX: usize = 64;

/// The text of a bootstrap value: this prefix and 64 lowercase hexadecimal digits.
const PREFIX: &str = "rsauthnz-bootstrap-1-";
/// The first item of each CBOR form of this module. The number changes with the form.
const IDENTITY_FORM: &str = "rsauthnz.local.bootstrap.1";
const RECORD_FORM: &str = "rsauthnz.local.1";
const VALUE_FORM: &str = "rsauthnz.local.value.2";
const BINDING_FORM: &str = "rsauthnz.local.administrator.3";
const UNLINK_FORM: &str = "rsauthnz.local.unlink.1";
/// The actions of the audit records.
const ISSUE: &str = "bootstrap.issue";
const CONSUME: &str = "bootstrap.consume";
const UNLINK: &str = "administrator.unlink";
const CHALLENGE: &str = "cli.challenge";
const CALL: &str = "cli.call";

/// The grant of the host that opens a local authority: the local owner and the origin of the application. The origin
/// is the audience of each CLI credential of the authority.
///
/// Only the host builds a grant, at its trusted boundary, for example for a call of its own user interface. A request
/// cannot assert a grant: a remote caller, a session, or an agent grant gives evidence, never a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostGrant {
    /// The local owner of the application.
    pub owner: Id<Human>,
    /// The origin of the application.
    pub origin: Id<Audience>,
}

/// A bootstrap value: 32 random bytes. Its text is `rsauthnz-bootstrap-1-` and 64 lowercase hexadecimal digits. It is
/// a secret, so `Debug` does not show it, and its memory is cleared when it drops.
pub struct Bootstrap(SecretBytes<32>);

impl Bootstrap {
    /// Reads the text of a bootstrap value.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Form`] if `text` is not `rsauthnz-bootstrap-1-` and 64 lowercase hexadecimal digits. [`Error::Dit`] if
    /// this build on this CPU cannot decode the value with data-independent timing.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let digits = text.strip_prefix(PREFIX).ok_or(Error::Form)?.as_bytes();
        (digits.len() == 64).ok_or(Error::Form)?;
        SecretBytes::try_fill_with(|secret| {
            rscodec::with_dit(|dit| hex::decode_secret(dit, digits, secret).map(drop))
                .map_err(|_| Error::Dit)?
                .map_err(|_| Error::Form)
        })
        .map(Self)
    }

    /// A new value from `random`, drawn into its owner.
    fn random(random: &mut ChaCha20Rng) -> Self {
        let Ok(secret) = SecretBytes::try_fill_with(|secret| {
            random.fill_bytes(secret);
            Ok::<_, !>(())
        });
        Self(secret)
    }

    /// The text of the value, in an allocation of its exact length. [`Prepared`] keeps that allocation and clears it.
    fn text(&self) -> Result<Vec<u8>, Error> {
        let mut text = vec![0; PREFIX.len() + 64];
        let (prefix, digits) = text.split_at_mut(PREFIX.len());
        prefix.copy_from_slice(PREFIX.as_bytes());
        rscodec::with_dit(|dit| {
            hex::encode_secret(dit, self.0.as_bytes(), digits).expect("64 digits hold the text of 32 bytes");
        })
        .map_err(|_| Error::Dit)?;
        Ok(text)
    }
}

impl fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bootstrap(..)")
    }
}

/// The purpose of a CLI credential: `rsauthnz:cli`.
fn cli() -> Id<Purpose> {
    Id::new("rsauthnz", "cli").expect("the purpose of a CLI credential is a valid identifier")
}

/// A local authority that its host grant opened. It holds no secret: custody holds the issuer key.
#[derive(Debug)]
pub struct Authority {
    id: Id<AuthorityKind>,
    grant: HostGrant,
    issuer: Handle,
    key: TrustedKey,
    profile: credential::Profile,
    limits: Limits,
}

impl Authority {
    /// Opens the local authority `id` under `grant`, with the issuer key `issuer` in custody. The proposals and the
    /// decode of each record use `limits`: give the limits of the commit driver.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One keyed read of the record of the authority. With no
    /// record, one range read of at most one administrator binding.
    ///
    /// # Errors
    ///
    /// [`Error::Grant`] if the record of the authority, or an administrator binding when the store has no record, has
    /// another owner or origin. [`Error::Issuer`] if it has another issuer key. [`Error::Record`] if the record has no
    /// valid form. [`Failure::Store`] if the read fails. [`Error::Credential`] if `issuer` is a trust-root key, which
    /// signs issuer keys and no credential.
    pub async fn open<S: Store>(
        store: &mut S,
        grant: &HostGrant,
        id: Id<AuthorityKind>,
        issuer: Handle,
        limits: Limits,
    ) -> Result<Self, Failure<S::Error>> {
        let key = issuer.trusted().ok_or(Error::Credential(credential::Error::Profile))?;
        let profile = credential::Profile::new(key.clone(), id.clone(), grant.origin.clone(), cli(), limits)
            .map_err(Error::Credential)?;
        let authority = Self {
            id,
            grant: grant.clone(),
            issuer,
            key,
            profile,
            limits,
        };
        match read(store, &authority.key()).await? {
            Some(record) => {
                authority.log(&record)?;
            }
            // A restore can keep an administrator binding and lose the record of the authority. Each binding names the
            // grant and the issuer key that bound it, so another grant or issuer key refuses.
            None => {
                let first = store
                    .range(&authority.prefix(), None, NonZeroUsize::MIN)
                    .await
                    .map_err(Failure::Store)?;
                for (_, record) in &first {
                    authority.decode(record)?;
                }
            }
        }
        Ok(authority)
    }

    /// The profile that verifies a CLI credential of the authority: its issuer key, the authority as the issuer, the
    /// origin of the grant as the audience, and the purpose `rsauthnz:cli`.
    #[must_use]
    pub const fn profile(&self) -> &credential::Profile {
        &self.profile
    }

    /// The issue of a bootstrap value for the administrator `administrator`, by the local owner of `grant`: the first
    /// value, or an owner re-bootstrap. The commit ends the earlier value that is not consumed, with an end entry in
    /// the restore journal, writes the new value, and adds the issue to the log. Draw `operation` from `random`, and
    /// keep it: after a lost response, look it up, and then issue again. The commit writes no creation entry.
    ///
    /// Only the receipt of the accepted commit gives the value, as its artifact: the text of a [`Bootstrap`]. Give it
    /// to the client by a local path, never by a URL or a log. A lookup gives no value.
    ///
    /// An administrator binding ends with its CLI credential. A binding whose credential ended is no administrator, so
    /// the owner issues a value for that administrator again, and the store removes the ended binding by expiry
    /// ([`store::expire`](crate::store::expire)). At [`ADMINISTRATORS_MAX`] bindings, an expiry pass removes each
    /// ended binding, and then the owner issues.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). Two keyed reads, and one range read of the administrator
    /// bindings.
    ///
    /// # Errors
    ///
    /// [`Error::Grant`] if `grant` is not the grant that opened the authority, or a binding has another grant.
    /// [`Error::Bound`] if `administrator` has a binding whose CLI credential can be valid at `now`. [`Error::Full`] if
    /// the store holds [`ADMINISTRATORS_MAX`] bindings of the authority, or the log cannot drop an issue.
    /// [`Error::Time`] if `now` has no bound. [`Error::Time`] if the end of the value overflows. [`Error::Dit`] if this
    /// build on this CPU cannot encode the value with data-independent timing. The errors of [`Self::open`] for the
    /// record of the authority and its bindings, and [`Error::Transition`] for the proposal.
    pub async fn issue<S: Store>(
        &self,
        store: &mut S,
        grant: &HostGrant,
        administrator: Id<Human>,
        now: Reading,
        random: &mut ChaCha20Rng,
        operation: OperationId,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        (*grant == self.grant).ok_or(Error::Grant)?;
        now.latest().map_err(Error::Time)?;
        let issued = now.estimate().as_secs();
        let expires = issued
            .checked_add(LIFETIME.as_secs())
            .ok_or(Error::Time(TimeError::Overflow))?;
        let value = Bootstrap::random(random);
        let identity = self.identity(&value);
        let value_data = encode(&[
            Value::Text(VALUE_FORM),
            administrator.to_cbor(),
            Value::Unsigned(issued),
            Value::Unsigned(expires),
        ]);
        let request = Value::Array(vec![
            Value::Bytes(&identity),
            administrator.to_cbor(),
            Value::Unsigned(expires),
        ]);
        let mut proposal = self.proposal(operation, &self.grant.owner, ISSUE, request, now)?;
        let key = self.key();
        let stored = read(store, &key).await?;
        let mut log = match &stored {
            Some(record) => self.log(record)?,
            None => Vec::new(),
        };
        proposal
            .read(dependency(&key, stored.as_ref()))
            .map_err(Error::Transition)?;
        // The earlier value that is not consumed ends. A value that is gone was consumed, or a restore applied its end.
        if let Some(last) = log.last_mut().filter(|entry| entry.state == State::Open) {
            let current = value_key(&last.identity);
            let record = read(store, &current).await?;
            proposal
                .read(dependency(&current, record.as_ref()))
                .map_err(Error::Transition)?;
            last.state = if record.is_some() {
                proposal.change(Change::End(current)).map_err(Error::Transition)?;
                State::Ended
            } else {
                State::Consumed
            };
        }
        // The read of the value that the issue ends conflicts with a concurrent consumption of it, which can bind the
        // same administrator. A binding whose credential ended is no administrator, so it does not refuse the issue.
        let live = self.administrators(store).await?;
        for (.., held) in &live {
            (held.issue.administrator != administrator || !held.usable(now)?).ok_or(Error::Bound)?;
        }
        (live.len() < ADMINISTRATORS_MAX).ok_or(Error::Full)?;
        log.push(Entry {
            identity,
            administrator,
            issued,
            expires,
            state: State::Open,
        });
        let data = self.fit(&mut log, &live, now)?;
        let version = self.next(stored.map(|record| record.version), &identity)?;
        proposal
            .change(Change::Write {
                key,
                version,
                end: None,
                data,
            })
            .map_err(Error::Transition)?;
        // The record has no end of the store: only an issue or a consumption ends it, each with a journal entry.
        let key = value_key(&identity);
        proposal
            .read(Dependency::Absent(key.clone()))
            .map_err(Error::Transition)?;
        let version = self.version(&[1]);
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: version.clone(),
                end: None,
                data: value_data.into_boxed_slice(),
            })
            .map_err(Error::Transition)?;
        proposal
            .prepare(Prepared::new(value.text()?, key, version))
            .map_err(Error::Transition)?;
        Ok((proposal, Plan::default()))
    }

    /// The first step of a bootstrap: the CLI credential of the administrator of `value`, with the `cnf` key `holder`,
    /// an ML-DSA-65 + Ed25519 key, and the serial `serial` ([`Driver::allocate`] of [`Kind::Credential`]). The client
    /// stores the private part of `holder` in its custody before it submits the value. Custody signs the bytes of
    /// [`Pending::to_be_signed`] with the issuer key, and [`Pending::finish`] gives the proposal. An administrator
    /// whose binding holds an ended CLI credential gets a new binding.
    ///
    /// [`Driver::allocate`]: crate::store::driver::Driver::allocate
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed read, one range read of the bindings of the
    /// administrator, and a check of `holder`.
    ///
    /// # Errors
    ///
    /// [`Error::Unknown`] if the authority holds no valid record of `value`: it is consumed or ended, or it is a value
    /// of another authority or issuer key. [`Error::Expired`] at or after the end of the value, and [`Error::Time`] if
    /// `now` has no bound. [`Error::Bound`] if the administrator has a binding whose CLI credential can be valid at
    /// `now`. [`Error::Credential`] if the draft refuses `holder`. [`Error::Record`] if a record has no valid form,
    /// [`Error::Grant`] or [`Error::Issuer`] if a binding has another grant or issuer key, and [`Failure::Store`] if a
    /// read fails.
    pub async fn bootstrap<S: Store>(
        &self,
        store: &mut S,
        value: &Bootstrap,
        holder: &[u8; 1984],
        serial: Serial,
        now: Reading,
    ) -> Result<Pending<'_>, Failure<S::Error>> {
        now.latest().map_err(Error::Time)?;
        let identity = self.identity(value);
        let key = value_key(&identity);
        let record = read(store, &key).await?.ok_or(Error::Unknown)?;
        let (administrator, issued, ends) = self.value(&record).ok_or(Error::Record)?;
        if expired(now, ends)? {
            return Err(Error::Expired.into());
        }
        // A binding whose credential ended stays until expiry removes it. The new binding has the key of its serial.
        if self.bound(store, &administrator, now).await?.is_some() {
            return Err(Error::Bound.into());
        }
        let expires = now
            .estimate()
            .checked_add(CLI_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let claims = Claims::new(
            self.id.clone(),
            self.grant.origin.clone(),
            Subject::Human(administrator.clone()),
            cli(),
            serial,
            expires,
        );
        let draft = Draft::credential(&self.key, &claims, Some(PublicKey::MlDsa65Ed25519(holder)), now)
            .map_err(Error::Credential)?;
        Ok(Pending {
            authority: self,
            draft,
            value: (key, record.version),
            issue: Entry {
                identity,
                administrator,
                issued,
                expires: ends,
                state: State::Consumed,
            },
            serial,
            holder: crypto::sha256(holder),
            expires: expires.as_secs(),
            now,
        })
    }

    /// The CLI credential of the binding of `administrator` whose `cnf` key is `holder`: the recovery of a client
    /// whose response was lost, or whose bootstrap a restore completed. The binding keeps the credential without its
    /// signature, so the store and the restore journal hold no signed credential. Custody signs the bytes of
    /// [`Reissue::to_be_signed`] with the issuer key again, and [`Reissue::finish`] gives the credential: the same
    /// claims, the same serial, and the same `cnf` key. The client keeps no secret for it: it gives the administrator
    /// that the local owner named, and the public key of its key in custody. The credential is no secret: a call needs
    /// the possession of its `cnf` key too.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One range read of the bindings of the administrator. The
    /// signature of custody is the cost of the host: limit the rate of recoveries of one administrator.
    ///
    /// # Errors
    ///
    /// [`Error::Unknown`] if no binding of `administrator` with a CLI credential that is valid at `now` has the `cnf`
    /// key `holder`: the bootstrap did not commit, an unlink ended the binding, its credential ended, or the binding
    /// holds another key. [`Error::Time`] if `now` has no bound. [`Error::Record`] if the binding has no valid form,
    /// [`Error::Grant`] or [`Error::Issuer`] if it has another grant or issuer key, and [`Failure::Store`] if the read
    /// fails.
    pub async fn credential<S: Store>(
        &self,
        store: &mut S,
        administrator: &Id<Human>,
        holder: &[u8; 1984],
        now: Reading,
    ) -> Result<Reissue, Failure<S::Error>> {
        now.latest().map_err(Error::Time)?;
        let (.., held) = self.bound(store, administrator, now).await?.ok_or(Error::Unknown)?;
        (held.holder == crypto::sha256(holder)).ok_or(Error::Unknown)?;
        Ok(Reissue {
            unsigned: Unsigned::from_parts(self.key.clone(), &held.protected, &held.payload),
            limits: self.limits,
        })
    }

    /// The challenge for the next call of the CLI of `administrator`: its first call, or a call after a refusal, a
    /// conflict, a lost response, or a restore. A binding has at most one challenge, in its challenge record.
    ///
    /// The request authenticates no caller. Thus it changes no challenge that can still admit a call: while the record
    /// holds a challenge that is valid at each time that `now` permits, it gives [`Offer::Open`] with that challenge,
    /// and nothing commits. Only with no such challenge does it give [`Offer::New`]: the proposal of a new challenge
    /// in the record, which ends after [`cli::CHALLENGE_LIFETIME`]. Its audit names `administrator`, not the caller.
    /// Only the receipt of the accepted commit gives the new challenge, as its artifact: the 32 bytes of a
    /// [`Challenge`]. After a lost response, ask again. The challenge is no secret: only the proof of a call shows the
    /// key.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One range read of the bindings of the administrator, and
    /// one keyed read.
    ///
    /// # Errors
    ///
    /// [`Error::NotEnrolled`] if `administrator` has no binding whose CLI credential can be valid at `now`.
    /// [`Error::Time`] if `now` has no bound or the end of the challenge overflows. [`Error::Record`] if a record has
    /// no valid form, [`Failure::Store`] if a read fails, and [`Error::Transition`] for the proposal.
    pub async fn challenge<S: Store>(
        &self,
        store: &mut S,
        administrator: &Id<Human>,
        now: Reading,
        random: &mut ChaCha20Rng,
        operation: OperationId,
    ) -> Result<Offer, Failure<S::Error>> {
        now.latest().map_err(Error::Time)?;
        let (binding, record, _) = self.bound(store, administrator, now).await?.ok_or(Error::NotEnrolled)?;
        let key = cli::key(&self.id, administrator);
        self.offer(
            store,
            administrator,
            (binding, record, None),
            key,
            now,
            random,
            operation,
        )
        .await
    }

    /// The offer of the challenge record `key` of the binding `bound` of `subject` ([`Self::challenge`]).
    #[expect(
        clippy::too_many_arguments,
        reason = "the private step of `challenge` and `account_challenge`, which take one less"
    )]
    async fn offer<S: Store>(
        &self,
        store: &mut S,
        subject: &Id<Human>,
        (binding, record, epoch): (Key, Record, Option<Dependency>),
        key: Key,
        now: Reading,
        random: &mut ChaCha20Rng,
        operation: OperationId,
    ) -> Result<Offer, Failure<S::Error>> {
        let pending = read(store, &key).await?;
        if let Some(pending) = &pending {
            let challenge = cli::challenge(pending, self.limits).ok_or(Error::Record)?;
            let end = pending.end.ok_or(Error::Record)?;
            if now.latest().map_err(Error::Time)? < end {
                return Ok(Offer::Open(challenge));
            }
        }
        let mut proposal = self.proposal(operation, subject, CHALLENGE, Value::Null, now)?;
        if let Some(epoch) = epoch {
            proposal.read(epoch).map_err(Error::Transition)?;
        }
        proposal
            .read(Dependency::Version(binding, record.version))
            .map_err(Error::Transition)?;
        let (challenge, version) = self.renew(&mut proposal, key.clone(), pending.as_ref(), now, random)?;
        proposal
            .prepare(Prepared::new(challenge.to_bytes().to_vec(), key, version))
            .map_err(Error::Transition)?;
        Ok(Offer::New(proposal, Plan::default()))
    }

    /// Admits the remote call `call` with the CLI credential `credential` and the proof `proof` of the possession of
    /// its `cnf` key over the request binding of `call` ([`cli::prove`]). The credential must be the credential of a
    /// live binding, an administrator binding or a CLI binding of an account ([`enroll`]), and the challenge of `call`
    /// the pending challenge of that binding, before its end. Thus a remote call refuses before its CLI enrolls, after
    /// an unlink of the binding, and with a challenge that a call consumed or a restore ended. [`Admitted::holder`]
    /// names the binding: give an administrator call only to [`Holder::Administrator`].
    ///
    /// The proposal reads the binding and the challenge record at their versions, and writes the next challenge into
    /// the record, so its commit consumes the challenge of `call`. Its deadline is the end of the challenge or of the
    /// credential, so its commit refuses after either one. Add the reads and the changes of the call to the proposal,
    /// then submit it with an empty [`Plan`]. Give the outcome of the commit to [`Admission::release`]: only the
    /// accepted commit of this proposal gives the [`Admitted`] call and its next challenge. The proposal carries the
    /// next challenge as its prepared artifact, so it carries no other artifact. Its operation is the operation of
    /// `call`, and its request names the authority and the request binding of `call`. An unlink of an administrator binding is a call of its
    /// own ([`Self::unlink`]).
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). Two signature checks of each composite artifact, and two
    /// keyed reads, or three for the CLI of an account.
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the credential or the proof refuses. [`Error::NotEnrolled`] if no live administrator
    /// binding holds the credential. [`Error::Challenge`] if the binding holds no pending challenge, another one, or
    /// one whose end passed. [`Error::Time`] if `now` has no bound or the end of the next challenge overflows.
    /// [`Error::Record`] if a record has no valid form, [`Failure::Store`] if a read fails, and
    /// [`Error::Transition`] for the proposal.
    pub async fn admit<S: Store>(
        &self,
        store: &mut S,
        credential: &[u8],
        proof: &[u8],
        call: &Call,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Admission), Failure<S::Error>> {
        let (proposal, admission, _) = self
            .admission(store, credential, proof, call, CALL, now, random)
            .await?;
        Ok((proposal, admission))
    }

    /// The unlink of the binding of the administrator of `unlink`, by the administrator of the CLI credential
    /// `credential`, whose proof `proof` signs the call of `unlink` ([`Unlink::call`], [`cli::prove`]). The proof binds
    /// the challenge, the operation, and the administrator of the unlink, so a proof of another call refuses. One
    /// commit consumes the challenge, as an admission does ([`Self::admit`]), and ends the binding: an anchor change
    /// with the last-anchor check. Its plan holds each administrator binding, so the commit driver refuses the unlink
    /// of the last one with [`transition::Error::LastAnchor`].
    ///
    /// The unlink keeps an administrator whose CLI credential is valid at `now`: the caller, or another one when the
    /// caller unlinks its own binding. The proposal reads that binding at its version, so two concurrent unlinks of the
    /// last two administrators conflict. Give the outcome to [`Admission::release`] for the next challenge.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The checks of [`Self::admit`], and one range read of the
    /// administrator bindings.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::admit`]. [`Error::NotEnrolled`] if the administrator of `unlink` has no binding. The unlink
    /// ends its binding with a valid CLI credential, else a binding whose credential ended.
    /// [`Error::Transition`] with [`transition::Error::LastAnchor`] if the caller unlinks its own binding and no other
    /// binding has a CLI credential that is valid at `now`. [`Error::Full`] if the authority has more than
    /// [`ADMINISTRATORS_MAX`] bindings, which an issue prevents.
    pub async fn unlink<S: Store>(
        &self,
        store: &mut S,
        credential: &[u8],
        proof: &[u8],
        unlink: &Unlink,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan, Admission), Failure<S::Error>> {
        let (mut proposal, admission, actor) = self
            .admission(store, credential, proof, &unlink.call, UNLINK, now, random)
            .await?;
        // The CLI of an account makes no administrator call.
        (admission.admitted.holder == Holder::Administrator).ok_or(Error::NotEnrolled)?;
        let live = self.administrators(store).await?;
        let named = |(.., held): &&(Key, Record, Binding)| held.issue.administrator == unlink.administrator;
        let (target, record, _) = live
            .iter()
            .filter(named)
            .find(|(.., held)| matches!(held.usable(now), Ok(true)))
            .or_else(|| live.iter().find(named))
            .ok_or(Error::NotEnrolled)?;
        // The admission read the binding of the caller. An unlink of it reads another administrator that stays.
        if *target == actor {
            let (survivor, record, _) = live
                .iter()
                .find(|(key, _, held)| *key != actor && matches!(held.usable(now), Ok(true)))
                .ok_or(Error::Transition(transition::Error::LastAnchor))?;
            proposal
                .read(Dependency::Version(survivor.clone(), record.version.clone()))
                .map_err(Error::Transition)?;
        }
        proposal
            .read(Dependency::Version(target.clone(), record.version.clone()))
            .map_err(Error::Transition)?;
        proposal
            .change(Change::End(target.clone()))
            .map_err(Error::Transition)?;
        let held = live
            .into_iter()
            .map(|(key, record, _)| Anchor {
                key,
                role: Role::Administrator(self.id.clone()),
                version: record.version,
                end: record.end,
                data: record.data,
            })
            .collect();
        let plan = Plan {
            held,
            ..Plan::default()
        };
        Ok((proposal, plan, admission))
    }

    /// The admission of `call` for `action`, and the key of the binding of the caller ([`Self::admit`]).
    #[expect(
        clippy::too_many_arguments,
        reason = "the private step of `admit` and `unlink`, which take one less"
    )]
    async fn admission<S: Store>(
        &self,
        store: &mut S,
        credential: &[u8],
        proof: &[u8],
        call: &Call,
        action: &str,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Admission, Key), Failure<S::Error>> {
        now.latest().map_err(Error::Time)?;
        let verified = self
            .profile
            .verify(credential, now, &mut SignatureBudget::new(&self.limits))
            .map_err(Error::Credential)?;
        let claims = verified.claims();
        let Subject::Human(subject) = &claims.subject else {
            return Err(Error::NotEnrolled.into());
        };
        // Each serial names one credential, so at most one of the two bindings holds it.
        let administrator = self.binding(subject, claims.serial);
        let (holder, binding, record) = match read(store, &administrator).await? {
            Some(record) => (Holder::Administrator, administrator, record),
            None => {
                let account = self.account_binding(subject, claims.serial);
                let record = read(store, &account).await?.ok_or(Error::NotEnrolled)?;
                (Holder::Account, account, record)
            }
        };
        (record.version == self.version(&claims.serial.0.to_be_bytes())).ok_or(Error::NotEnrolled)?;
        // The binding keeps the credential without its signature: another credential with the same serial refuses.
        let (protected, payload, epoch) = match holder {
            Holder::Administrator => {
                let held = self.decode(&record)?;
                (held.protected, held.payload, None)
            }
            Holder::Account => {
                let held = self.decode_account(&record)?;
                Self::check_epoch(store, &held.epoch).await?;
                (held.protected, held.payload, Some(held.epoch.dependency()))
            }
        };
        let sign1 = Sign1::decode(credential, self.limits).map_err(|error| Error::Credential(error.into()))?;
        (sign1.protected_bytes() == protected.as_slice() && sign1.payload() == payload.as_slice())
            .ok_or(Error::NotEnrolled)?;
        let key = match holder {
            Holder::Administrator => cli::key(&self.id, subject),
            Holder::Account => cli::binding_key(&self.id, &binding),
        };
        let pending = read(store, &key).await?.ok_or(Error::Challenge)?;
        let challenge = cli::challenge(&pending, self.limits).ok_or(Error::Record)?;
        let end = pending.end.ok_or(Error::Record)?;
        (challenge == call.challenge() && now.latest().map_err(Error::Time)? < end).ok_or(Error::Challenge)?;
        let evidence = verified
            .possession(proof, call.binding(), now, &mut SignatureBudget::new(&self.limits))
            .map_err(Error::Credential)?;
        let request = Value::Bytes(call.binding());
        let mut proposal = self.proposal(call.operation().clone(), subject, action, request, now)?;
        if let Some(epoch) = epoch {
            proposal.read(epoch).map_err(Error::Transition)?;
        }
        proposal
            .read(Dependency::Version(binding.clone(), record.version))
            .map_err(Error::Transition)?;
        proposal.until(end.min(claims.expires));
        let (next, version) = self.renew(&mut proposal, key.clone(), Some(&pending), now, random)?;
        proposal
            .prepare(Prepared::new(next.to_bytes().to_vec(), key, version))
            .map_err(Error::Transition)?;
        let admitted = Admitted {
            subject: subject.clone(),
            holder,
            evidence,
            next,
        };
        let admission = Admission {
            operation: call.operation().clone(),
            admitted,
        };
        Ok((proposal, admission, binding))
    }

    /// The report of the authority, oldest first. It gives each issue in its log with the state of its value at `now`,
    /// and each live administrator binding with the issue of its value. A restore keeps each live binding, but the log
    /// of an older snapshot does not name the issues after it. Thus the report of a restored store still gives each
    /// live administrator. It does not give an issue after the snapshot that left no live binding: the restore lost its
    /// value, or an unlink ended its binding.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One keyed read of the record of the authority, one range
    /// read of the administrator bindings, and at most one keyed read of the newest value.
    ///
    /// # Errors
    ///
    /// [`Error::Time`] if `now` has no bound and the newest value is not consumed. [`Error::Full`] if the authority has
    /// more than [`ADMINISTRATORS_MAX`] live bindings, which an issue prevents. The errors of [`Self::open`] for the
    /// record of the authority and its bindings.
    pub async fn report<S: Store>(&self, store: &mut S, now: Reading) -> Result<Report, Failure<S::Error>> {
        let log = match read(store, &self.key()).await? {
            Some(record) => self.log(&record)?,
            None => Vec::new(),
        };
        let mut live = Vec::new();
        for (.., held) in self.administrators(store).await? {
            if held.usable(now)? {
                live.push(held.issue);
            }
        }
        let mut issues = Vec::with_capacity(log.len() + live.len());
        for entry in log {
            let bound = live
                .iter()
                .position(|issue| issue.identity == entry.identity)
                .map(|index| live.remove(index))
                .is_some();
            let open =
                entry.state == State::Open && !bound && read(store, &value_key(&entry.identity)).await?.is_some();
            let status = match entry.state {
                State::Ended => Status::Ended,
                State::Open if open && expired(now, entry.expires)? => Status::Expired,
                State::Open if open => Status::Valid,
                State::Open | State::Consumed => Status::Consumed { bound },
            };
            issues.push(entry.issue(status));
        }
        issues.extend(
            live.into_iter()
                .map(|issue| issue.issue(Status::Consumed { bound: true })),
        );
        issues.sort_by_key(|issue| issue.issued);
        Ok(Report { issues })
    }

    /// The SHA-256 digest of the canonical CBOR form of the authority.
    fn digest(&self) -> [u8; 32] {
        crypto::sha256(&encode(&[self.id.to_cbor()]))
    }

    /// The key of the record of the authority: [`Kind::Local`] with the digest of the authority.
    fn key(&self) -> Key {
        Kind::Local.key(&self.digest()).expect("a key of 33 bytes is valid")
    }

    /// The prefix of the administrator bindings of the authority: [`Kind::Administrator`] with the digest of the
    /// authority.
    fn prefix(&self) -> Key {
        Kind::Administrator
            .key(&self.digest())
            .expect("a key of 33 bytes is valid")
    }

    /// The prefix of the bindings of `administrator`: the prefix of the authority, then the SHA-256 digest of the
    /// authority and the administrator.
    fn named(&self, administrator: &Id<Human>) -> Key {
        let digest = crypto::sha256(&encode(&[self.id.to_cbor(), administrator.to_cbor()]));
        Kind::Administrator
            .key(&[self.digest(), digest].concat())
            .expect("a key of 65 bytes is valid")
    }

    /// The key of the binding of `administrator` whose CLI credential has the serial `serial`: the prefix of the
    /// administrator, then the 8 bytes of the serial. A bootstrap that replaces an ended binding writes a new key, so a
    /// restore can complete it.
    fn binding(&self, administrator: &Id<Human>, serial: Serial) -> Key {
        Key::new(&[self.named(administrator).as_bytes(), &serial.0.to_be_bytes()].concat())
            .expect("a key of 73 bytes is valid")
    }

    /// Each administrator binding of the authority in key order: one range read of the prefix of the authority. A
    /// binding under the key of another administrator or serial has no valid form.
    async fn administrators<S: Store>(&self, store: &mut S) -> Result<Vec<(Key, Record, Binding)>, Failure<S::Error>> {
        let limit = NonZeroUsize::new(ADMINISTRATORS_MAX + 1).expect("the limit is not zero");
        let records = store.range(&self.prefix(), None, limit).await.map_err(Failure::Store)?;
        (records.len() <= ADMINISTRATORS_MAX).ok_or(Error::Full)?;
        let mut live = Vec::with_capacity(records.len());
        for (key, record) in records {
            let held = self.held(&key, &record)?;
            live.push((key, record, held));
        }
        Ok(live)
    }

    /// The binding of `administrator` whose CLI credential is valid at `now`, or `None`: one range read of the bindings
    /// of the administrator. A binding whose credential ended stays until expiry removes it, and an administrator has
    /// at most one other binding: an issue refuses an administrator with a valid one.
    async fn bound<S: Store>(
        &self,
        store: &mut S,
        administrator: &Id<Human>,
        now: Reading,
    ) -> Result<Option<(Key, Record, Binding)>, Failure<S::Error>> {
        let limit = NonZeroUsize::new(ADMINISTRATORS_MAX + 1).expect("the limit is not zero");
        let records = store
            .range(&self.named(administrator), None, limit)
            .await
            .map_err(Failure::Store)?;
        (records.len() <= ADMINISTRATORS_MAX).ok_or(Error::Full)?;
        for (key, record) in records {
            let held = self.held(&key, &record)?;
            if held.usable(now)? {
                return Ok(Some((key, record, held)));
            }
        }
        Ok(None)
    }

    /// The binding of the record `record` under `key`, after a check that `key` is the key of its administrator and its
    /// serial.
    fn held(&self, key: &Key, record: &Record) -> Result<Binding, Error> {
        let held = self.decode(record)?;
        let serial = record
            .version
            .coordinate()
            .try_into()
            .map(|serial| Serial(u64::from_be_bytes(serial)))
            .map_err(|_| Error::Record)?;
        (*key == self.binding(&held.issue.administrator, serial)).ok_or(Error::Record)?;
        Ok(held)
    }

    /// The binding of the record `record`, after a check that the grant and the issuer key of the authority bound it.
    fn decode(&self, record: &Record) -> Result<Binding, Error> {
        let value = cbor::decode(&record.data, self.limits).map_err(|_| Error::Record)?;
        let Value::Array(items) = &value else {
            return Err(Error::Record);
        };
        let [
            Value::Text(BINDING_FORM),
            issue,
            owner,
            origin,
            Value::Bytes(issuer),
            Value::Bytes(kid),
            Value::Unsigned(expires),
            Value::Bytes(holder),
            Value::Bytes(protected),
            Value::Bytes(payload),
        ] = items.as_slice()
        else {
            return Err(Error::Record);
        };
        let owner = Id::<Human>::from_cbor(owner).map_err(|_| Error::Record)?;
        let origin = Id::<Audience>::from_cbor(origin).map_err(|_| Error::Record)?;
        (owner == self.grant.owner && origin == self.grant.origin).ok_or(Error::Grant)?;
        (*issuer == self.issuer.id().to_bytes() && *kid == self.key.kid().as_slice()).ok_or(Error::Issuer)?;
        Ok(Binding {
            issue: Entry::from_cbor(issue).ok_or(Error::Record)?,
            expires: *expires,
            holder: (*holder).try_into().map_err(|_| Error::Record)?,
            protected: protected.to_vec(),
            payload: payload.to_vec(),
        })
    }

    /// The record form of a binding: `["rsauthnz.local.administrator.3", issue, owner, origin, issuer, kid, expires,
    /// holder, protected, payload]`. `issuer` is the custody ID of the issuer key and `kid` its COSE Key Thumbprint,
    /// `expires` the end of the CLI credential in whole seconds, `holder` the SHA-256 digest of its `cnf` key, and
    /// `protected` and `payload` the credential without its signature.
    fn binding_form(&self, issue: &Entry, expires: u64, holder: &[u8; 32], unsigned: &Unsigned) -> Box<[u8]> {
        encode(&[
            Value::Text(BINDING_FORM),
            issue.to_cbor(),
            self.grant.owner.to_cbor(),
            self.grant.origin.to_cbor(),
            Value::Bytes(&self.issuer.id().to_bytes()),
            Value::Bytes(self.key.kid()),
            Value::Unsigned(expires),
            Value::Bytes(holder),
            Value::Bytes(unsigned.protected()),
            Value::Bytes(unsigned.payload()),
        ])
        .into_boxed_slice()
    }

    /// The identity of `value`: the SHA-256 digest of the canonical CBOR form `["rsauthnz.local.bootstrap.1",
    /// authority, issuer public key, secret]`. Thus a value of another authority or issuer key has another identity.
    /// The digest reads the form in parts, so no buffer holds the secret.
    fn identity(&self, value: &Bootstrap) -> [u8; 32] {
        let public = self.issuer.public_key();
        let prefix = cbor::prefix(&[Value::Text(IDENTITY_FORM), self.id.to_cbor(), Value::Bytes(&public)]);
        let secret = value.0.as_bytes();
        let mut head = Vec::with_capacity(2);
        cbor::head(&mut head, 2, secret.len() as u64);
        crypto::sha256_parts(&[&prefix, &head, secret])
    }

    /// The version `coordinate` of the authority.
    fn version(&self, coordinate: &[u8]) -> AuthorityVersion {
        AuthorityVersion::new(self.id.clone(), coordinate).expect("each coordinate of this module is valid")
    }

    /// The next version of the record of the authority after `read`: a counter, then the identity of the new value.
    /// The identity makes each version unique, so a proposal from before a restore never finds an equal version of
    /// another state.
    fn next(&self, read: Option<AuthorityVersion>, identity: &[u8; 32]) -> Result<AuthorityVersion, Error> {
        let count = match read {
            Some(version) => {
                let count = version.coordinate().first_chunk::<8>().ok_or(Error::Record)?;
                u64::from_be_bytes(*count).checked_add(1).ok_or(Error::Record)?
            }
            None => 1,
        };
        Ok(self.version(&[count.to_be_bytes().as_slice(), identity].concat()))
    }

    /// Adds to `proposal` the read of the challenge record `key`, which is `pending` in the store, and the write of a
    /// new challenge into it, which ends after [`cli::CHALLENGE_LIFETIME`]. The version is a counter and the SHA-256
    /// digest of the challenge, as for the record of the authority. Thus `Debug` of the version shows no challenge.
    fn renew(
        &self,
        proposal: &mut Proposal,
        key: Key,
        pending: Option<&Record>,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Challenge, AuthorityVersion), Error> {
        let end = now
            .estimate()
            .checked_add(cli::CHALLENGE_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let challenge = Challenge::random(random);
        let version = self.next(
            pending.map(|record| record.version.clone()),
            &crypto::sha256(&challenge.to_bytes()),
        )?;
        proposal.read(dependency(&key, pending)).map_err(Error::Transition)?;
        proposal
            .change(Change::Write {
                key,
                version: version.clone(),
                end: Some(end),
                data: cli::record(challenge),
            })
            .map_err(Error::Transition)?;
        Ok((challenge, version))
    }

    /// A proposal of `actor` for `action` on `request`. Its request is `[authority, request]`, so one operation
    /// identity under two authorities of one store binds two requests.
    fn proposal(
        &self,
        operation: OperationId,
        actor: &Id<Human>,
        action: &str,
        request: Value<'_>,
        now: Reading,
    ) -> Result<Proposal, Error> {
        let audit = Audit {
            actor: Principal::Human(actor.clone()),
            action: Id::new("rsauthnz", action).expect("each action of this module is a valid identifier"),
            time: now,
        };
        let request = Value::Array(vec![self.id.to_cbor(), request]);
        Proposal::new(operation, audit, &request, self.limits).map_err(Error::Transition)
    }

    /// The log of the record of the authority, after a check of its grant and its issuer key.
    fn log(&self, record: &Record) -> Result<Vec<Entry>, Error> {
        let value = cbor::decode(&record.data, self.limits).map_err(|_| Error::Record)?;
        let Value::Array(items) = &value else {
            return Err(Error::Record);
        };
        let [
            Value::Text(RECORD_FORM),
            owner,
            origin,
            Value::Bytes(issuer),
            Value::Bytes(public),
            Value::Array(entries),
        ] = items.as_slice()
        else {
            return Err(Error::Record);
        };
        let owner = Id::<Human>::from_cbor(owner).map_err(|_| Error::Record)?;
        let origin = Id::<Audience>::from_cbor(origin).map_err(|_| Error::Record)?;
        (owner == self.grant.owner && origin == self.grant.origin).ok_or(Error::Grant)?;
        (*issuer == self.issuer.id().to_bytes() && *public == self.issuer.public_key()).ok_or(Error::Issuer)?;
        entries
            .iter()
            .map(Entry::from_cbor)
            .collect::<Option<_>>()
            .ok_or(Error::Record)
    }

    /// The record form of the authority with `log`. Each issue past [`ISSUES_MAX`] drops the oldest issue whose value
    /// bound no binding of `live` with a CLI credential that is valid at `now`, and so does a form that does not decode
    /// within the limits. A binding keeps its issue, so the report gives a dropped issue of a binding too. The newest
    /// issue stays. The loop ends: each step drops an issue or passes one.
    fn fit(&self, log: &mut Vec<Entry>, live: &[(Key, Record, Binding)], now: Reading) -> Result<Box<[u8]>, Error> {
        let (id, public) = (self.issuer.id().to_bytes(), self.issuer.public_key());
        let mut index = 0;
        loop {
            let entries: Vec<Value<'_>> = log.iter().map(Entry::to_cbor).collect();
            let form = Value::Array(vec![
                Value::Text(RECORD_FORM),
                self.grant.owner.to_cbor(),
                self.grant.origin.to_cbor(),
                Value::Bytes(&id),
                Value::Bytes(&public),
                Value::Array(entries),
            ]);
            // A form that encodes within the limits decodes within them.
            if log.len() <= ISSUES_MAX
                && let Ok(data) = cbor::encode(&form, self.limits)
            {
                return Ok(data.into_boxed_slice());
            }
            let (_, older) = log.split_last().expect("the log holds the new issue");
            let entry = older.get(index).ok_or(Error::Full)?;
            let bound = live
                .iter()
                .any(|(.., held)| held.issue.identity == entry.identity && matches!(held.usable(now), Ok(true)));
            if entry.state == State::Ended || !bound {
                log.remove(index);
            } else {
                index += 1;
            }
        }
    }

    /// The administrator, the time of the issue, and the end of the value record `record`.
    fn value(&self, record: &Record) -> Option<(Id<Human>, u64, u64)> {
        let value = cbor::decode(&record.data, self.limits).ok()?;
        let Value::Array(items) = &value else {
            return None;
        };
        let [
            Value::Text(VALUE_FORM),
            administrator,
            Value::Unsigned(issued),
            Value::Unsigned(expires),
        ] = items.as_slice()
        else {
            return None;
        };
        Some((Id::from_cbor(administrator).ok()?, *issued, *expires))
    }
}

/// The second step of a bootstrap: the draft of the CLI credential, which custody signs.
#[derive(Debug)]
pub struct Pending<'a> {
    authority: &'a Authority,
    draft: Draft,
    value: (Key, AuthorityVersion),
    issue: Entry,
    serial: Serial,
    holder: [u8; 32],
    /// The end of the CLI credential, in whole seconds.
    expires: u64,
    now: Reading,
}

impl Pending<'_> {
    /// The bytes that custody signs with the issuer key of the authority.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        self.draft.to_be_signed()
    }

    /// Verifies `signature` with the issuer key, and gives the proposal of the bootstrap and its plan. The commit
    /// consumes the value, writes the issuance record of the credential ([`Draft::record`]), and binds the
    /// administrator. The binding keeps the credential without its signature, so the proposal holds no signed
    /// credential outside its prepared artifact, and it ends with the credential. Its deadline is the end of the value. Its consumption entry in the restore journal records the
    /// transition, so a restore completes it when it is in doubt. Only the receipt of the accepted commit gives the
    /// credential. The client chooses `operation` and keeps it for a lookup.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the signature does not verify with the issuer key, and [`Error::Transition`] for the
    /// proposal.
    pub fn finish(self, signature: &[u8], operation: OperationId) -> Result<(Proposal, Plan), Error> {
        let authority = self.authority;
        let request = Value::Array(vec![Value::Bytes(&self.issue.identity), Value::Bytes(&self.holder)]);
        let mut proposal = authority.proposal(operation, &self.issue.administrator, CONSUME, request, self.now)?;
        let (value, version) = self.value;
        proposal
            .read(Dependency::Version(value.clone(), version))
            .map_err(Error::Transition)?;
        proposal.change(Change::End(value)).map_err(Error::Transition)?;
        proposal.until(Duration::from_secs(self.issue.expires));
        self.draft.record(&mut proposal).map_err(Error::Transition)?;
        let key = authority.binding(&self.issue.administrator, self.serial);
        proposal
            .read(Dependency::Absent(key.clone()))
            .map_err(Error::Transition)?;
        // The version is the serial, so a binding of the same administrator after an unlink has a later version than
        // the end entry of the unlink. The binding keeps the issue of the value, so a restore that keeps the binding
        // keeps the issue in the report. It ends with its credential, so expiry removes it.
        let data = authority.binding_form(&self.issue, self.expires, &self.holder, self.draft.unsigned());
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: authority.version(&self.serial.0.to_be_bytes()),
                end: Some(Duration::from_secs(self.expires)),
                data,
            })
            .map_err(Error::Transition)?;
        let credential = self
            .draft
            .finish(signature, &mut SignatureBudget::new(&authority.limits))
            .map_err(Error::Credential)?;
        proposal.prepare(credential).map_err(Error::Transition)?;
        let plan = Plan {
            anchors: vec![(key, Role::Administrator(authority.id.clone()))],
            ..Plan::default()
        };
        Ok((proposal, plan))
    }
}

/// The CLI credential of a binding, which custody signs again ([`Authority::credential`]).
#[derive(Debug)]
pub struct Reissue {
    unsigned: Unsigned,
    limits: Limits,
}

impl Reissue {
    /// The bytes that custody signs with the issuer key of the authority.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        self.unsigned.to_be_signed()
    }

    /// Verifies `signature` with the issuer key, and gives the credential of the binding.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the signature does not verify with the issuer key.
    pub fn finish(self, signature: &[u8]) -> Result<Vec<u8>, Error> {
        self.unsigned
            .sign(signature, &mut SignatureBudget::new(&self.limits))
            .map_err(Error::Credential)
    }
}

/// The unlink of the binding of an administrator, as a call of the CLI of an administrator ([`Authority::unlink`]):
/// its challenge, its operation, and the administrator. The CLI makes it and proves its call, and the authority makes
/// it again from the values that it received.
#[derive(Clone, Debug)]
pub struct Unlink {
    call: Call,
    administrator: Id<Human>,
}

impl Unlink {
    /// The unlink of the binding of `administrator` under `operation` over `challenge`. The request of its call is the
    /// canonical CBOR form `["rsauthnz.local.unlink.1", administrator]`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// The errors of [`Call::new`].
    pub fn new(
        challenge: Challenge,
        operation: OperationId,
        administrator: Id<Human>,
        limits: Limits,
    ) -> Result<Self, cli::Error> {
        let request = Value::Array(vec![Value::Text(UNLINK_FORM), administrator.to_cbor()]);
        let call = Call::new(challenge, operation, &request, limits)?;
        Ok(Self { call, administrator })
    }

    /// The call of the unlink, which the CLI proves ([`cli::prove`]).
    #[must_use]
    pub const fn call(&self) -> &Call {
        &self.call
    }

    /// The administrator whose binding the unlink ends.
    #[must_use]
    pub const fn administrator(&self) -> &Id<Human> {
        &self.administrator
    }
}

/// The challenge that a challenge request offers ([`Authority::challenge`]).
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "the caller matches the offer at once, as it takes `(Proposal, Plan)` from each other operation; a box adds an allocation to each request"
)]
pub enum Offer {
    /// The challenge record holds this challenge, which is valid at the time of the request. Nothing commits: give it
    /// to the CLI.
    Open(Challenge),
    /// The record holds no valid challenge. Submit the proposal of a new one with its plan: the receipt of the
    /// accepted commit gives the new challenge, as its artifact.
    New(Proposal, Plan),
}

/// An admission of a remote call whose proposal waits for its commit ([`Authority::admit`]). It gives no admitted call
/// before that commit.
#[derive(Debug)]
pub struct Admission {
    operation: OperationId,
    admitted: Admitted,
}

impl Admission {
    /// The admitted call that the accepted commit of the proposal of this admission gives. Each other outcome gives
    /// `None`: refuse the call, and follow the recovery of the outcome ([`Outcome::recovery`]). An earlier commit of the
    /// same operation gives `None` too, because only the commit of this proposal consumes the challenge.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn release(self, outcome: &Outcome) -> Option<Admitted> {
        let Outcome::Accepted(receipt) = outcome else {
            return None;
        };
        let next = self.admitted.next.to_bytes();
        (*receipt.operation() == self.operation && receipt.artifact() == Some(next.as_slice())).then_some(self.admitted)
    }
}

/// A remote call that the commit of its admission accepted: the evidence of the possession of the key of a live CLI
/// binding, and the challenge of the next call.
#[derive(Debug)]
pub struct Admitted {
    subject: Id<Human>,
    holder: Holder,
    evidence: Evidence,
    next: Challenge,
}

/// The binding of the CLI of a call: an administrator binding, or the binding of a CLI of an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Holder {
    /// The administrator binding that a bootstrap value paid for ([`Authority::bootstrap`]).
    Administrator,
    /// A CLI of an account, which the account approved in a browser ([`Authority::approve`]). It acts for the account
    /// under the policy of the application, and it makes no administrator call.
    Account,
}

impl Admitted {
    /// The human of the CLI credential: the administrator, or the account.
    #[must_use]
    pub const fn subject(&self) -> &Id<Human> {
        &self.subject
    }

    /// The binding of the CLI: give an administrator call only to [`Holder::Administrator`].
    #[must_use]
    pub const fn holder(&self) -> Holder {
        self.holder
    }

    /// The evidence of the possession.
    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The challenge of the next call of the CLI, which the commit wrote. Give it to the CLI in the response of the
    /// call.
    #[must_use]
    pub const fn next(&self) -> Challenge {
        self.next
    }
}

/// The report of a local authority: each issue of its log, oldest first. It holds no value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The issues.
    pub issues: Vec<Issue>,
}

/// One issue of a bootstrap value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// The administrator that the value names.
    pub administrator: Id<Human>,
    /// The time of the issue, in whole seconds since the Unix epoch.
    pub issued: Duration,
    /// The end of the value, in whole seconds since the Unix epoch.
    pub expires: Duration,
    /// The state of the value.
    pub status: Status,
}

/// The state of an issued value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// The value is not consumed, and a bootstrap can consume it until its end.
    Valid,
    /// The value is not consumed, and its end passed. The next issue ends it.
    Expired,
    /// A later issue ended the value before a consumption.
    Ended,
    /// The value is spent: a bootstrap consumed it, or a restore applied the end of the value from a history that the
    /// restore did not keep. `bound` is true while the administrator binding of the consumption is live, and false
    /// after an unlink or with no binding.
    Consumed {
        /// Whether the administrator binding of the consumption is live.
        bound: bool,
    },
}

/// The cause of a refused operation of a local authority. No error holds a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The text is not `rsauthnz-bootstrap-1-` and 64 lowercase hexadecimal digits. Refuse it.
    Form,
    /// This build on this CPU cannot encode or decode a bootstrap value with data-independent timing, as on Windows
    /// aarch64 without `-C target-feature=+dit`. Build with `-C target-feature=+dit`.
    Dit,
    /// The host grant is not the grant of the authority: another owner or origin. Open the authority with its grant.
    Grant,
    /// The custody key is not the issuer key of the authority. Open the authority with its issuer key.
    Issuer,
    /// The authority holds no valid record of the bootstrap value: it is consumed or ended, or it is a value of
    /// another authority or issuer key. Ask the local owner to issue a new value.
    Unknown,
    /// The end of the bootstrap value or of the enrollment request passed. Ask the local owner to issue a new value, or
    /// make a new request.
    Expired,
    /// The administrator has a live binding. Name another administrator, or unlink the binding.
    Bound,
    /// The store holds [`ADMINISTRATORS_MAX`] administrator bindings of the authority, each issue of the full log
    /// bound an administrator with a valid CLI credential, or the account has
    /// [`ACCOUNT_CLIS_MAX`](enroll::ACCOUNT_CLIS_MAX) CLI bindings. Run an expiry pass
    /// ([`store::expire`](crate::store::expire)), which removes each binding whose credential ended, or unlink an
    /// administrator, then try again.
    Full,
    /// No live administrator binding holds the credential or the administrator. Refuse the call.
    NotEnrolled,
    /// The binding holds no pending challenge, or another one, or one whose end passed: a call consumed it, a later
    /// issue replaced it, or a restore ended it. Refuse the call. The CLI asks for a new challenge, and makes a new call.
    Challenge,
    /// A record of the authority has no valid form. Restore the store from a snapshot.
    Record,
    /// The reading of the time has no bound, or a time overflows. Use a reading with a bound.
    Time(TimeError),
    /// The credential, its signature, or the proof of possession refuses. The error gives the cause.
    Credential(credential::Error),
    /// The proposal refuses. The error gives the recovery.
    Transition(transition::Error),
    /// The name of a CLI is empty, longer than [`CLI_NAME_BYTES_MAX`](enroll::CLI_NAME_BYTES_MAX), or holds a control
    /// character.
    Name,
    /// No open enrollment request has the user code and the device code: the request ended, or a finish consumed it.
    /// The CLI makes a new request.
    Request,
    /// The enrollment request had [`ATTEMPTS_MAX`](crate::agent::ATTEMPTS_MAX) wrong checks of its user code. The CLI
    /// makes a new request.
    Locked,
    /// No account approved the enrollment request yet. The CLI asks again after 5 seconds.
    Waiting,
    /// An account approved the enrollment request already.
    Approved,
    /// Another account approved the enrollment request. The CLI finishes with the account of [`Authority::poll`].
    Account,
    /// A loopback enrollment request has no redirect code or another one, or a request with no loopback address has
    /// one. Refuse it. A CLI whose browser did not bring the redirect code makes a new request.
    Redirect,
}

impl Recover for Error {
    /// Read the current state again when the challenge or the enrollment request changes.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Expired
            | Self::Challenge
            | Self::Request
            | Self::Locked
            | Self::Approved
            | Self::Waiting
            | Self::Account => Recovery::Restart,
            Self::Transition(error) => error.recovery(),
            _ => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Form => f.write_str("the text is not a bootstrap value"),
            Self::Dit => f.write_str("this build cannot handle a bootstrap value with data-independent timing"),
            Self::Grant => f.write_str("the host grant is not the grant of the authority"),
            Self::Issuer => f.write_str("the custody key is not the issuer key of the authority"),
            Self::Unknown => f.write_str("the authority holds no valid bootstrap value of this text"),
            Self::Expired => f.write_str("the bootstrap value expired"),
            Self::Bound => f.write_str("the administrator has a live binding"),
            Self::Full => {
                f.write_str("the authority has the most live administrators, or each issue of its log bound one")
            }
            Self::NotEnrolled => f.write_str("no live CLI binding holds the credential"),
            Self::Challenge => f.write_str("the binding holds no pending challenge of the call"),
            Self::Record => f.write_str("a record of the authority has no valid form"),
            Self::Time(error) => write!(f, "the time refused: {error}"),
            Self::Credential(error) => write!(f, "the credential refused: {error}"),
            Self::Transition(error) => write!(f, "the proposal refused: {error}"),
            Self::Name => f.write_str("the name of the CLI is not valid"),
            Self::Request => f.write_str("no open enrollment request has the codes"),
            Self::Locked => f.write_str("the enrollment request had too many wrong checks of its user code"),
            Self::Waiting => f.write_str("no account approved the enrollment request yet"),
            Self::Approved => f.write_str("an account approved the enrollment request already"),
            Self::Account => f.write_str("another account approved the enrollment request"),
            Self::Redirect => f.write_str("the redirect code is missing, wrong, or not expected"),
        }
    }
}

impl core::error::Error for Error {}

/// The failure of an operation that reads the store: a refusal, or a failed read.
pub type Failure<E> = crate::store::Failure<Error, E>;

/// The state of an issue in the log. An issue freezes the state of the issue before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The newest issue: its value record tells its state.
    Open,
    /// The value was gone at the next issue.
    Consumed,
    /// The next issue ended the value.
    Ended,
}

/// An administrator binding: the issue of the value that its consumption spent, the end of its CLI credential, the
/// digest of its `cnf` key, and the credential without its signature.
#[derive(Debug)]
struct Binding {
    issue: Entry,
    expires: u64,
    holder: [u8; 32],
    protected: Vec<u8>,
    payload: Vec<u8>,
}

impl Binding {
    /// Whether its CLI credential is valid at each time that `now` permits: a binding whose credential can be past its
    /// end is no administrator.
    fn usable(&self, now: Reading) -> Result<bool, Error> {
        Ok(now.latest().map_err(Error::Time)? < Duration::from_secs(self.expires))
    }
}

/// An issue in the log of the record of the authority, or in an administrator binding.
#[derive(Debug)]
struct Entry {
    identity: [u8; 32],
    administrator: Id<Human>,
    issued: u64,
    expires: u64,
    state: State,
}

impl Entry {
    /// The issue of the report with `status`.
    fn issue(self, status: Status) -> Issue {
        Issue {
            administrator: self.administrator,
            issued: Duration::from_secs(self.issued),
            expires: Duration::from_secs(self.expires),
            status,
        }
    }

    /// The form `[identity, administrator, issued, expires, state]`, with the state 0 for open, 1 for consumed, and 2
    /// for ended.
    fn to_cbor(&self) -> Value<'_> {
        Value::Array(vec![
            Value::Bytes(&self.identity),
            self.administrator.to_cbor(),
            Value::Unsigned(self.issued),
            Value::Unsigned(self.expires),
            Value::Unsigned(match self.state {
                State::Open => 0,
                State::Consumed => 1,
                State::Ended => 2,
            }),
        ])
    }

    fn from_cbor(value: &Value<'_>) -> Option<Self> {
        let Value::Array(items) = value else {
            return None;
        };
        let [
            Value::Bytes(identity),
            administrator,
            Value::Unsigned(issued),
            Value::Unsigned(expires),
            Value::Unsigned(state),
        ] = items.as_slice()
        else {
            return None;
        };
        Some(Self {
            identity: (*identity).try_into().ok()?,
            administrator: Id::from_cbor(administrator).ok()?,
            issued: *issued,
            expires: *expires,
            state: match state {
                0 => State::Open,
                1 => State::Consumed,
                2 => State::Ended,
                _ => return None,
            },
        })
    }
}

/// The key of the value record of the value with `identity`.
fn value_key(identity: &[u8; 32]) -> Key {
    Kind::Bootstrap.key(identity).expect("a key of 33 bytes is valid")
}

/// The read of `key` as a dependency: its version, or its absence.
fn dependency(key: &Key, record: Option<&Record>) -> Dependency {
    record.map_or_else(
        || Dependency::Absent(key.clone()),
        |record| Dependency::Version(key.clone(), record.version.clone()),
    )
}

/// Whether a value that ends at `expires`, in whole seconds, can be past its end at `now`.
fn expired(now: Reading, expires: u64) -> Result<bool, Error> {
    Ok(now.latest().map_err(Error::Time)? >= Duration::from_secs(expires))
}

/// The canonical CBOR form of the array `items`.
fn encode(items: &[Value<'_>]) -> Vec<u8> {
    cbor::encode(&Value::Array(items.to_vec()), Limits::FORM)
        .expect("the forms of this module have no map and no simple value")
}

/// The keyed read of `key`.
async fn read<S: Store>(store: &mut S, key: &Key) -> Result<Option<Record>, Failure<S::Error>> {
    store.read(key).await.map_err(Failure::Store)
}

#[cfg(test)]
mod tests;
