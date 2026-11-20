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
//! and [`Pending::finish`] gives the proposal. Its commit consumes the value and binds the administrator. A remote
//! call is admitted only for the credential of a live administrator binding ([`Authority::admit`]). Thus remote access
//! refuses before a separate identity enrolls.
//!
//! The store keeps no secret. A value record holds the administrator and the end of the value, under a key that the
//! SHA-256 digest of the authority, the issuer public key, and the secret names. Thus a value of another authority, or
//! of another issuer key, finds no record. The record of the authority ([`Kind::Local`]) holds the grant, the issuer
//! key, and the log of the last [`ISSUES_MAX`] issues: the report of each issue and each consumption
//! ([`Authority::report`]).
//!
//! Each operation reads the store with [`Store::read`] and gives a proposal and its plan. Submit them to the commit
//! driver ([`Driver::submit`](crate::store::driver::Driver::submit)). Only the receipt of the accepted commit gives
//! the bootstrap value or the credential. After a lost response, the outcome lookup shows the commit and no value:
//! the owner issues again, and that issue ends the value of the lost commit.
//!
//! This example runs the journey on the memory binding of `rsauthnz-conformance`. rscrypto signs in place of custody,
//! so that the example holds its keys.
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::cose::{Key, PublicKey, TrustedKey};
//! use rsauthnz::credential::{ProofDraft, Serial};
//! use rsauthnz::crypto::Algorithm;
//! use rsauthnz::custody::{Handle, KeyId};
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::{Limits, SignatureBudget};
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
//! let (holder_public, holder_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(2)))?;
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
//! // 3. On a remote call, the administrator proves the possession of its key over the challenge of the call.
//! let holder = TrustedKey::new(Algorithm::MlDsa65Ed25519, &Key {
//!     kid: None,
//!     alg: None,
//!     public: PublicKey::MlDsa65Ed25519(&holder_public),
//! })?;
//! let challenge = [9; 32];
//! let draft = ProofDraft::new(&holder, &credential, &grant.origin, &challenge, now)?;
//! let signature = holder_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//! let proof = draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?;
//! let admitted = ready(authority.admit(&mut memory, &credential, &proof, &challenge, now))?;
//! assert_eq!(admitted.administrator(), &alice);
//!
//! // The value is one-use.
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
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};
use core::time::Duration;

use rscrypto::ChaCha20Rng;

use crate::cbor::{self, Value};
use crate::cose::{Key as CoseKey, PublicKey, TrustedKey};
use crate::credential::{self, Claims, Draft, Serial, Subject};
use crate::crypto::{self, Algorithm};
use crate::custody::Handle;
use crate::evidence::Evidence;
use crate::id::{Audience, Authority as AuthorityKind, AuthorityVersion, Human, Id, Principal, Purpose};
use crate::limits::{Limits, SignatureBudget};
use crate::store::driver::Plan;
use crate::store::journal::{Anchor, Role};
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{self, Audit, Change, Dependency, Key, OperationId, Prepared, Proposal};

/// The declared lifetime of a bootstrap value: the first value and each value of a re-bootstrap. A consumption at or
/// after the end refuses, and the local owner issues a new value.
pub const LIFETIME: Duration = Duration::from_secs(15 * 60);

/// The lifetime of the CLI credential that a bootstrap issues: 365 days.
pub const CLI_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The most issues in the log of an authority. An issue past it drops the oldest issue whose value bound no live
/// administrator.
pub const ISSUES_MAX: usize = 64;

/// The text of a bootstrap value: this prefix and 64 lowercase hexadecimal digits.
const PREFIX: &str = "rsauthnz-bootstrap-1-";
/// The first item of each CBOR form of this module. The number changes with the form.
const IDENTITY_FORM: &str = "rsauthnz.local.bootstrap.1";
const RECORD_FORM: &str = "rsauthnz.local.1";
const VALUE_FORM: &str = "rsauthnz.local.value.1";
const BINDING_FORM: &str = "rsauthnz.local.administrator.1";
/// The actions of the audit records.
const ISSUE: &str = "bootstrap.issue";
const CONSUME: &str = "bootstrap.consume";
const UNLINK: &str = "administrator.unlink";

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
/// a secret, so `Debug` does not show it.
pub struct Bootstrap([u8; 32]);

impl Bootstrap {
    /// Reads the text of a bootstrap value.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Form`] if `text` is not `rsauthnz-bootstrap-1-` and 64 lowercase hexadecimal digits.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let hex = text.strip_prefix(PREFIX).ok_or(Error::Form)?;
        let (pairs, []) = hex.as_bytes().as_chunks::<2>() else {
            return Err(Error::Form);
        };
        let mut secret = [0; 32];
        (pairs.len() == secret.len()).ok_or(Error::Form)?;
        for (byte, [high, low]) in secret.iter_mut().zip(pairs) {
            *byte = (digit(*high)? << 4) | digit(*low)?;
        }
        Ok(Self(secret))
    }

    /// The text of the value.
    fn text(&self) -> String {
        let mut text = String::with_capacity(PREFIX.len() + 64);
        text.push_str(PREFIX);
        for byte in self.0 {
            write!(text, "{byte:02x}").expect("a write to a String does not fail");
        }
        text
    }
}

impl fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bootstrap(..)")
    }
}

/// The value of a lowercase hexadecimal digit.
const fn digit(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::Form),
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
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One keyed read of the record of the authority.
    ///
    /// # Errors
    ///
    /// [`Error::Grant`] if the record of the authority has another owner or origin. [`Error::Issuer`] if it has
    /// another issuer key. [`Error::Record`] if the record has no valid form. [`Failure::Store`] if the read fails.
    pub async fn open<S: Store>(
        store: &mut S,
        grant: &HostGrant,
        id: Id<AuthorityKind>,
        issuer: Handle,
        limits: Limits,
    ) -> Result<Self, Failure<S::Error>> {
        let public = issuer.public_key();
        let public = match issuer.algorithm() {
            Algorithm::MlDsa65Ed25519 => public.as_slice().try_into().map(PublicKey::MlDsa65Ed25519),
            Algorithm::MlDsa65EcdsaP256 => public.as_slice().try_into().map(PublicKey::MlDsa65EcdsaP256),
            _ => return Err(Error::Issuer.into()),
        }
        .map_err(|_| Error::Issuer)?;
        let key = TrustedKey::new(
            issuer.algorithm(),
            &CoseKey {
                kid: None,
                alg: None,
                public,
            },
        )
        .map_err(|_| Error::Issuer)?;
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
        if let Some(record) = read(store, &authority.key()).await? {
            authority.log(&record)?;
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
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). Three keyed reads, and one more for each issue that a
    /// full log drops.
    ///
    /// # Errors
    ///
    /// [`Error::Grant`] if `grant` is not the grant that opened the authority. [`Error::Bound`] if `administrator` has
    /// a live binding. [`Error::Full`] if the log cannot drop an issue. [`Error::Time`] if the end of the value
    /// overflows. The errors of [`Self::open`] for the record of the authority, and [`Error::Transition`] for the
    /// proposal.
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
        let issued = now.estimate().as_secs();
        let expires = issued
            .checked_add(LIFETIME.as_secs())
            .ok_or(Error::Time(TimeError::Overflow))?;
        let mut secret = [0; 32];
        random.fill_bytes(&mut secret);
        let value = Bootstrap(secret);
        let identity = self.identity(&value);
        let value_data = encode(&[
            Value::Text(VALUE_FORM),
            administrator.to_cbor(),
            Value::Unsigned(expires),
        ]);
        let request = Value::Array(vec![
            Value::Bytes(&identity),
            administrator.to_cbor(),
            Value::Unsigned(expires),
        ]);
        let mut proposal = self.proposal(operation, &self.grant.owner, ISSUE, &request, now)?;
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
        let binding = self.binding(&administrator);
        if read(store, &binding).await?.is_some() {
            return Err(Error::Bound.into());
        }
        proposal.read(Dependency::Absent(binding)).map_err(Error::Transition)?;
        log.push(Entry {
            identity,
            administrator,
            issued,
            expires,
            state: State::Open,
        });
        let data = self.fit(store, &mut log).await?;
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
        proposal
            .change(Change::Write {
                key,
                version: self.version(&[1]),
                end: None,
                data: value_data.into_boxed_slice(),
            })
            .map_err(Error::Transition)?;
        proposal.prepare(Prepared::new(value.text().into_bytes().into_boxed_slice()));
        Ok((proposal, Plan::default()))
    }

    /// The first step of a bootstrap: the CLI credential of the administrator of `value`, with the `cnf` key `holder`,
    /// an ML-DSA-65 + Ed25519 key, and the serial `serial` ([`Driver::allocate`] of [`Kind::Credential`]). The client
    /// stores the private part of `holder` in its custody before it submits the value. Custody signs the bytes of
    /// [`Pending::to_be_signed`] with the issuer key, and [`Pending::finish`] gives the proposal.
    ///
    /// [`Driver::allocate`]: crate::store::driver::Driver::allocate
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed read, and a check of `holder`.
    ///
    /// # Errors
    ///
    /// [`Error::Unknown`] if the authority holds no valid record of `value`: it is consumed or ended, or it is a value
    /// of another authority or issuer key. [`Error::Expired`] at or after the end of the value, and [`Error::Time`] if
    /// `now` has no bound. [`Error::Credential`] if the draft refuses `holder`. [`Error::Record`] if the record of the
    /// value has no valid form, and [`Failure::Store`] if the read fails.
    pub async fn bootstrap<S: Store>(
        &self,
        store: &mut S,
        value: &Bootstrap,
        holder: &[u8; 1984],
        serial: Serial,
        now: Reading,
    ) -> Result<Pending<'_>, Failure<S::Error>> {
        let identity = self.identity(value);
        let key = value_key(&identity);
        let record = read(store, &key).await?.ok_or(Error::Unknown)?;
        let (administrator, expires) = self.value(&record).ok_or(Error::Record)?;
        if expired(now, expires)? {
            return Err(Error::Expired.into());
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
            administrator,
            identity,
            serial,
            holder: crypto::sha256(holder),
            now,
        })
    }

    /// The CLI credential that the consumption of `value` issued, from the binding of `administrator`, the
    /// administrator that the value names: the recovery of a client whose response was lost, or whose bootstrap a
    /// restore completed. It is no secret: a call needs the possession of its `cnf` key too.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One keyed read.
    ///
    /// # Errors
    ///
    /// [`Error::Unknown`] if no live binding of `administrator` holds the consumption of `value`: the consumption did
    /// not commit, an unlink ended the binding, or the value names another administrator. [`Error::Record`] if the
    /// binding has no valid form, and [`Failure::Store`] if the read fails.
    pub async fn credential<S: Store>(
        &self,
        store: &mut S,
        value: &Bootstrap,
        administrator: &Id<Human>,
    ) -> Result<Vec<u8>, Failure<S::Error>> {
        let record = read(store, &self.binding(administrator)).await?.ok_or(Error::Unknown)?;
        let (identity, credential) = decode_binding(&record, self.limits).ok_or(Error::Record)?;
        (identity == self.identity(value)).ok_or(Error::Unknown)?;
        Ok(credential)
    }

    /// Admits a remote call with the CLI credential `credential` and the proof `proof` of the possession of its `cnf`
    /// key over `challenge`, which the host chose for this call. The credential must be the credential of a live
    /// administrator binding. Thus a remote call refuses before an administrator enrolls, and after an unlink of the
    /// binding.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). Two signature checks of each composite artifact, and one
    /// keyed read.
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the credential or the proof refuses. [`Error::NotEnrolled`] if no live administrator
    /// binding holds the credential. [`Failure::Store`] if the read fails.
    pub async fn admit<S: Store>(
        &self,
        store: &mut S,
        credential: &[u8],
        proof: &[u8],
        challenge: &[u8],
        now: Reading,
    ) -> Result<Admitted, Failure<S::Error>> {
        let verified = self
            .profile
            .verify(credential, now, &mut SignatureBudget::new(&self.limits))
            .map_err(Error::Credential)?;
        let claims = verified.claims();
        let Subject::Human(administrator) = &claims.subject else {
            return Err(Error::NotEnrolled.into());
        };
        let record = read(store, &self.binding(administrator))
            .await?
            .ok_or(Error::NotEnrolled)?;
        (record.version == self.version(&claims.serial.0.to_be_bytes())).ok_or(Error::NotEnrolled)?;
        let evidence = verified
            .possession(proof, challenge, now, &mut SignatureBudget::new(&self.limits))
            .map_err(Error::Credential)?;
        Ok(Admitted {
            authority: self.id.clone(),
            administrator: administrator.clone(),
            version: record.version,
            evidence,
        })
    }

    /// The unlink of the binding of `administrator` by the admitted administrator `actor`: an anchor change with the
    /// last-anchor check. The plan holds each live administrator binding, so the commit driver refuses the unlink of
    /// the last one with [`transition::Error::LastAnchor`]. An administrator can unlink its own binding when another
    /// one is live.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One keyed read of the record of the authority, and one of
    /// each administrator binding in its log.
    ///
    /// # Errors
    ///
    /// [`Error::NotEnrolled`] if `actor` is of another authority, or `administrator` has no live binding. The errors
    /// of [`Self::open`] for the record of the authority, and [`Error::Transition`] for the proposal, such as
    /// [`transition::Error::Changed`] when the binding of `actor` changed after its admission.
    pub async fn unlink<S: Store>(
        &self,
        store: &mut S,
        actor: &Admitted,
        administrator: &Id<Human>,
        now: Reading,
        operation: OperationId,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        (actor.authority == self.id).ok_or(Error::NotEnrolled)?;
        let key = self.binding(administrator);
        let record = read(store, &key).await?.ok_or(Error::NotEnrolled)?;
        let request = Value::Array(vec![administrator.to_cbor()]);
        let mut proposal = self.proposal(operation, &actor.administrator, UNLINK, &request, now)?;
        proposal
            .read(Dependency::Version(
                self.binding(&actor.administrator),
                actor.version.clone(),
            ))
            .map_err(Error::Transition)?;
        proposal
            .read(Dependency::Version(key.clone(), record.version))
            .map_err(Error::Transition)?;
        proposal.change(Change::End(key)).map_err(Error::Transition)?;
        // The bindings that the log names, and the binding that the unlink ends: a restore keeps a binding whose issue
        // came after its snapshot, and the log of the snapshot does not name it. A binding that the plan lacks can
        // only make the check refuse.
        let log = match read(store, &self.key()).await? {
            Some(record) => self.log(&record)?,
            None => Vec::new(),
        };
        let administrators: BTreeSet<&Id<Human>> = log
            .iter()
            .map(|entry| &entry.administrator)
            .chain([administrator])
            .collect();
        let mut held = Vec::new();
        for administrator in administrators {
            let key = self.binding(administrator);
            if let Some(record) = read(store, &key).await? {
                held.push(Anchor {
                    key,
                    role: Role::Administrator(self.id.clone()),
                    version: record.version,
                    end: record.end,
                    data: record.data,
                });
            }
        }
        Ok((
            proposal,
            Plan {
                held,
                ..Plan::default()
            },
        ))
    }

    /// The report of the authority: each issue in its log, oldest first, with the state of its value at `now`.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One keyed read of the record of the authority, and at most
    /// one more for each issue.
    ///
    /// # Errors
    ///
    /// [`Error::Time`] if `now` has no bound and the newest value is not consumed. The errors of [`Self::open`] for the
    /// record of the authority.
    pub async fn report<S: Store>(&self, store: &mut S, now: Reading) -> Result<Report, Failure<S::Error>> {
        let log = match read(store, &self.key()).await? {
            Some(record) => self.log(&record)?,
            None => Vec::new(),
        };
        let mut issues = Vec::with_capacity(log.len());
        for entry in log {
            let open = entry.state == State::Open && read(store, &value_key(&entry.identity)).await?.is_some();
            let status = match entry.state {
                State::Ended => Status::Ended,
                State::Open if open && expired(now, entry.expires)? => Status::Expired,
                State::Open if open => Status::Valid,
                State::Open | State::Consumed => Status::Consumed {
                    bound: self.bound(store, &entry).await?,
                },
            };
            issues.push(Issue {
                administrator: entry.administrator,
                issued: Duration::from_secs(entry.issued),
                expires: Duration::from_secs(entry.expires),
                status,
            });
        }
        Ok(Report { issues })
    }

    /// The key of the record of the authority: [`Kind::Local`] with the SHA-256 digest of the canonical CBOR form of the
    /// authority.
    fn key(&self) -> Key {
        Kind::Local
            .key(&crypto::sha256(&encode(&[self.id.to_cbor()])))
            .expect("a key of 33 bytes is valid")
    }

    /// The key of the administrator binding of `administrator`: [`Kind::Administrator`] with the SHA-256 digest of the
    /// authority and the administrator.
    fn binding(&self, administrator: &Id<Human>) -> Key {
        Kind::Administrator
            .key(&crypto::sha256(&encode(&[self.id.to_cbor(), administrator.to_cbor()])))
            .expect("a key of 33 bytes is valid")
    }

    /// The identity of `value`: the SHA-256 digest of the authority, the issuer public key, and the secret. Thus a value
    /// of another authority or issuer key has another identity.
    fn identity(&self, value: &Bootstrap) -> [u8; 32] {
        crypto::sha256(&encode(&[
            Value::Text(IDENTITY_FORM),
            self.id.to_cbor(),
            Value::Bytes(&self.issuer.public_key()),
            Value::Bytes(&value.0),
        ]))
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

    /// A proposal of `actor` for `action` on `request`.
    fn proposal(
        &self,
        operation: OperationId,
        actor: &Id<Human>,
        action: &str,
        request: &Value<'_>,
        now: Reading,
    ) -> Result<Proposal, Error> {
        let audit = Audit {
            actor: Principal::Human(actor.clone()),
            action: Id::new("rsauthnz", action).expect("each action of this module is a valid identifier"),
            time: now,
        };
        Proposal::new(operation, audit, request, self.limits).map_err(Error::Transition)
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
    /// bound no live administrator, and so does a form that does not decode within the limits. The newest issue stays.
    /// The loop ends: each step drops an issue or passes one.
    async fn fit<S: Store>(&self, store: &mut S, log: &mut Vec<Entry>) -> Result<Box<[u8]>, Failure<S::Error>> {
        let (id, public) = (self.issuer.id().to_bytes(), self.issuer.public_key());
        let mut index = 0;
        loop {
            let entries: Vec<Value<'_>> = log.iter().map(Entry::to_cbor).collect();
            let data = encode(&[
                Value::Text(RECORD_FORM),
                self.grant.owner.to_cbor(),
                self.grant.origin.to_cbor(),
                Value::Bytes(&id),
                Value::Bytes(&public),
                Value::Array(entries),
            ]);
            if log.len() <= ISSUES_MAX && cbor::decode(&data, self.limits).is_ok() {
                return Ok(data.into_boxed_slice());
            }
            let (_, older) = log.split_last().expect("the log holds the new issue");
            let entry = older.get(index).ok_or(Error::Full)?;
            if entry.state == State::Ended || !self.bound(store, entry).await? {
                log.remove(index);
            } else {
                index += 1;
            }
        }
    }

    /// Whether the binding of the administrator of `entry` is live and holds the consumption of its value.
    async fn bound<S: Store>(&self, store: &mut S, entry: &Entry) -> Result<bool, Failure<S::Error>> {
        let Some(record) = read(store, &self.binding(&entry.administrator)).await? else {
            return Ok(false);
        };
        let (identity, _) = decode_binding(&record, self.limits).ok_or(Error::Record)?;
        Ok(identity == entry.identity)
    }

    /// The administrator and the end of the value record `record`.
    fn value(&self, record: &Record) -> Option<(Id<Human>, u64)> {
        let value = cbor::decode(&record.data, self.limits).ok()?;
        let Value::Array(items) = &value else {
            return None;
        };
        let [Value::Text(VALUE_FORM), administrator, Value::Unsigned(expires)] = items.as_slice() else {
            return None;
        };
        Some((Id::from_cbor(administrator).ok()?, *expires))
    }
}

/// The second step of a bootstrap: the draft of the CLI credential, which custody signs.
#[derive(Debug)]
pub struct Pending<'a> {
    authority: &'a Authority,
    draft: Draft,
    value: (Key, AuthorityVersion),
    administrator: Id<Human>,
    identity: [u8; 32],
    serial: Serial,
    holder: [u8; 32],
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
    /// consumes the value and binds the administrator, with the credential in its binding. Its consumption entry in
    /// the restore journal records the transition, so a restore completes it when it is in doubt. Only the receipt of
    /// the accepted commit gives the credential. The client chooses `operation` and keeps it for a lookup.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the signature does not verify with the issuer key, and [`Error::Transition`] for the
    /// proposal.
    pub fn finish(self, signature: &[u8], operation: OperationId) -> Result<(Proposal, Plan), Error> {
        let authority = self.authority;
        let credential = self
            .draft
            .finish(signature, &mut SignatureBudget::new(&authority.limits))
            .map_err(Error::Credential)?;
        let request = Value::Array(vec![Value::Bytes(&self.identity), Value::Bytes(&self.holder)]);
        let mut proposal = authority.proposal(operation, &self.administrator, CONSUME, &request, self.now)?;
        let (value, version) = self.value;
        proposal
            .read(Dependency::Version(value.clone(), version))
            .map_err(Error::Transition)?;
        proposal.change(Change::End(value)).map_err(Error::Transition)?;
        let key = authority.binding(&self.administrator);
        proposal
            .read(Dependency::Absent(key.clone()))
            .map_err(Error::Transition)?;
        // The version is the serial, so a binding of the same administrator after an unlink has a later version than
        // the end entry of the unlink.
        let data = encode(&[
            Value::Text(BINDING_FORM),
            Value::Bytes(&self.identity),
            Value::Bytes(credential.as_bytes()),
        ]);
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: authority.version(&self.serial.0.to_be_bytes()),
                end: None,
                data: data.into_boxed_slice(),
            })
            .map_err(Error::Transition)?;
        proposal.prepare(credential);
        let plan = Plan {
            anchors: vec![(key, Role::Administrator(authority.id.clone()))],
            ..Plan::default()
        };
        Ok((proposal, plan))
    }
}

/// A remote call that [`Authority::admit`] admitted: the evidence of the possession of the key of a live
/// administrator binding.
#[derive(Debug)]
pub struct Admitted {
    authority: Id<AuthorityKind>,
    administrator: Id<Human>,
    version: AuthorityVersion,
    evidence: Evidence,
}

impl Admitted {
    /// The administrator.
    #[must_use]
    pub const fn administrator(&self) -> &Id<Human> {
        &self.administrator
    }

    /// The evidence of the possession.
    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
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
    /// The host grant is not the grant of the authority: another owner or origin. Open the authority with its grant.
    Grant,
    /// The custody key is not the issuer key of the authority, or not a composite key. Open the authority with its
    /// issuer key.
    Issuer,
    /// The authority holds no valid record of the bootstrap value: it is consumed or ended, or it is a value of
    /// another authority or issuer key. Ask the local owner to issue a new value.
    Unknown,
    /// The end of the bootstrap value passed. Ask the local owner to issue a new value.
    Expired,
    /// The administrator has a live binding. Name another administrator, or unlink the binding.
    Bound,
    /// Each issue of the full log bound a live administrator. Unlink an administrator, then issue again.
    Full,
    /// No live administrator binding holds the credential or the administrator. Refuse the call.
    NotEnrolled,
    /// A record of the authority has no valid form. Restore the store from a snapshot.
    Record,
    /// The reading of the time has no bound, or a time overflows. Use a reading with a bound.
    Time(TimeError),
    /// The credential, its signature, or the proof of possession refuses. The error gives the cause.
    Credential(credential::Error),
    /// The proposal refuses. The error gives the recovery.
    Transition(transition::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Form => f.write_str("the text is not a bootstrap value"),
            Self::Grant => f.write_str("the host grant is not the grant of the authority"),
            Self::Issuer => f.write_str("the custody key is not the issuer key of the authority"),
            Self::Unknown => f.write_str("the authority holds no valid bootstrap value of this text"),
            Self::Expired => f.write_str("the bootstrap value expired"),
            Self::Bound => f.write_str("the administrator has a live binding"),
            Self::Full => f.write_str("each issue of the log bound a live administrator"),
            Self::NotEnrolled => f.write_str("no live administrator binding holds the credential"),
            Self::Record => f.write_str("a record of the authority has no valid form"),
            Self::Time(error) => write!(f, "the time refused: {error}"),
            Self::Credential(error) => write!(f, "the credential refused: {error}"),
            Self::Transition(error) => write!(f, "the proposal refused: {error}"),
        }
    }
}

impl core::error::Error for Error {}

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

/// An issue in the log of the record of the authority.
struct Entry {
    identity: [u8; 32],
    administrator: Id<Human>,
    issued: u64,
    expires: u64,
    state: State,
}

impl Entry {
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

/// The identity of the value and the credential of the administrator binding `record`.
fn decode_binding(record: &Record, limits: Limits) -> Option<([u8; 32], Vec<u8>)> {
    let value = cbor::decode(&record.data, limits).ok()?;
    let Value::Array(items) = &value else {
        return None;
    };
    let [
        Value::Text(BINDING_FORM),
        Value::Bytes(identity),
        Value::Bytes(credential),
    ] = items.as_slice()
    else {
        return None;
    };
    Some(((*identity).try_into().ok()?, credential.to_vec()))
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
    cbor::encode(&Value::Array(items.to_vec())).expect("the forms of this module have no map and no simple value")
}

/// The keyed read of `key`.
async fn read<S: Store>(store: &mut S, key: &Key) -> Result<Option<Record>, Failure<S::Error>> {
    store.read(key).await.map_err(Failure::Store)
}

#[cfg(test)]
mod tests;
