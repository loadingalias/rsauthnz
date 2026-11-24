//! The enrollment of a CLI that a human approves in a browser, in the shape of OAuth device authorization
//! ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).
//!
//! 1. The CLI stores its key in custody, then asks for an enrollment with its public key and a name
//!    ([`Authority::enroll`]). The commit writes the request, and gives the CLI a [`UserCode`] and a [`DeviceCode`].
//! 2. The CLI shows the user code and the address of the approval page. The human signs in there with a passkey, sees
//!    the name and the key fingerprint of the CLI ([`Authority::request`]), and approves with a fresh user verification
//!    ([`Authority::approve`]). The commit writes the request as approved by the account of the human.
//! 3. The CLI asks for the state of its request with its device code ([`Authority::poll`]), and learns the account.
//! 4. The CLI submits the finish ([`Authority::finish`]): one commit consumes the request and binds the key of the CLI
//!    to a CLI credential of the account. Its binding is an anchor of the account, and no sign-in method.
//!
//! After a lost response of the finish, the CLI gives its account and its public key, and custody signs the credential
//! of its binding again ([`Authority::account_credential`]). Each later call proves the possession of the key over a
//! one-use challenge of its binding ([`Authority::account_challenge`], [`Authority::admit`]).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use rscrypto::{ChaCha20Rng, SecretBytes};

use super::{Authority, CLI_LIFETIME, Error, Failure, Offer, Reissue, cli, encode, read};
use crate::account::{
    Fresh,
    generation::{Epoch, Revision},
};
use crate::cbor::{self, Value};
use crate::cli as calls;
use crate::cose::PublicKey;
use crate::credential::{Claims, Draft, Serial, Subject, Unsigned};
use crate::crypto;
use crate::id::{AuthorityVersion, Human, Id};
use crate::limits::SignatureBudget;
use crate::session::Access;
use crate::store::driver::Plan;
use crate::store::journal::Role;
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{Change, Dependency, Key, OperationId, Prepared, Proposal};
use core::num::NonZeroUsize;

/// The lifetime of an enrollment request: 10 minutes. An approval gives the CLI the same time again to finish.
pub const ENROLLMENT_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// The most bytes of the name of a CLI, which the approval page shows.
pub const CLI_NAME_BYTES_MAX: usize = 64;

/// The most active CLI bindings for one account, passkey site, and CLI issuer.
pub const ACCOUNT_CLIS_MAX: usize = 16;

/// The first item of each CBOR form of this module. The number changes with the form.
const REQUEST_FORM: &str = "rsauthnz.local.enrollment.2";
const ACCOUNT_FORM: &str = "rsauthnz.local.cli.2";
/// The actions of the audit records.
const ENROLL: &str = "cli.enroll";
const APPROVE: &str = "cli.approve";
const BIND: &str = "cli.bind";
const DISCONNECT: &str = "cli.disconnect";

/// The letters of a user code: the base20 alphabet of RFC 8628, section 6.1, with no vowel, so no code spells a word.
const LETTERS: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

/// The user code of an enrollment request: 8 letters of the base20 alphabet of RFC 8628, about 34 bits. The CLI shows
/// it as `WDJB-MJHT`, and the human gives it to the approval page. It finds the request, and it proves nothing: the
/// approval needs a fresh user verification. `Debug` does not show it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserCode([u8; 8]);

impl UserCode {
    /// Reads a user code: 8 letters of the alphabet in either case, with each `-` and space ignored.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Request`] for another text: no request has it.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut code = [0; 8];
        let mut letters = text.bytes().filter(|byte| !matches!(byte, b'-' | b' '));
        for slot in &mut code {
            let letter = letters.next().ok_or(Error::Request)?.to_ascii_uppercase();
            LETTERS.contains(&letter).ok_or(Error::Request)?;
            *slot = letter;
        }
        letters.next().is_none().ok_or(Error::Request)?;
        Ok(Self(code))
    }

    /// The text of the code: two groups of 4 letters, such as `WDJB-MJHT`.
    #[must_use]
    pub fn text(&self) -> String {
        let (head, tail) = self.0.split_at(4);
        [head, b"-", tail].concat().into_iter().map(char::from).collect()
    }

    /// A new code from `random`. A byte at or past 240 is drawn again, so each letter has the same chance.
    fn random(random: &mut ChaCha20Rng) -> Self {
        let mut code = [0; 8];
        for slot in &mut code {
            *slot = loop {
                let mut byte = [0];
                random.fill_bytes(&mut byte);
                if byte[0] < 240 {
                    break LETTERS[usize::from(byte[0] % 20)];
                }
            };
        }
        Self(code)
    }
}

impl fmt::Debug for UserCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserCode(..)")
    }
}

/// The device code of an enrollment request: 32 random bytes that only the CLI holds. It is a secret, so `Debug` does
/// not show it, and its memory is cleared when it drops. The store keeps only its SHA-256 digest.
pub struct DeviceCode(SecretBytes<32>);

impl DeviceCode {
    /// The device code of `bytes`, such as the artifact of the accepted commit of [`Authority::enroll`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let Ok(secret) = SecretBytes::try_fill_with(|secret| {
            secret.copy_from_slice(&bytes);
            Ok::<_, !>(())
        });
        Self(secret)
    }

    /// The bytes of the code, which the CLI sends with each poll and its finish.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// The SHA-256 digest of the code, which the request record keeps.
    fn digest(&self) -> [u8; 32] {
        crypto::sha256(self.0.as_bytes())
    }
}

impl fmt::Debug for DeviceCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceCode(..)")
    }
}

/// An enrollment request, as the approval page shows it to a signed-in human ([`Authority::request`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The name that the CLI gave, such as `alice-laptop`. Show it as text, never as markup.
    pub name: String,
    /// The SHA-256 digest of the public key of the CLI. The CLI shows the same digest, so the human can compare them.
    pub fingerprint: [u8; 32],
    /// The time of the request, as the time since the Unix epoch.
    pub created: Duration,
    /// The end of the request, as the time since the Unix epoch.
    pub ends: Duration,
    /// Whether an account approved the request.
    pub approved: bool,
}

/// The state of an enrollment request for its CLI ([`Authority::poll`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// No account approved the request yet. Ask again after 5 seconds.
    Waiting,
    /// The account approved the request. Submit the finish with it ([`Authority::finish`]).
    Approved(CliId),
}

/// The account and credential serial returned by browser approval. The CLI saves both before finishing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliId {
    /// The account that approved the request.
    pub account: Id<Human>,
    /// The credential serial reserved for this approval.
    pub serial: Serial,
}

/// The second step of an enrollment finish: the draft of the CLI credential, which custody signs
/// ([`Authority::finish`]).
#[derive(Debug)]
pub struct Finish<'a> {
    authority: &'a Authority,
    draft: Draft,
    request: (Key, Record),
    account: Id<Human>,
    serial: Serial,
    holder: [u8; 32],
    name: String,
    capacity: Capacity,
    epoch: Epoch,
    /// The end of the CLI credential, in whole seconds.
    expires: u64,
    now: Reading,
}

impl Finish<'_> {
    /// The bytes that custody signs with the issuer key of the authority.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        self.draft.to_be_signed()
    }

    /// Verifies `signature` with the issuer key, and gives the proposal of the finish and its plan. The commit
    /// consumes the request, writes the issuance record of the credential, and binds the key of the CLI to the
    /// account. The binding keeps the credential without its signature, and it ends with the credential. The plan names
    /// the binding as a CLI anchor of the account ([`Role::Cli`]), so the consumption entry of the restore journal
    /// records the transition, and a restore completes it when it is in doubt. Its deadline is the end of the request.
    /// Only the receipt of the accepted commit gives the credential. Choose `operation`, and keep it for a lookup.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the signature does not verify with the issuer key, and [`Error::Transition`] for the
    /// proposal.
    pub fn finish(self, signature: &[u8], operation: OperationId) -> Result<(Proposal, Plan), Error> {
        let authority = self.authority;
        let (request, record) = self.request;
        let end = record.end.ok_or(Error::Record)?;
        let form = Value::Array(vec![Value::Bytes(request.as_bytes()), Value::Bytes(&self.holder)]);
        let mut proposal = authority.proposal(operation, &self.account, BIND, form, self.now)?;
        proposal.read(self.epoch.dependency()).map_err(Error::Transition)?;
        proposal
            .read(Dependency::Version(request.clone(), record.version))
            .map_err(Error::Transition)?;
        proposal.change(Change::End(request)).map_err(Error::Transition)?;
        proposal.until(end);
        self.draft.record(&mut proposal).map_err(Error::Transition)?;
        let key = authority.account_binding(&self.account, self.serial);
        proposal
            .read(Dependency::Absent(key.clone()))
            .map_err(Error::Transition)?;
        let data = authority.account_form(&self.epoch, self.expires, &self.holder, self.draft.unsigned());
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
        let mut plan = Plan {
            anchors: vec![(key, Role::Cli(self.account.clone()))],
            ..Plan::default()
        };
        let prefix = authority.devices_prefix(&self.account, &self.epoch);
        let device = Device {
            serial: self.serial,
            fingerprint: self.holder,
            name: self.name,
            expires: Duration::from_secs(self.expires),
        };
        let key = device_key(&prefix, device.serial);
        proposal
            .read(Dependency::Absent(key.clone()))
            .map_err(Error::Transition)?;
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: authority.version(&self.serial.0.to_be_bytes()),
                end: Some(device.expires),
                data: encode(&[Value::Text(&device.name), Value::Bytes(&device.fingerprint)]).into_boxed_slice(),
            })
            .map_err(Error::Transition)?;
        plan.anchors.push((key, Role::AccountState(self.account.clone())));
        if let Some((key, version)) = self.capacity.expired {
            proposal
                .read(Dependency::Version(key.clone(), version))
                .map_err(Error::Transition)?;
            proposal.change(Change::End(key)).map_err(Error::Transition)?;
        }
        self.capacity
            .revision
            .write(
                &self.account,
                authority.version(&self.serial.0.to_be_bytes()),
                Box::default(),
                &mut proposal,
                &mut plan,
            )
            .map_err(Error::Transition)?;
        Ok((proposal, plan))
    }
}

/// An enrollment request record: `["rsauthnz.local.enrollment.2", device, holder, name, created, approved]`. `device`
/// is the SHA-256 digest of the device code, `holder` the public key of the CLI, `created` the time of the request in
/// whole seconds, and `approved` the account, reserved serial, and account revision, or null.
struct Pending {
    device: [u8; 32],
    holder: Vec<u8>,
    name: String,
    created: u64,
    approved: Option<(Id<Human>, Serial, Epoch)>,
}

/// A connected account CLI, as the owner sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// The identifier used to disconnect this binding.
    pub serial: Serial,
    /// The name shown when the owner approved the request.
    pub name: String,
    /// The SHA-256 digest of the CLI's public key.
    pub fingerprint: [u8; 32],
    /// The end of the credential, since the Unix epoch.
    pub expires: Duration,
}

/// All finishes that saw the same capacity claim the same successor key, including during restore.
#[derive(Debug)]
struct Capacity {
    revision: Revision,
    expired: Option<(Key, AuthorityVersion)>,
}

fn device_key(prefix: &Key, serial: Serial) -> Key {
    Key::new(&[prefix.as_bytes(), &serial.0.to_be_bytes()].concat()).expect("a device key has 41 bytes")
}

/// A CLI binding holds its account revision, expiry, holder digest, and credential
/// without its signature.
pub(super) struct Account {
    pub(super) epoch: Epoch,
    expires: u64,
    holder: [u8; 32],
    pub(super) protected: Vec<u8>,
    pub(super) payload: Vec<u8>,
}

impl Authority {
    /// Proposes an enrollment request of a CLI with the public key `holder`, an ML-DSA-65 + Ed25519 key, and the name
    /// `name`. The CLI stores the private part of `holder` in custody before the request. The commit writes the
    /// request, which ends after [`ENROLLMENT_LIFETIME`]. Give the CLI the user code at once, and the device code from
    /// the artifact of the accepted commit: [`DeviceCode::from_bytes`]. A request authenticates no caller, so its audit
    /// names the local owner. The operation identity is new: after a lost response, the CLI asks again, and the earlier
    /// request ends unused. Two requests with one user code conflict: ask again.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse), and its commit. Limit the rate of requests of one client.
    ///
    /// # Errors
    ///
    /// [`Error::Name`] if `name` is empty, longer than [`CLI_NAME_BYTES_MAX`], or holds a control character.
    /// [`Error::Time`] if `now` has no bound or the end overflows, and [`Error::Transition`] for the proposal.
    pub fn enroll(
        &self,
        holder: &[u8; 1984],
        name: &str,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan, UserCode), Error> {
        let valid = (1..=CLI_NAME_BYTES_MAX).contains(&name.len()) && !name.chars().any(char::is_control);
        valid.ok_or(Error::Name)?;
        now.latest().map_err(Error::Time)?;
        let code = UserCode::random(random);
        let mut device = [0; 32];
        random.fill_bytes(&mut device);
        let device = DeviceCode::from_bytes(device);
        let key = self.request_key(&code);
        let end = now
            .estimate()
            .checked_add(ENROLLMENT_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let mut operation = [0; 16];
        random.fill_bytes(&mut operation);
        let operation = OperationId::new(&operation).expect("16 bytes are a valid operation identity");
        let owner = self.grant.owner.clone();
        let mut proposal = self.proposal(operation, &owner, ENROLL, Value::Bytes(key.as_bytes()), now)?;
        proposal
            .read(Dependency::Absent(key.clone()))
            .map_err(Error::Transition)?;
        let version = self.next(None, &device.digest())?;
        let data = encode(&[
            Value::Text(REQUEST_FORM),
            Value::Bytes(&device.digest()),
            Value::Bytes(holder),
            Value::Text(name),
            Value::Unsigned(now.estimate().as_secs()),
            Value::Null,
        ]);
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: version.clone(),
                end: Some(end),
                data: data.into_boxed_slice(),
            })
            .map_err(Error::Transition)?;
        proposal
            .prepare(Prepared::new(device.as_bytes().to_vec(), key, version))
            .map_err(Error::Transition)?;
        Ok((proposal, Plan::default(), code))
    }

    /// The request of the user code `code`, for the approval page. Show it only to a signed-in human: it names the
    /// CLI. Show its fingerprint as the CLI shows it, so that the human approves only the CLI on their own screen.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One request lookup and, for an approved request, one account revision lookup.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] if no request has the code: it ended, or a finish consumed it. [`Error::Expired`] after its
    /// end, and [`Error::Time`] if `now` has no bound. [`Error::Record`] if the record has no valid form, and
    /// [`Failure::Store`] if the read fails.
    pub async fn request<S: Store>(
        &self,
        store: &mut S,
        code: &UserCode,
        now: Reading,
    ) -> Result<Request, Failure<S::Error>> {
        let (_, record, pending) = self.pending(store, code, now).await?;
        Ok(Request {
            fingerprint: crypto::sha256(&pending.holder),
            name: pending.name,
            created: Duration::from_secs(pending.created),
            ends: record.end.ok_or(Error::Record)?,
            approved: pending.approved.is_some(),
        })
    }

    /// Proposes the approval of the request of `code` by the account of `fresh`, a fresh user verification of a
    /// passkey session. Thus an approval comes only from a signed-in human, and the account comes only from the
    /// approval. Reserve `serial` with [`crate::store::driver::Driver::allocate`] for [`Kind::Credential`]. The CLI then has
    /// [`ENROLLMENT_LIFETIME`] to finish. It reads the session at its version, and the request at its version, so a
    /// second approval conflicts. Its deadline is the earliest of the end of the verification and of the request.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One request lookup and, for an approved request, one account revision lookup.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::request`]. [`Error::Approved`] if an account approved the request already. [`Error::Time`]
    /// if the end overflows, and [`Error::Transition`] for the proposal.
    pub async fn approve<S: Store>(
        &self,
        store: &mut S,
        fresh: &Fresh,
        code: &UserCode,
        serial: Serial,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        let (key, record, pending) = self.pending(store, code, now).await?;
        pending.approved.is_none().ok_or(Error::Approved)?;
        let account = fresh.account();
        let mut operation = [0; 16];
        random.fill_bytes(&mut operation);
        let operation = OperationId::new(&operation).expect("16 bytes are a valid operation identity");
        let form = Value::Bytes(key.as_bytes());
        let mut proposal = self.proposal(operation, account, APPROVE, form, now)?;
        fresh.gate(&mut proposal).map_err(Error::Transition)?;
        proposal.until(record.end.ok_or(Error::Record)?);
        let end = now
            .estimate()
            .checked_add(ENROLLMENT_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let version = self.next(
            Some(record.version.clone()),
            &crypto::sha256(&encode(&[account.to_cbor()])),
        )?;
        proposal
            .read(Dependency::Version(key.clone(), record.version))
            .map_err(Error::Transition)?;
        let data = encode(&[
            Value::Text(REQUEST_FORM),
            Value::Bytes(&pending.device),
            Value::Bytes(&pending.holder),
            Value::Text(&pending.name),
            Value::Unsigned(pending.created),
            Value::Array(vec![account.to_cbor(), Value::Unsigned(serial.0), fresh.epoch.form()]),
        ]);
        proposal
            .change(Change::Write {
                key,
                version,
                end: Some(end),
                data: data.into_boxed_slice(),
            })
            .map_err(Error::Transition)?;
        Ok((proposal, Plan::default()))
    }

    /// The state of the request of `code` for its CLI, which proves itself with its device code `device`. After
    /// [`Status::Approved`], store the [`CliId`] before sending the finish. It also identifies the binding after a lost response.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One request lookup and, for an approved request, one account revision lookup.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::request`], also when `device` is not the device code of the request.
    pub async fn poll<S: Store>(
        &self,
        store: &mut S,
        code: &UserCode,
        device: &DeviceCode,
        now: Reading,
    ) -> Result<Status, Failure<S::Error>> {
        let (_, _, pending) = self.pending(store, code, now).await?;
        (pending.device == device.digest()).ok_or(Error::Request)?;
        Ok(pending.approved.map_or(Status::Waiting, |(account, serial, _)| {
            Status::Approved(CliId { account, serial })
        }))
    }

    /// The first step of the finish of the request of `code` by its CLI, which proves itself with its device code
    /// `device`. The approval supplies the account and the reserved serial. Its `cnf` key is the public key of the request, so an approval
    /// of one request binds no other key. Custody signs the bytes of [`Finish::to_be_signed`] with the issuer key, and
    /// [`Finish::finish`] gives the proposal.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). Two keyed lookups, one capacity revision, and one bounded device page.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::request`], also when `device` is not the device code of the request. [`Error::Waiting`] if
    /// no account approved the request, and [`Error::Account`] if another account approved it. [`Error::Full`] if the
    /// account has [`ACCOUNT_CLIS_MAX`] bindings. [`Error::Credential`] if the draft refuses the public key.
    pub async fn finish<S: Store>(
        &self,
        store: &mut S,
        code: &UserCode,
        device: &DeviceCode,
        account: &Id<Human>,
        now: Reading,
    ) -> Result<Finish<'_>, Failure<S::Error>> {
        let (key, record, pending) = self.pending(store, code, now).await?;
        (pending.device == device.digest()).ok_or(Error::Request)?;
        let holder: &[u8; 1984] = pending.holder.as_slice().try_into().map_err(|_| Error::Record)?;
        let (approved, serial, epoch) = pending.approved.ok_or(Error::Waiting)?;
        (&approved == account).ok_or(Error::Account)?;
        let capacity = self.capacity(store, account, &epoch, now).await?;
        let expires = now
            .estimate()
            .checked_add(CLI_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let fingerprint = crypto::sha256(holder);
        let claims = Claims::new(
            self.id.clone(),
            self.grant.origin.clone(),
            Subject::Human(account.clone()),
            cli(),
            serial,
            expires,
        );
        let draft = Draft::credential(&self.key, &claims, Some(PublicKey::MlDsa65Ed25519(holder)), now)
            .map_err(Error::Credential)?;
        Ok(Finish {
            authority: self,
            draft,
            request: (key, record),
            account: account.clone(),
            serial,
            holder: fingerprint,
            epoch,
            name: pending.name,
            capacity,
            expires: expires.as_secs(),
            now,
        })
    }

    /// The CLI credential of the binding `id` whose `cnf` key is `holder`: the recovery of a CLI whose finish
    /// response was lost, or whose finish a restore completed. Custody signs the bytes of [`Reissue::to_be_signed`]
    /// again, and [`Reissue::finish`] gives the same credential.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). Two keyed lookups for the binding and account revision.
    /// The signature of custody is the cost of the host: limit the rate of recoveries of one account.
    ///
    /// # Errors
    ///
    /// [`Error::NotEnrolled`] if `id` and `holder` have no current binding. [`Error::Time`] if the reading has no bound.
    /// [`Error::Record`], [`Error::Grant`], or [`Error::Issuer`] for an invalid binding. [`Failure::Store`] if a read fails.
    pub async fn account_credential<S: Store>(
        &self,
        store: &mut S,
        id: &CliId,
        holder: &[u8; 1984],
        now: Reading,
    ) -> Result<Reissue, Failure<S::Error>> {
        let (_, _, held) = self.account_bound(store, &id.account, id.serial, holder, now).await?;
        Ok(Reissue {
            unsigned: Unsigned::from_parts(self.key.clone(), &held.protected, &held.payload),
            limits: self.limits,
        })
    }

    /// The challenge for the next call of the binding `id` with the `cnf` key `holder`, as
    /// [`Self::challenge`] gives it for an administrator. Each binding has its own challenge record, so two CLIs of
    /// one account take no challenge of each other.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). Three keyed lookups for the binding, account revision, and challenge.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::account_credential`], and of [`Self::challenge`] for the proposal.
    pub async fn account_challenge<S: Store>(
        &self,
        store: &mut S,
        id: &CliId,
        holder: &[u8; 1984],
        now: Reading,
        random: &mut ChaCha20Rng,
        operation: OperationId,
    ) -> Result<Offer, Failure<S::Error>> {
        let (binding, record, held) = self.account_bound(store, &id.account, id.serial, holder, now).await?;
        let key = calls::binding_key(&self.id, &binding);
        self.offer(
            store,
            &id.account,
            (binding, record, Some(held.epoch.dependency())),
            key,
            now,
            random,
            operation,
        )
        .await
    }

    /// The key of the request of `code`: [`Kind::CliEnrollment`] with the SHA-256 digest of the canonical CBOR form
    /// `["rsauthnz.local.enrollment.2", authority, code]`.
    fn request_key(&self, code: &UserCode) -> Key {
        let digest = crypto::sha256(&encode(&[
            Value::Text(REQUEST_FORM),
            self.id.to_cbor(),
            Value::Bytes(&code.0),
        ]));
        Kind::CliEnrollment.key(&digest).expect("a key of 33 bytes is valid")
    }

    /// The key, the record, and the request of `code`, while it is open at `now`.
    async fn pending<S: Store>(
        &self,
        store: &mut S,
        code: &UserCode,
        now: Reading,
    ) -> Result<(Key, Record, Pending), Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        let key = self.request_key(code);
        let record = read(store, &key).await?.ok_or(Error::Request)?;
        (latest < record.end.ok_or(Error::Record)?).ok_or(Error::Expired)?;
        let pending = self.decode_request(&record).ok_or(Error::Record)?;
        if let Some((_, _, epoch)) = &pending.approved {
            Self::check_epoch(store, epoch).await?;
        }
        Ok((key, record, pending))
    }

    /// The request of the record `record`, or `None` for another form.
    fn decode_request(&self, record: &Record) -> Option<Pending> {
        let value = cbor::decode(&record.data, self.limits).ok()?;
        let Value::Array(items) = &value else {
            return None;
        };
        let [
            Value::Text(REQUEST_FORM),
            Value::Bytes(device),
            Value::Bytes(holder),
            Value::Text(name),
            Value::Unsigned(created),
            approved,
        ] = items.as_slice()
        else {
            return None;
        };
        let approved = match approved {
            Value::Null => None,
            Value::Array(items) => {
                let [account, Value::Unsigned(serial), epoch] = items.as_slice() else {
                    return None;
                };
                Some((Id::from_cbor(account).ok()?, Serial(*serial), Epoch::parse(epoch)?))
            }
            _ => return None,
        };
        Some(Pending {
            device: (*device).try_into().ok()?,
            holder: holder.to_vec(),
            name: (*name).into(),
            created: *created,
            approved,
        })
    }

    /// The prefix of the CLI bindings of `account`: [`Kind::Credential`] with the SHA-256 digest of the canonical
    /// CBOR form `["rsauthnz.local.cli.2", authority, account]`.
    fn account_prefix(&self, account: &Id<Human>) -> Key {
        let digest = crypto::sha256(&encode(&[
            Value::Text(ACCOUNT_FORM),
            self.id.to_cbor(),
            account.to_cbor(),
        ]));
        Kind::Credential.key(&digest).expect("a key of 33 bytes is valid")
    }

    /// The key of the CLI binding of `account` whose credential has the serial `serial`: the prefix of the account,
    /// then the 8 bytes of the serial.
    pub(super) fn account_binding(&self, account: &Id<Human>, serial: Serial) -> Key {
        Key::new(&[self.account_prefix(account).as_bytes(), &serial.0.to_be_bytes()].concat())
            .expect("a key of 41 bytes is valid")
    }

    fn devices_prefix(&self, account: &Id<Human>, epoch: &Epoch) -> Key {
        let scope = crypto::sha256(&encode(&[
            Value::Text("rsauthnz.local.devices.1"),
            self.id.to_cbor(),
            account.to_cbor(),
            epoch.form(),
        ]));
        Kind::Credential.key(&scope).expect("a device prefix has 33 bytes")
    }

    async fn devices<S: Store>(
        &self,
        store: &mut S,
        account: &Id<Human>,
        epoch: &Epoch,
    ) -> Result<Vec<(Key, Record)>, Failure<S::Error>> {
        let limit = NonZeroUsize::new(ACCOUNT_CLIS_MAX + 1).expect("the device limit is positive");
        let rows = store
            .range(&self.devices_prefix(account, epoch), None, limit)
            .await
            .map_err(Failure::Store)?;
        (rows.len() <= ACCOUNT_CLIS_MAX).ok_or(Error::Full)?;
        Ok(rows)
    }

    async fn capacity<S: Store>(
        &self,
        store: &mut S,
        account: &Id<Human>,
        epoch: &Epoch,
        now: Reading,
    ) -> Result<Capacity, Failure<S::Error>> {
        let scope = crypto::sha256(&encode(&[
            Value::Text("rsauthnz.local.capacity.1"),
            self.id.to_cbor(),
            account.to_cbor(),
            Value::Bytes(&epoch.scope),
        ]));
        // Read the revision first. An intervening enrollment must conflict even if the device page changes.
        let revision = Revision::read(store, &scope)
            .await
            .map_err(Failure::Store)?
            .ok_or(Error::Record)?;
        let rows = self.devices(store, account, epoch).await?;
        let earliest = now.earliest().map_err(Error::Time)?;
        let expired = if rows.len() == ACCOUNT_CLIS_MAX {
            Some(
                rows.into_iter()
                    .find(|(_, record)| record.end.is_some_and(|end| end <= earliest))
                    .map(|(key, record)| (key, record.version))
                    .ok_or(Error::Full)?,
            )
        } else {
            None
        };
        Ok(Capacity { revision, expired })
    }

    /// Lists the connected CLIs of the signed-in owner at this passkey site in one bounded page.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One paired session read and one page of at most 17 records.
    ///
    /// # Errors
    ///
    /// [`Error::NotEnrolled`] if the session ended. A store failure or an invalid record refuses the listing.
    pub async fn account_clis<S: Store>(
        &self,
        store: &mut S,
        access: &Access,
        now: Reading,
    ) -> Result<Vec<Device>, Failure<S::Error>> {
        let session = access.session();
        let latest = now.latest().map_err(Error::Time)?;
        let rows = self.devices(store, session.account(), &session.epoch).await?;
        let [family, guard] = store
            .read_pair([session.key(), &session.epoch.key()])
            .await
            .map_err(Failure::Store)?;
        (family
            .as_ref()
            .is_some_and(|record| &record.version == session.version())
            && session.epoch.holds(guard.as_ref())
            && latest < session.end())
        .ok_or(Error::NotEnrolled)?;
        let mut devices = Vec::with_capacity(rows.len());
        for (key, record) in rows {
            let expires = record.end.ok_or(Error::Record)?;
            if expires <= latest {
                continue;
            }
            let serial = Serial(u64::from_be_bytes(
                key.as_bytes()
                    .get(33..)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Record)?,
            ));
            let form = cbor::decode(&record.data, self.limits).map_err(|_| Error::Record)?;
            let Value::Array(fields) = form else {
                return Err(Error::Record.into());
            };
            let [Value::Text(name), Value::Bytes(fingerprint)] = fields.as_slice() else {
                return Err(Error::Record.into());
            };
            devices.push(Device {
                serial,
                name: (*name).into(),
                fingerprint: (*fingerprint).try_into().map_err(|_| Error::Record)?,
                expires,
            });
        }
        Ok(devices)
    }

    /// Proposes the end of one account CLI after fresh user verification. Submit the proposal and its plan together.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One paired read and one commit.
    ///
    /// # Errors
    ///
    /// [`Error::Expired`] if verification expired. [`Error::NotEnrolled`] if this account has no such live CLI.
    pub async fn disconnect<S: Store>(
        &self,
        store: &mut S,
        fresh: &Fresh,
        serial: Serial,
        now: Reading,
        operation: OperationId,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        (latest < fresh.deadline()).ok_or(Error::Expired)?;
        let binding = self.account_binding(fresh.account(), serial);
        let device = device_key(&self.devices_prefix(fresh.account(), &fresh.epoch), serial);
        let [bound, listed] = store.read_pair([&binding, &device]).await.map_err(Failure::Store)?;
        let bound = bound.ok_or(Error::NotEnrolled)?;
        let listed = listed.ok_or(Error::NotEnrolled)?;
        (self.decode_account(&bound)?.epoch == fresh.epoch && latest < bound.end.ok_or(Error::Record)?)
            .ok_or(Error::NotEnrolled)?;
        let mut proposal = self.proposal(
            operation,
            fresh.account(),
            DISCONNECT,
            Value::Bytes(binding.as_bytes()),
            now,
        )?;
        fresh.gate(&mut proposal).map_err(Error::Transition)?;
        for (key, record) in [(binding, bound), (device, listed)] {
            proposal
                .read(Dependency::Version(key.clone(), record.version))
                .map_err(Error::Transition)?;
            proposal.change(Change::End(key)).map_err(Error::Transition)?;
        }
        Ok((proposal, Plan::default()))
    }

    /// Reads one binding by the serial returned at approval.
    async fn account_bound<S: Store>(
        &self,
        store: &mut S,
        account: &Id<Human>,
        serial: Serial,
        holder: &[u8; 1984],
        now: Reading,
    ) -> Result<(Key, Record, Account), Failure<S::Error>> {
        let key = self.account_binding(account, serial);
        let record = read(store, &key).await?.ok_or(Error::NotEnrolled)?;
        let held = self.decode_account(&record)?;
        (held.holder == crypto::sha256(holder)
            && now.latest().map_err(Error::Time)? < Duration::from_secs(held.expires))
        .ok_or(Error::NotEnrolled)?;
        Self::check_epoch(store, &held.epoch).await?;
        Ok((key, record, held))
    }

    pub(super) async fn check_epoch<S: Store>(store: &mut S, epoch: &Epoch) -> Result<(), Failure<S::Error>> {
        epoch
            .holds(read(store, &epoch.key()).await?.as_ref())
            .ok_or(Error::NotEnrolled)?;
        Ok(())
    }

    /// The record form of a CLI binding of an account: `["rsauthnz.local.cli.2", owner, origin, issuer, kid,
    /// expires, holder, epoch, protected, payload]`, as the form of an administrator binding names them.
    pub(super) fn account_form(
        &self,
        epoch: &Epoch,
        expires: u64,
        holder: &[u8; 32],
        unsigned: &Unsigned,
    ) -> Box<[u8]> {
        encode(&[
            Value::Text(ACCOUNT_FORM),
            self.grant.owner.to_cbor(),
            self.grant.origin.to_cbor(),
            Value::Bytes(&self.issuer.id().to_bytes()),
            Value::Bytes(self.key.kid()),
            Value::Unsigned(expires),
            Value::Bytes(holder),
            epoch.form(),
            Value::Bytes(unsigned.protected()),
            Value::Bytes(unsigned.payload()),
        ])
        .into_boxed_slice()
    }

    /// The CLI binding of the record `record`, after a check that the grant and the issuer key of the authority bound
    /// it.
    pub(super) fn decode_account(&self, record: &Record) -> Result<Account, Error> {
        let value = cbor::decode(&record.data, self.limits).map_err(|_| Error::Record)?;
        let Value::Array(items) = &value else {
            return Err(Error::Record);
        };
        let [
            Value::Text(ACCOUNT_FORM),
            owner,
            origin,
            Value::Bytes(issuer),
            Value::Bytes(kid),
            Value::Unsigned(expires),
            Value::Bytes(holder),
            epoch,
            Value::Bytes(protected),
            Value::Bytes(payload),
        ] = items.as_slice()
        else {
            return Err(Error::Record);
        };
        let owner = Id::<Human>::from_cbor(owner).map_err(|_| Error::Record)?;
        let origin = Id::from_cbor(origin).map_err(|_| Error::Record)?;
        (owner == self.grant.owner && origin == self.grant.origin).ok_or(Error::Grant)?;
        (*issuer == self.issuer.id().to_bytes() && *kid == self.key.kid()).ok_or(Error::Issuer)?;
        Ok(Account {
            epoch: Epoch::parse(epoch).ok_or(Error::Record)?,
            expires: *expires,
            holder: (*holder).try_into().map_err(|_| Error::Record)?,
            protected: protected.to_vec(),
            payload: payload.to_vec(),
        })
    }
}
