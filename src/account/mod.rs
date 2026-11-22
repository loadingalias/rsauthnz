//! Accounts: invitations, the passkeys of an account, and the gate of a fresh user verification.
//!
//! An invitation lets one recipient activate one account. [`RelyingParty::invite`] checks the authority of the issuer
//! with the policy of the application, and it proposes the invitation record. Only the accepted commit releases the
//! invitation value: [`INVITATION_BYTES`] random bytes, such as in the link that the issuer sends. The store keeps only
//! a digest of the value, so a read of the store gives no usable invitation.
//!
//! The invitation is the registration ceremony of its activation:
//!
//! 1. [`RelyingParty::activation_options`] reads the invitation and gives the options of the first passkey of the
//!    recipient. It writes nothing: the challenge holds the invitation key and its time under an HMAC-SHA256 tag of
//!    the key of the relying party.
//! 2. [`RelyingParty::activate`] checks the response, the recipient, and the current authority of the issuer. Its
//!    commit consumes the invitation and writes the passkey. The plan names the passkey as a sign-in method of the
//!    account, so a restore completes an activation that a crash left in doubt.
//!
//! A sensitive change needs a fresh user verification ([`Fresh`]): the evidence of the session has user
//! verification, and it is at most [`FRESH_MAX`] old at the commit. The sensitive changes are an additional passkey
//! ([`Decision::Add`](crate::passkey::Decision::Add)), the removal of a passkey ([`RelyingParty::remove`]), a new
//! recovery code ([`RelyingParty::recovery_code`]), and the end of another session of the account
//! ([`Revoker::Fresh`](crate::session::Revoker::Fresh)). A rename needs only the session of the account
//! ([`RelyingParty::rename`]).
//!
//! The example asks for the options of an activation on the memory binding of `rsauthnz-conformance`. A value that
//! is not an open invitation refuses after one keyed read. An issue needs the evidence of a signed-in issuer, and a
//! finish needs a browser and an authenticator.
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::account::{INVITATION_BYTES, Invitee};
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::Limits;
//! use rsauthnz::passkey::{Error, Failure, RelyingParty};
//! use rsauthnz::store::driver::Driver;
//! use rsauthnz::store::{Profile, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz_conformance::memory::{Memory, Schedule};
//! use rsauthnz_conformance::suite::execute;
//! use rscrypto::ChaCha20Rng;
//!
//! /// The output of a future of the memory binding, which is ready at its first poll.
//! fn ready<T>(future: impl Future<Output = T>) -> T {
//!     let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
//!         unreachable!("the memory binding does no I/O");
//!     };
//!     output
//! }
//!
//! let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! let mut memory = Memory::new(Schedule::None);
//! let mut driver = Driver::new(Profile::new(memory.declaration())?, Limits::default())?;
//! driver.start(now);
//! while let Some(effect) = driver.effect() {
//!     let output = ready(execute(&mut memory, effect));
//!     driver.give(output)?;
//! }
//! let mut random = ChaCha20Rng::from_seed([7; 32]);
//! let rp = RelyingParty::new(Id::new("acme", "auth")?, "app.example", "https://app.example", "Acme", [3; 32], Limits::default())?;
//!
//! // Bob opens the link of an invitation with a value that the store does not hold.
//! let bob = Id::new("acme", "bob")?;
//! let invitee = Invitee { account: &bob, name: "bob@app.example", display_name: "Bob" };
//! let refused = ready(rp.activation_options(&mut memory, &[1; INVITATION_BYTES], &invitee, now, &mut random));
//! assert!(matches!(refused, Err(Failure::Refused(Error::Invitation))));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use rscrypto::ChaCha20Rng;

use crate::authz::{self, Policy};
use crate::cbor::Value;
use crate::crypto;
use crate::evidence::Evidence;
use crate::id::{Action, AuthorityVersion, Human, Id, Principal, Resource};
use crate::passkey::{self, Credential, Failure, RelyingParty, Response, User, UserHandle};
use crate::session::{Access, Generation};
use crate::store::driver::{Driver, Plan};
use crate::store::journal::{Anchor, Role};
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{self, Change, Dependency, Key, OperationId, Prepared, Proposal, Recover, Recovery};

/// The most time from the user verification of a session to the commit of a sensitive change: 300 seconds. An
/// application can only make it shorter ([`Fresh::check`]).
pub const FRESH_MAX: Duration = Duration::from_secs(300);

/// The longest lifetime of an invitation: 7 days.
pub const INVITATION_LIFETIME_MAX: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The bytes of an invitation value: 32 random bytes.
pub const INVITATION_BYTES: usize = 32;

/// The record form of an invitation, and the domain of the digest of its value.
const INVITATION_FORM: &str = "rsauthnz.invitation.1";

/// The domain of the tag of an activation challenge, and of the operation identity of an activation.
const ACTIVATION_FORM: &str = "rsauthnz.passkey.activation.1";

/// The audit actions.
const INVITE: &str = "invitation.issue";
const ACTIVATE: &str = "invitation.activate";
const RENAME: &str = "passkey.rename";
const REMOVE: &str = "passkey.remove";

/// A fresh user verification of a signed-in account: a session whose evidence has user verification and is at most
/// [`FRESH_MAX`] old. A fresh verification is a passkey sign-in that replaces the session
/// ([`SignIn::open`](crate::passkey::SignIn::open) with the current session). A sensitive change takes it: its commit
/// reads the session at its version, so a revocation or a renewal of the session conflicts, and its deadline is the
/// end of the verification.
#[derive(Clone, Debug)]
pub struct Fresh {
    session: Key,
    version: AuthorityVersion,
    account: Id<Human>,
    deadline: Duration,
}

impl Fresh {
    /// Checks that `access`, the session of a request, has a fresh user verification at `now`: its evidence has user
    /// verification, and its earliest time is less than `max_age` before the latest time of `now`. `max_age` is at most
    /// [`FRESH_MAX`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Stale`] if the evidence has no user verification or is older than `max_age`: verify the user again.
    /// [`Error::Replaced`] if `access` holds the replaced generation. [`Error::Window`] if `max_age` is longer than
    /// [`FRESH_MAX`], and [`Error::Time`] if a reading has no bound.
    pub fn check(access: &Access, max_age: Duration, now: Reading) -> Result<Self, Error> {
        (max_age <= FRESH_MAX).ok_or(Error::Window)?;
        (access.generation() == Generation::Current).ok_or(Error::Replaced)?;
        let session = access.session();
        let evidence = session.evidence();
        evidence.user_verified().ok_or(Error::Stale)?;
        let verified = evidence.time().earliest().map_err(Error::Time)?;
        let deadline = verified
            .checked_add(max_age)
            .ok_or(Error::Time(TimeError::Overflow))?
            .min(session.end());
        (now.latest().map_err(Error::Time)? < deadline).ok_or(Error::Stale)?;
        Ok(Self {
            session: session.key().clone(),
            version: session.version().clone(),
            account: session.account().clone(),
            deadline,
        })
    }

    /// The account of the verification.
    #[must_use]
    pub const fn account(&self) -> &Id<Human> {
        &self.account
    }

    /// The end of the verification, as the time since the Unix epoch: the earliest of its time plus the maximum age,
    /// and the end of its session. A commit at or after it refuses.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Adds the gate to `proposal`: the read of the session at its version, and the deadline.
    pub(crate) fn gate(&self, proposal: &mut Proposal) -> Result<(), transition::Error> {
        proposal.read(Dependency::Version(self.session.clone(), self.version.clone()))?;
        proposal.until(self.deadline);
        Ok(())
    }
}

/// The invitation of [`RelyingParty::invite`].
#[derive(Clone, Copy, Debug)]
pub struct Invite<'a> {
    /// The account that the invitation activates.
    pub recipient: &'a Id<Human>,
    /// The user handle of the account, which each passkey of the account has. Draw it for a new account.
    pub handle: UserHandle,
    /// The action of the issuer, such as `acme:team.invite`. The policy must permit it on `resource` at the issue and at
    /// the activation.
    pub action: &'a Id<Action>,
    /// The resource of the action, such as the team that the recipient joins.
    pub resource: &'a Id<Resource>,
    /// The time from the issue to the end of the invitation: more than zero, and at most
    /// [`INVITATION_LIFETIME_MAX`].
    pub lifetime: Duration,
}

/// The recipient of an activation ([`RelyingParty::activation_options`]), and the names that the authenticator shows.
/// Each name has 1 to [`NAME_BYTES_MAX`](crate::passkey::NAME_BYTES_MAX) bytes.
#[derive(Clone, Copy, Debug)]
pub struct Invitee<'a> {
    /// The account that the activation activates. It must be the recipient of the invitation.
    pub account: &'a Id<Human>,
    /// The name, such as an email address or a username.
    pub name: &'a str,
    /// The display name, such as a full name.
    pub display_name: &'a str,
}

/// A checked activation that waits for the decision of the application: the account, its first passkey, the action of
/// the issuer, and the commit that [`RelyingParty::activate`] made.
pub struct Activation {
    account: Id<Human>,
    credential: Credential,
    action: Id<Action>,
    resource: Id<Resource>,
    proposal: Proposal,
    plan: Plan,
}

impl Activation {
    /// The account that the invitation activates.
    #[must_use]
    pub const fn account(&self) -> &Id<Human> {
        &self.account
    }

    /// The first passkey of the account.
    #[must_use]
    pub const fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The action of the issuer of the invitation.
    #[must_use]
    pub const fn action(&self) -> &Id<Action> {
        &self.action
    }

    /// The resource of the action of the issuer, such as the team that the recipient joins.
    #[must_use]
    pub const fn resource(&self) -> &Id<Resource> {
        &self.resource
    }

    /// The commit of the activation, with the reads of `decision`, the decision of the application, such as the state
    /// of the account in the records of the application. Submit the proposal with the plan. After a lost response,
    /// look up the operation of the proposal.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`passkey::Error::Transition`] if `decision` reads a record of the activation with another result, or reads more records
    /// than the limits permit.
    pub fn propose(mut self, decision: &[Dependency]) -> Result<(Proposal, Plan), passkey::Error> {
        passkey::decide(&mut self.proposal, decision)?;
        Ok((self.proposal, self.plan))
    }
}

impl fmt::Debug for Activation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Activation")
            .field("account", &self.account)
            .field("credential", &self.credential)
            .field("action", &self.action)
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

/// A passkey of an account as the store holds it ([`RelyingParty::passkeys`]).
#[derive(Clone, Debug)]
pub struct Passkey {
    key: Key,
    version: AuthorityVersion,
    account: Id<Human>,
    handle: UserHandle,
    credential: Credential,
}

impl Passkey {
    /// The key of the credential record.
    #[must_use]
    pub const fn key(&self) -> &Key {
        &self.key
    }

    /// The account of the passkey.
    #[must_use]
    pub const fn account(&self) -> &Id<Human> {
        &self.account
    }

    /// The credential: its ID, its algorithm, its counter, its backup state, and its name.
    #[must_use]
    pub const fn credential(&self) -> &Credential {
        &self.credential
    }
}

/// A credential record of the passkeys of one account, with its record.
pub(crate) struct Stored {
    pub(crate) passkey: Passkey,
    pub(crate) record: Record,
}

impl RelyingParty {
    /// Proposes an invitation of `invite` by the subject of `evidence`. [`authz::check`] checks that `policy` permits
    /// the action of the invitation on its resource for the issuer. The commit writes the invitation record, which ends
    /// after the lifetime, and only the accepted commit releases the invitation value as the artifact of the receipt.
    /// The operation identity is new: after a lost response, issue again, because the receipt of a lookup has no
    /// artifact, and the earlier invitation ends unused.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The call of `policy` is the cost of the application.
    ///
    /// # Errors
    ///
    /// [`passkey::Error::Lifetime`] for a lifetime that is zero or longer than [`INVITATION_LIFETIME_MAX`], and
    /// [`passkey::Error::Authorization`] if the policy refuses the issuer. [`passkey::Error::Time`] if the end overflows,
    /// [`passkey::Error::Driver`] if the driver does not serve, and [`passkey::Error::Transition`] for the proposal.
    pub fn invite(
        &self,
        evidence: &Evidence,
        policy: &impl Policy,
        invite: &Invite<'_>,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan), passkey::Error> {
        (!invite.lifetime.is_zero() && invite.lifetime <= INVITATION_LIFETIME_MAX).ok_or(passkey::Error::Lifetime)?;
        let checked = authz::check(evidence, invite.action, invite.resource, policy, now)
            .map_err(passkey::Error::Authorization)?;
        let mut value = vec![0; INVITATION_BYTES];
        random.fill_bytes(&mut value);
        let key = self.invitation_key(&value);
        let end = now
            .estimate()
            .checked_add(invite.lifetime)
            .ok_or(passkey::Error::Time(TimeError::Overflow))?;
        let issuer = evidence.subject();
        let request = Value::Array(vec![
            invite.recipient.to_cbor(),
            invite.action.to_cbor(),
            invite.resource.to_cbor(),
        ]);
        let mut proposal = self.proposal_by(passkey::operation(random), issuer.clone(), INVITE, &request, now)?;
        proposal.read(Dependency::Policy(checked.permit().version.clone()))?;
        proposal.until(checked.deadline());
        proposal.read(Dependency::Absent(key.clone()))?;
        let version = self.version(driver.allocate(Kind::Invitation)?);
        let data = passkey::encode(&Value::Array(vec![
            Value::Text(INVITATION_FORM),
            invite.recipient.to_cbor(),
            Value::Bytes(&invite.handle.to_bytes()),
            issuer.to_cbor(),
            invite.action.to_cbor(),
            invite.resource.to_cbor(),
        ]));
        proposal.change(Change::Write {
            key: key.clone(),
            version: version.clone(),
            end: Some(end),
            data,
        })?;
        proposal.prepare(Prepared::new(value, key, version))?;
        Ok((proposal, Plan::default()))
    }

    /// The options of the first passkey of `invitee`, the recipient of the invitation with the value `value`:
    /// `PublicKeyCredentialCreationOptionsJSON`, for `PublicKeyCredential.parseCreationOptionsFromJSON()`. The options
    /// require what the options of a registration require, and they exclude no credential. The start writes nothing:
    /// the challenge holds the invitation key and the earliest time of `now` under an HMAC-SHA256 tag of the key of the
    /// relying party. It serves for [`REGISTRATION_LIFETIME`](crate::passkey::REGISTRATION_LIFETIME) from that time,
    /// and the activation consumes the invitation, so it serves one activation.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed read, and one range read of at most
    /// [`CREDENTIALS_MAX`](crate::passkey::CREDENTIALS_MAX) credential records.
    ///
    /// # Errors
    ///
    /// [`passkey::Error::Name`] if a name of `invitee` is empty or longer than [`NAME_BYTES_MAX`](crate::passkey::NAME_BYTES_MAX).
    /// [`passkey::Error::Invitation`] if the store has no open invitation with the value, also after its end or its activation.
    /// [`passkey::Error::Recipient`] if the invitation is for another account, and [`passkey::Error::Activated`] if the account has a
    /// passkey: an authenticator would replace it. [`passkey::Error::Record`] if a record has no valid form, and
    /// [`passkey::Error::Time`] if `now` has no bound. [`Failure::Store`] if a read fails.
    pub async fn activation_options<S: Store>(
        &self,
        store: &mut S,
        value: &[u8],
        invitee: &Invitee<'_>,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<Vec<u8>, Failure<S::Error>> {
        passkey::name_valid(invitee.name)?;
        passkey::name_valid(invitee.display_name)?;
        (value.len() == INVITATION_BYTES).ok_or(passkey::Error::Invitation)?;
        let key = self.invitation_key(value);
        let (_, invitation) = self.invitation(store, &key, now).await?;
        (invitation.recipient == *invitee.account).ok_or(passkey::Error::Recipient)?;
        self.unregistered(store, &invitation.handle).await?;
        let challenge = self.bound_challenge(ACTIVATION_FORM, &key.as_bytes()[1..], now, random)?;
        let user = User {
            account: invitee.account,
            handle: invitation.handle,
            name: invitee.name,
            display_name: invitee.display_name,
        };
        Ok(self.options(&user, &challenge, &[]))
    }

    /// Checks the registration `response` of an activation for `recipient`, and gives the [`Activation`]. The check
    /// refuses a challenge that the key of the relying party did not make, or that is older than
    /// [`REGISTRATION_LIFETIME`](crate::passkey::REGISTRATION_LIFETIME), before any read. Then it reads the invitation of
    /// the challenge, checks its recipient, checks that the recipient has no passkey, and checks the response as
    /// [`Self::verify`] does. The policy must still permit the action of the issuer: its permit, and its policy version,
    /// are a read of the commit.
    ///
    /// The commit consumes the invitation and writes the credential record of the first passkey of the account. Its
    /// plan names the passkey as a sign-in method, so a restore completes an activation that a crash left in doubt.
    /// The operation identity is a digest of the invitation and the credential key, so the same response again gets
    /// the receipt of the first commit, and two passkeys for one invitation are two operations that the read of the
    /// invitation orders: one commits, and the other conflicts. The deadline is the earliest of the end of the
    /// challenge, of the invitation, and of the permit of the issuer.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The checks of [`Self::verify`], one keyed read, and one
    /// range read of at most [`CREDENTIALS_MAX`](crate::passkey::CREDENTIALS_MAX) credential records. The call of `policy` is the cost of the
    /// application.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::verify`]. [`passkey::Error::Challenge`] if the challenge is not an activation challenge of the key,
    /// or it ended. [`passkey::Error::Invitation`] if the store has no open invitation of the challenge, also after its end or
    /// its activation. [`passkey::Error::Recipient`] if the invitation is for another account, and [`passkey::Error::Activated`] if the
    /// account has a passkey. [`passkey::Error::Issuer`] if the current policy does not permit the action of the issuer.
    /// [`passkey::Error::Record`] if a record has no valid form, [`passkey::Error::Time`] if `now` has no bound, [`passkey::Error::Driver`] if the
    /// driver does not serve, and [`passkey::Error::Transition`] for the proposal. [`Failure::Store`] if a read fails.
    pub async fn activate<S: Store>(
        &self,
        store: &mut S,
        response: &Response,
        recipient: &Id<Human>,
        policy: &impl Policy,
        now: Reading,
        driver: &mut Driver,
    ) -> Result<Activation, Failure<S::Error>> {
        let challenge = response.challenge();
        let (bound, expires) = self.bound_end(ACTIVATION_FORM, challenge, 32, now)?;
        let key = Kind::Invitation.key(bound).expect("a key of 33 bytes is valid");
        let (record, invitation) = self.invitation(store, &key, now).await?;
        let end = record.end.ok_or(passkey::Error::Record)?;
        (invitation.recipient == *recipient).ok_or(passkey::Error::Recipient)?;
        self.unregistered(store, &invitation.handle).await?;
        let credential = self.verify(response, challenge)?;
        let request = authz::Request {
            principal: &invitation.issuer,
            action: &invitation.action,
            resource: &invitation.resource,
        };
        let permit = policy.resolve(&request).ok_or(passkey::Error::Issuer)?;
        let scope = (&permit.principal, &permit.action, &permit.resource);
        let current = scope == (request.principal, request.action, request.resource)
            && permit.version == *policy.version()
            && now.latest().map_err(passkey::Error::Time)? < permit.expires;
        current.ok_or(passkey::Error::Issuer)?;

        let credential_key = self.credential_key(&invitation.handle, credential.id());
        let data = credential.record(recipient, &invitation.handle);
        let id = crypto::sha256_parts(&[ACTIVATION_FORM.as_bytes(), key.as_bytes(), credential_key.as_bytes()]);
        let operation = OperationId::new(&id).expect("32 bytes are a valid operation identity");
        let request = Value::Array(vec![Value::Bytes(key.as_bytes()), Value::Bytes(&data)]);
        let mut proposal = self.proposal(operation, recipient, ACTIVATE, &request, now)?;
        proposal
            .read(Dependency::Version(key.clone(), record.version))
            .map_err(passkey::Error::from)?;
        proposal.change(Change::End(key)).map_err(passkey::Error::from)?;
        proposal
            .read(Dependency::Policy(permit.version))
            .map_err(passkey::Error::from)?;
        proposal
            .read(Dependency::Absent(credential_key.clone()))
            .map_err(passkey::Error::from)?;
        let version = self.version(driver.allocate(Kind::Credential).map_err(passkey::Error::from)?);
        proposal
            .change(Change::Write {
                key: credential_key.clone(),
                version,
                end: None,
                data,
            })
            .map_err(passkey::Error::from)?;
        proposal.until(expires.min(end).min(permit.expires));
        let plan = Plan {
            anchors: vec![(credential_key, Role::SignIn(recipient.clone()))],
            ..Plan::default()
        };
        Ok(Activation {
            account: invitation.recipient,
            credential,
            action: invitation.action,
            resource: invitation.resource,
            proposal,
            plan,
        })
    }

    /// The passkeys of the account with the user handle `handle`, from one range read of `store`, in the order of their
    /// keys.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One range read of at most [`CREDENTIALS_MAX`](crate::passkey::CREDENTIALS_MAX) credential
    /// records.
    ///
    /// # Errors
    ///
    /// [`passkey::Error::Record`] if a record has no valid form. [`Failure::Store`] if the read fails.
    pub async fn passkeys<S: Store>(
        &self,
        store: &mut S,
        handle: &UserHandle,
    ) -> Result<Vec<Passkey>, Failure<S::Error>> {
        let stored = self.stored(store, handle).await?;
        Ok(stored.into_iter().map(|stored| stored.passkey).collect())
    }

    /// Proposes the name `name` of `passkey`, a passkey of the account of `access`, such as "Work laptop". The commit
    /// reads the session and the credential record at their versions, so a change of either one conflicts: read the
    /// passkeys again. A rename is not a sensitive change, so it needs no fresh user verification. Add the reads of the
    /// decision of the application to the proposal before the submission.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`passkey::Error::Name`] if `name` is empty or longer than [`NAME_BYTES_MAX`](crate::passkey::NAME_BYTES_MAX), and
    /// [`passkey::Error::Credential`] if the passkey is of another account. [`passkey::Error::Driver`] if the driver does not serve, and
    /// [`passkey::Error::Transition`] for the proposal.
    pub fn rename(
        &self,
        access: &Access,
        passkey: &Passkey,
        name: &str,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan), passkey::Error> {
        passkey::name_valid(name)?;
        let session = access.session();
        (*session.account() == passkey.account).ok_or(passkey::Error::Credential)?;
        let request = Value::Array(vec![Value::Bytes(passkey.key.as_bytes()), Value::Text(name)]);
        let mut proposal = self.proposal(passkey::operation(random), &passkey.account, RENAME, &request, now)?;
        proposal.read(Dependency::Version(session.key().clone(), session.version().clone()))?;
        proposal.read(Dependency::Version(passkey.key.clone(), passkey.version.clone()))?;
        let mut credential = passkey.credential.clone();
        credential.name = name.into();
        let version = self.version(driver.allocate(Kind::Credential)?);
        proposal.change(Change::Write {
            key: passkey.key.clone(),
            version,
            end: None,
            data: credential.record(&passkey.account, &passkey.handle),
        })?;
        Ok((proposal, Plan::default()))
    }

    /// Proposes the removal of the passkey `id` of the account with the user handle `handle`, after a fresh user
    /// verification of the account. The commit ends the credential record, and it reads another passkey of the account
    /// at its version, so the account keeps a sign-in method, also when two removals run at once. Its plan holds each
    /// passkey of the account, so the commit driver refuses the removal of the last sign-in method that the restore
    /// journal records as live. A recovery value is no sign-in method. Add the reads of the decision of the application
    /// to the proposal before the submission.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One range read of at most [`CREDENTIALS_MAX`](crate::passkey::CREDENTIALS_MAX) credential
    /// records.
    ///
    /// # Errors
    ///
    /// [`passkey::Error::Credential`] if the account of `fresh` has no passkey `id` under `handle`, and [`passkey::Error::Transition`]
    /// with [`transition::Error::LastAnchor`] if it is the last passkey of the account. [`passkey::Error::Record`] if a record
    /// has no valid form, and [`passkey::Error::Transition`] for the proposal. [`Failure::Store`] if the read fails.
    pub async fn remove<S: Store>(
        &self,
        store: &mut S,
        fresh: &Fresh,
        handle: &UserHandle,
        id: &[u8],
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        let stored = self.stored(store, handle).await?;
        let mut owned = stored.iter().filter(|stored| stored.passkey.account == fresh.account);
        let target = owned
            .clone()
            .find(|stored| stored.passkey.credential.id() == id)
            .ok_or(passkey::Error::Credential)?;
        let survivor = owned
            .find(|stored| stored.passkey.key != target.passkey.key)
            .ok_or(passkey::Error::Transition(transition::Error::LastAnchor))?;
        let request = Value::Bytes(target.passkey.key.as_bytes());
        let mut proposal = self.proposal(passkey::operation(random), &fresh.account, REMOVE, &request, now)?;
        fresh.gate(&mut proposal).map_err(passkey::Error::from)?;
        for kept in [survivor, target] {
            proposal
                .read(Dependency::Version(
                    kept.passkey.key.clone(),
                    kept.record.version.clone(),
                ))
                .map_err(passkey::Error::from)?;
        }
        proposal
            .change(Change::End(target.passkey.key.clone()))
            .map_err(passkey::Error::from)?;
        let held = stored
            .into_iter()
            .filter(|stored| stored.passkey.account == fresh.account)
            .map(|stored| Anchor {
                key: stored.passkey.key,
                role: Role::SignIn(fresh.account.clone()),
                version: stored.record.version,
                end: stored.record.end,
                data: stored.record.data,
            })
            .collect();
        let plan = Plan {
            held,
            ..Plan::default()
        };
        Ok((proposal, plan))
    }

    /// The credential records of the account with the user handle `handle`, from one range read of `store`.
    pub(crate) async fn stored<S: Store>(
        &self,
        store: &mut S,
        handle: &UserHandle,
    ) -> Result<Vec<Stored>, Failure<S::Error>> {
        let records = store
            .range(&self.account_prefix(handle), None, passkey::CREDENTIALS)
            .await
            .map_err(Failure::Store)?;
        let mut stored = Vec::with_capacity(records.len());
        for (key, record) in records {
            let (account, handle, credential) = passkey::credential_form(&record.data, self.limits)?;
            stored.push(Stored {
                passkey: Passkey {
                    key,
                    version: record.version.clone(),
                    account,
                    handle,
                    credential,
                },
                record,
            });
        }
        Ok(stored)
    }

    /// Refuses an activation of the account with the user handle `handle` when the account has a passkey.
    async fn unregistered<S: Store>(&self, store: &mut S, handle: &UserHandle) -> Result<(), Failure<S::Error>> {
        let records = store
            .range(&self.account_prefix(handle), None, passkey::CREDENTIALS)
            .await
            .map_err(Failure::Store)?;
        records.is_empty().ok_or(passkey::Error::Activated)?;
        Ok(())
    }

    /// The record and the invitation at `key`, while it is open at `now`.
    async fn invitation<S: Store>(
        &self,
        store: &mut S,
        key: &Key,
        now: Reading,
    ) -> Result<(Record, Invitation), Failure<S::Error>> {
        let record = passkey::read(store, key).await?.ok_or(passkey::Error::Invitation)?;
        let end = record.end.ok_or(passkey::Error::Record)?;
        (now.latest().map_err(passkey::Error::Time)? < end).ok_or(passkey::Error::Invitation)?;
        let invitation = Invitation::decode(&record.data, self)?;
        Ok((record, invitation))
    }

    /// The key of the invitation record of the value `value`: [`Kind::Invitation`] with the SHA-256 digest of the CBOR
    /// form `["rsauthnz.invitation.1", authority, relying party ID, value]`.
    fn invitation_key(&self, value: &[u8]) -> Key {
        Kind::Invitation
            .key(&self.digest(INVITATION_FORM, value))
            .expect("a key of 33 bytes is valid")
    }
}

/// The invitation record form `["rsauthnz.invitation.1", recipient, user handle, issuer, action, resource]`.
struct Invitation {
    recipient: Id<Human>,
    handle: UserHandle,
    issuer: Principal,
    action: Id<Action>,
    resource: Id<Resource>,
}

impl Invitation {
    fn decode(data: &[u8], rp: &RelyingParty) -> Result<Self, passkey::Error> {
        let form = crate::cbor::decode(data, rp.limits).map_err(|_| passkey::Error::Record)?;
        let Value::Array(items) = &form else {
            return Err(passkey::Error::Record);
        };
        let [
            Value::Text(INVITATION_FORM),
            recipient,
            Value::Bytes(handle),
            issuer,
            action,
            resource,
        ] = items.as_slice()
        else {
            return Err(passkey::Error::Record);
        };
        Ok(Self {
            recipient: Id::from_cbor(recipient).map_err(|_| passkey::Error::Record)?,
            handle: UserHandle::from_bytes(<[u8; 32]>::try_from(*handle).map_err(|_| passkey::Error::Record)?),
            issuer: Principal::from_cbor(issuer).map_err(|_| passkey::Error::Record)?,
            action: Id::from_cbor(action).map_err(|_| passkey::Error::Record)?,
            resource: Id::from_cbor(resource).map_err(|_| passkey::Error::Record)?,
        })
    }
}

/// The cause of a refused [`Fresh::check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The evidence of the session has no user verification, or it is older than the maximum age. Verify the user
    /// again: a passkey sign-in that replaces the session.
    Stale,
    /// The identifier holds the replaced generation of its session. The next request holds the current one.
    Replaced,
    /// The maximum age is longer than [`FRESH_MAX`].
    Window,
    /// A time reading has no bound, or a time overflows.
    Time(TimeError),
}

impl Recover for Error {
    /// The recovery of the caller: verify the user again after [`Error::Stale`], and send the request again with the
    /// current identifier after [`Error::Replaced`]. Refuse each other request.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Stale => Recovery::Verify,
            Self::Replaced => Recovery::Restart,
            Self::Window | Self::Time(_) => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale => f.write_str("the session has no fresh user verification"),
            Self::Replaced => f.write_str("the identifier holds a replaced generation"),
            Self::Window => f.write_str("the maximum age of a user verification is too long"),
            Self::Time(error) => write!(f, "the time reading gave no value: {error}"),
        }
    }
}

impl core::error::Error for Error {}
