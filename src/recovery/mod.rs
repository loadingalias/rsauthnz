//! Recovery: one recovery code for each account. A recovery signs the account in with a new passkey after its user lost
//! each other passkey.
//!
//! A recovery code is [`CODE_BYTES`] random bytes from the generator of the caller: 128 bits. Its text has
//! [`CODE_CHARS`] characters: 32 hexadecimal digits in eight groups of four, such as
//! `3f9a-08c1-7d2e-55b0-c4a9-1e63-f087-2b5d`. [`Code::parse`] takes the digits in either case, with or without the
//! hyphens and spaces.
//!
//! The store keeps only the keyed BLAKE3 digest of the code under the recovery key of the relying party
//! ([`RelyingParty::with_recovery`]), so a dump of the store gives no code. The code has 128 random bits, so a
//! memory-hard KDF would add no protection: it would only make each attempt cost more. Each account has one record of
//! its code at a key of the account, so one keyed read finds it, also in a large store. A new recovery key ends each
//! code, because no digest verifies under it.
//!
//! 1. [`RelyingParty::recovery_code`] proposes a new code of a signed-in account, after a fresh user verification. The
//!    commit writes the record of the code and ends the earlier code of the account. Only the accepted commit
//!    releases the text of the code, as the artifact of the receipt. Show it to the user once.
//! 2. A user who lost each passkey gives the name of the account and the code. The application finds the account by
//!    the name, and [`RelyingParty::recovery_options`] checks the code with one keyed hash and one keyed read. The name,
//!    such as an email address, only finds the account: the code is the proof. The options are those of a new passkey of
//!    the account, and they write nothing: the challenge holds the record of the code at its version under an
//!    HMAC-SHA256 tag of the key of the relying party.
//! 3. [`RelyingParty::recover`] checks the registration response and gives an [`Attempt`]. [`Attempt::propose`] gives
//!    one commit with the decision of the application. The commit consumes the code, writes the new passkey, ends the
//!    sessions of the account, and with [`Passkeys::End`] ends each other passkey of the account. It opens a new
//!    session, which only the accepted commit releases. The plan names the new passkey as a sign-in method, so a
//!    restore completes a recovery that a crash left in doubt.
//!
//! The evidence of a recovery records its method, so it never records phishing resistance. It records the user
//! verification of the registration of the new passkey. Thus the new session is a fresh user verification
//! ([`Fresh`]) for [`FRESH_MAX`](crate::account::FRESH_MAX): make a new recovery code at once, and end each
//! passkey that the user lost. A recovery uses up the code, so the account has no code until it makes a new one.
//!
//! The example checks codes on the memory binding of `rsauthnz-conformance`. An email address is no code, and a code
//! that the store does not hold refuses after one keyed read. A recovery needs a browser and an authenticator.
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::Limits;
//! use rsauthnz::passkey::{Error, Failure, RelyingParty, User, UserHandle};
//! use rsauthnz::recovery::Code;
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
//! // The host keeps both keys in its custody. A new recovery key ends each recovery code.
//! let rp = RelyingParty::new(Id::new("acme", "auth")?, "app.example", "https://app.example", "Acme", [3; 32], Limits::default())?
//!     .with_recovery([4; 32]);
//!
//! // An email address is no recovery code.
//! assert_eq!(Code::parse(b"alice@app.example").err(), Some(Error::Code));
//!
//! // Alice gives the name of her account and a code. The application found her account and its user handle by the name.
//! let alice = Id::new("acme", "alice")?;
//! let user = User { account: &alice, handle: UserHandle::from_bytes([9; 32]), name: "alice@app.example", display_name: "Alice" };
//! let code = Code::parse(b"3F9A 08C1 7D2E 55B0 C4A9 1E63 F087 2B5D")?;
//! let refused = ready(rp.recovery_options(&mut memory, &user, &code, now, &mut random));
//! assert!(matches!(refused, Err(Failure::Refused(Error::Code))));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use rscodec::hex;
use rscrypto::{ChaCha20Rng, SecretBytes};

use crate::account::{Fresh, Stored};
use crate::cbor::{self, Value};
use crate::crypto;
use crate::evidence::{Evidence, Method};
use crate::id::{AuthorityVersion, Human, Id, Principal};
use crate::passkey::{self, CREDENTIALS_MAX, Credential, Error, Failure, RelyingParty, Response, User, UserHandle};
use crate::session::{self, Opening, Session, Sessions};
use crate::store::driver::{Driver, Plan};
use crate::store::journal::{Anchor, Role};
use crate::store::{Kind, Store};
use crate::time::Reading;
use crate::transition::{Change, Dependency, Key, Prepared, Proposal};

/// The random bytes of a recovery code: 128 bits.
pub const CODE_BYTES: usize = 16;

/// The characters of the text of a recovery code: 32 hexadecimal digits in eight groups of four, with a hyphen between
/// two groups.
pub const CODE_CHARS: usize = 39;

/// The most bytes of a text that [`Code::parse`] reads.
const TEXT_BYTES_MAX: usize = 64;

/// The record form of a recovery code, and the domain of the key of the record and of the digest of the code.
const FORM: &str = "rsauthnz.recovery.1";

/// The domain of the tag of a recovery challenge.
const CHALLENGE_FORM: &str = "rsauthnz.passkey.recovery.1";

/// The audit actions.
const ISSUE: &str = "recovery.issue";
const RECOVER: &str = "recovery.use";

/// A recovery code that a user typed. It is a bearer secret, so `Debug` shows nothing of it, and its memory is cleared
/// when it drops.
pub struct Code(SecretBytes<CODE_BYTES>);

impl Code {
    /// Reads the text `text` of a recovery code: 32 hexadecimal digits in either case, with any hyphens and spaces.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The work is linear in `text`, which has at most 64 bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Code`] if `text` is longer than 64 bytes or holds another character or another number of digits.
    /// [`Error::Dit`] if this build on this CPU cannot decode the code with data-independent timing.
    pub fn parse(text: &[u8]) -> Result<Self, Error> {
        (text.len() <= TEXT_BYTES_MAX).ok_or(Error::Code)?;
        let mut count = 0;
        let digits = SecretBytes::<{ 2 * CODE_BYTES }>::try_fill_with(|digits| {
            // A separator is at a position of the text, which holds no secret.
            for &byte in text.iter().filter(|byte| !matches!(byte, b'-' | b' ')) {
                *digits.get_mut(count).ok_or(Error::Code)? = byte.to_ascii_lowercase();
                count += 1;
            }
            (count == 2 * CODE_BYTES).ok_or(Error::Code)
        })?;
        let code = SecretBytes::try_fill_with(|code| {
            rscodec::with_dit(|dit| hex::decode_secret(dit, digits.as_bytes(), code).map(|_| ()))
                .map_err(|_| Error::Dit)?
                .map_err(|_| Error::Code)
        })?;
        Ok(Self(code))
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Code(..)")
    }
}

/// What a recovery does with the other passkeys of the account: the policy of the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Passkeys {
    /// The other passkeys stay, so a user who still holds one keeps it. A thief of the code cannot remove them.
    Keep,
    /// The commit ends each other passkey of the account, such as the passkey of a lost device, or of a thief who signed
    /// in with it.
    End,
}

/// Whether the commit of a recovery ends each session of the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ended {
    /// The commit ends each session of the account that did not end.
    All,
    /// The proposal has no room for each session of the account: more sessions than [`Limits::dependencies`] permits
    /// with the other reads. After the commit, list the sessions of the account ([`Sessions::list`]), and end each one
    /// other than the new session with [`Revoker::Fresh`](crate::session::Revoker::Fresh) of the new session.
    ///
    /// [`Limits::dependencies`]: crate::limits::Limits::dependencies
    Part,
}

/// A checked recovery that waits for the decision of the application: the account, its new passkey, and the commit that
/// [`RelyingParty::recover`] made.
pub struct Attempt {
    account: Id<Human>,
    credential: Credential,
    /// The key and the version of each other passkey of the account.
    passkeys: Vec<(Key, AuthorityVersion)>,
    /// The sessions of the account that the list read, and whether the list read each one.
    sessions: Vec<Session>,
    listed: bool,
    dependencies_max: usize,
    proposal: Proposal,
    plan: Plan,
    opening: Opening,
}

impl Attempt {
    /// The account of the recovery code.
    #[must_use]
    pub const fn account(&self) -> &Id<Human> {
        &self.account
    }

    /// The new passkey of the account.
    #[must_use]
    pub const fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The commit of the recovery, with `passkeys`, the policy for the other passkeys of the account, and `decision`,
    /// the reads of the decision of the application, such as the state of the account in its records. The commit reads
    /// each passkey that it ends and each session at its version, so a change of one makes it conflict: recover again
    /// with the same response while its challenge serves. It ends each session that fits after the other reads, and
    /// [`Ended`] tells whether a session stays.
    ///
    /// Submit the proposal with the plan, and give its outcome to [`Opening::release`]. After a lost response, keep the
    /// opening, and look up the operation of the proposal: no second recovery runs by itself.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Full`] for [`Passkeys::Keep`] when the account has [`CREDENTIALS_MAX`] passkeys. [`Error::Transition`] if
    /// `decision` reads a record of the recovery with another result, or the reads of the decision and of the passkeys
    /// are more than the limits permit.
    pub fn propose(
        mut self,
        passkeys: Passkeys,
        decision: &[Dependency],
    ) -> Result<(Proposal, Plan, Opening, Ended), Error> {
        passkey::decide(&mut self.proposal, decision)?;
        match passkeys {
            Passkeys::Keep => (self.passkeys.len() < CREDENTIALS_MAX).ok_or(Error::Full)?,
            Passkeys::End => {
                for (key, version) in self.passkeys {
                    self.proposal.read(Dependency::Version(key.clone(), version))?;
                    self.proposal.change(Change::End(key))?;
                }
            }
        }
        let mut ended = if self.listed { Ended::All } else { Ended::Part };
        for session in &self.sessions {
            // Each change has its own read, so the room for reads is also room for changes.
            if self.proposal.dependencies().len() == self.dependencies_max {
                ended = Ended::Part;
                break;
            }
            self.proposal
                .read(Dependency::Version(session.key().clone(), session.version().clone()))?;
            self.proposal.change(Change::End(session.key().clone()))?;
        }
        Ok((self.proposal, self.plan, self.opening, ended))
    }
}

impl fmt::Debug for Attempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attempt")
            .field("account", &self.account)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl RelyingParty {
    /// The relying party with the recovery key `key`: 32 random bytes that the host keeps in its custody, as it keeps
    /// the key of the challenges. The store keeps the digest of each recovery code under this key. Keep the key for the
    /// life of the codes: a new key ends each code, and each account makes a new one.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn with_recovery(mut self, key: [u8; 32]) -> Self {
        self.recovery = Some(SecretBytes::new(key));
        self
    }

    /// Proposes a new recovery code of the account of `fresh`, whose passkeys have the user handle `handle`. A new code
    /// is a sensitive change, so it needs a fresh user verification: the commit reads its session at its version, and
    /// its deadline is the end of the verification. The code has [`CODE_BYTES`] bytes from `random`, and the commit
    /// writes only its keyed digest. When the account has a code, the commit ends it in the same step, and it reads a
    /// passkey of the account at its version, so the account keeps a sign-in method.
    ///
    /// Only the accepted commit releases the text of the code, [`CODE_CHARS`] ASCII bytes, as the artifact of the
    /// receipt. Show it to the user once. The operation identity is new: after a lost response, propose again, because
    /// the receipt of a lookup has no artifact, and the new code ends the code of the lost response.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One range read of at most
    /// [`CREDENTIALS_MAX`] credential records, one keyed read, and one keyed hash.
    ///
    /// # Errors
    ///
    /// [`Error::RecoveryKey`] if the relying party has no recovery key, and [`Error::Credential`] if the account of
    /// `fresh` has no passkey under `handle`. [`Error::Record`] if a record has no valid form, [`Error::Dit`] if this
    /// CPU cannot encode the code with data-independent timing, [`Error::Driver`] if the driver does not serve, and
    /// [`Error::Transition`] for the proposal. [`Failure::Store`] if a read fails.
    pub async fn recovery_code<S: Store>(
        &self,
        store: &mut S,
        fresh: &Fresh,
        handle: &UserHandle,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        let secret = self.recovery.as_ref().ok_or(Error::RecoveryKey)?;
        let account = fresh.account();
        let stored = self.stored(store, handle).await?;
        let owned: Vec<&Stored> = stored
            .iter()
            .filter(|stored| stored.passkey.account() == account)
            .collect();
        let survivor = owned.first().ok_or(Error::Credential)?;
        let key = self.recovery_key(handle);
        let earlier = passkey::read(store, &key).await?;
        let request = Value::Bytes(key.as_bytes());
        let mut proposal = self.proposal(passkey::operation(random), account, ISSUE, &request, now)?;
        fresh.gate(&mut proposal).map_err(Error::from)?;
        proposal
            .read(Dependency::Version(
                survivor.passkey.key().clone(),
                survivor.record.version.clone(),
            ))
            .map_err(Error::from)?;
        let mut held: Vec<Anchor> = owned
            .iter()
            .map(|stored| Anchor {
                key: stored.passkey.key().clone(),
                role: Role::SignIn(account.clone()),
                version: stored.record.version.clone(),
                end: stored.record.end,
                data: stored.record.data.clone(),
            })
            .collect();
        let replaced = match earlier {
            Some(record) => {
                let (holder, _, _) = self.code_form(&record.data)?;
                (holder == *account).ok_or(Error::Record)?;
                proposal
                    .read(Dependency::Version(key.clone(), record.version.clone()))
                    .map_err(Error::from)?;
                held.push(Anchor {
                    key: key.clone(),
                    role: Role::Recovery(account.clone()),
                    version: record.version,
                    end: record.end,
                    data: record.data,
                });
                vec![key.clone()]
            }
            None => {
                proposal.read(Dependency::Absent(key.clone())).map_err(Error::from)?;
                Vec::new()
            }
        };
        let code = SecretBytes::<CODE_BYTES>::try_fill_with(|code| {
            random.fill_bytes(code);
            Ok::<_, Error>(())
        })?;
        let digest = crypto::blake3_keyed(secret.as_bytes(), &[FORM.as_bytes(), key.as_bytes(), code.as_bytes()]);
        let version = self.version(driver.allocate(Kind::Recovery).map_err(Error::from)?);
        let data = passkey::encode(&Value::Array(vec![
            Value::Text(FORM),
            account.to_cbor(),
            Value::Bytes(&handle.to_bytes()),
            Value::Bytes(&digest),
        ]));
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: version.clone(),
                end: None,
                data,
            })
            .map_err(Error::from)?;
        proposal
            .prepare(Prepared::new(text(&code)?, key.clone(), version))
            .map_err(Error::from)?;
        let plan = Plan {
            held,
            replaced,
            anchors: vec![(key, Role::Recovery(account.clone()))],
        };
        Ok((proposal, plan))
    }

    /// The options of a new passkey of `user` after a check of the recovery code `code`: one keyed hash, and one keyed
    /// read of the record of the code of the account. They are `PublicKeyCredentialCreationOptionsJSON`, for
    /// `PublicKeyCredential.parseCreationOptionsFromJSON()`, and they require what the options of a registration
    /// require. They exclude no credential, so the check reads no other record. The start writes nothing: the
    /// challenge holds the record of the code at its version and the earliest time of `now` under an HMAC-SHA256 tag
    /// of the key of the relying party. It serves for [`REGISTRATION_LIFETIME`](crate::passkey::REGISTRATION_LIFETIME)
    /// from that time, and a recovery or a new code ends it.
    ///
    /// The application finds `user` by the name that the user gave, such as an email address. The name only finds the
    /// account: each refusal of a code is [`Error::Code`], also for an account with no code, and the check computes the
    /// keyed hash before the read.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed hash and one keyed read.
    ///
    /// # Errors
    ///
    /// [`Error::Name`] if a name of `user` is empty or longer than [`NAME_BYTES_MAX`](crate::passkey::NAME_BYTES_MAX).
    /// [`Error::RecoveryKey`] if the relying party has no recovery key. [`Error::Code`] if the account of `user` has no
    /// code with the value. [`Error::Record`] if the record has no valid form, and [`Error::Time`] if `now` has no
    /// bound. [`Failure::Store`] if the read fails.
    pub async fn recovery_options<S: Store>(
        &self,
        store: &mut S,
        user: &User<'_>,
        code: &Code,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<Vec<u8>, Failure<S::Error>> {
        passkey::name_valid(user.name)?;
        passkey::name_valid(user.display_name)?;
        let secret = self.recovery.as_ref().ok_or(Error::RecoveryKey)?;
        let key = self.recovery_key(&user.handle);
        let digest = crypto::blake3_keyed(secret.as_bytes(), &[FORM.as_bytes(), key.as_bytes(), code.0.as_bytes()]);
        let record = passkey::read(store, &key).await?.ok_or(Error::Code)?;
        let (account, _, stored) = self.code_form(&record.data)?;
        (crypto::blake3_keyed_eq(&digest, &stored) && account == *user.account).ok_or(Error::Code)?;
        let version = <&[u8; 8]>::try_from(record.version.coordinate()).map_err(|_| Error::Record)?;
        let bound = [&key.as_bytes()[1..], version].concat();
        let challenge = self.bound_challenge(CHALLENGE_FORM, &bound, now, random)?;
        Ok(self.options(user, &challenge, &[]))
    }

    /// Checks the registration `response` of a recovery, and gives the [`Attempt`]. The check refuses a challenge that
    /// the key of the relying party did not make, or that is older than
    /// [`REGISTRATION_LIFETIME`](crate::passkey::REGISTRATION_LIFETIME), before any read. Then it reads the record of the
    /// code of the challenge, checks that it is at the version of the challenge, and checks the response as
    /// [`Self::verify`] does. It reads the other passkeys of the account and one page of its sessions of `sessions`.
    ///
    /// The commit consumes the code, writes the credential record of the new passkey, and opens a new session of
    /// `sessions` whose evidence is a recovery. Its plan names the passkey as a sign-in method, so a restore completes a
    /// recovery that a crash left in doubt. The operation identity is new, and the read of the code orders two
    /// recoveries with one code: one commits, and the other conflicts. The deadline is the end of the challenge.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The checks of [`Self::verify`], one keyed read, one range
    /// read of at most [`CREDENTIALS_MAX`] credential records, and one range read of at most
    /// [`PAGE_MAX`](crate::session::PAGE_MAX) sessions.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::verify`]. [`Error::Challenge`] if the challenge is not a recovery challenge of the key, or
    /// it ended. [`Error::Code`] if the account has no code at the version of the challenge: a recovery or a new code
    /// ended it. [`Error::Record`] if a record has no valid form, [`Error::Time`] if `now` has no bound,
    /// [`Error::Session`] for the new session, [`Error::Driver`] if the driver does not serve, and
    /// [`Error::Transition`] for the proposal. [`Failure::Store`] if a read fails.
    pub async fn recover<S: Store>(
        &self,
        store: &mut S,
        response: &Response,
        sessions: &Sessions,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<Attempt, Failure<S::Error>> {
        let challenge = response.challenge();
        let (bound, expires) = self.bound_end(CHALLENGE_FORM, challenge, 40, now)?;
        let (id, version) = bound.split_at(32);
        let key = Kind::Recovery.key(id).expect("a key of 33 bytes is valid");
        let record = passkey::read(store, &key).await?.ok_or(Error::Code)?;
        (record.version.coordinate() == version).ok_or(Error::Code)?;
        let (account, handle, _) = self.code_form(&record.data)?;
        let credential = self.verify(response, challenge)?;
        let passkeys = self
            .stored(store, &handle)
            .await?
            .into_iter()
            .filter(|stored| *stored.passkey.account() == account)
            .map(|stored| (stored.passkey.key().clone(), stored.record.version))
            .collect();
        let page = sessions
            .list(store, &account, None, now)
            .await
            .map_err(|failure| match failure {
                session::Failure::Refused(error) => Failure::Refused(Error::Session(error)),
                session::Failure::Store(error) => Failure::Store(error),
            })?;

        let credential_key = self.credential_key(&handle, credential.id());
        let data = credential.record(&account, &handle);
        let request = Value::Array(vec![Value::Bytes(key.as_bytes()), Value::Bytes(&data)]);
        let mut proposal = self.proposal(passkey::operation(random), &account, RECOVER, &request, now)?;
        proposal
            .read(Dependency::Version(key.clone(), record.version))
            .map_err(Error::from)?;
        proposal.change(Change::End(key)).map_err(Error::from)?;
        proposal
            .read(Dependency::Absent(credential_key.clone()))
            .map_err(Error::from)?;
        proposal
            .read(Dependency::Absent(Self::removal_key(&credential_key)))
            .map_err(Error::from)?;
        let version = self.version(driver.allocate(Kind::Credential).map_err(Error::from)?);
        proposal
            .change(Change::Write {
                key: credential_key.clone(),
                version,
                end: None,
                data,
            })
            .map_err(Error::from)?;
        proposal.until(expires);
        // The registration of the new passkey required user verification. No signature of the account proved it, so the
        // evidence has no authentication, and a recovery is never phishing resistant.
        let evidence = Evidence::new(
            Principal::Human(account.clone()),
            Method::Recovery,
            now,
            true,
            false,
            None,
            None,
        );
        let opening = sessions
            .open(&mut proposal, evidence, None, random, driver)
            .map_err(Error::Session)?;
        let plan = Plan {
            anchors: vec![(credential_key, Role::SignIn(account.clone()))],
            ..Plan::default()
        };
        Ok(Attempt {
            account,
            credential,
            passkeys,
            sessions: page.sessions,
            listed: page.next.is_none(),
            dependencies_max: self.limits.dependencies,
            proposal,
            plan,
            opening,
        })
    }

    /// The key of the record of the recovery code of the account with the user handle `handle`: [`Kind::Recovery`] with
    /// the SHA-256 digest of the CBOR form `["rsauthnz.recovery.1", authority, relying party ID, user handle]`.
    fn recovery_key(&self, handle: &UserHandle) -> Key {
        Kind::Recovery
            .key(&self.digest(FORM, &handle.to_bytes()))
            .expect("a key of 33 bytes is valid")
    }

    /// The account, the user handle, and the keyed digest of the record form `["rsauthnz.recovery.1", account, user
    /// handle, digest]`.
    fn code_form(&self, data: &[u8]) -> Result<(Id<Human>, UserHandle, [u8; 32]), Error> {
        let form = cbor::decode(data, self.limits).map_err(|_| Error::Record)?;
        let Value::Array(items) = &form else {
            return Err(Error::Record);
        };
        let [Value::Text(FORM), account, Value::Bytes(handle), Value::Bytes(digest)] = items.as_slice() else {
            return Err(Error::Record);
        };
        Ok((
            Id::from_cbor(account).map_err(|_| Error::Record)?,
            UserHandle::from_bytes(<[u8; 32]>::try_from(*handle).map_err(|_| Error::Record)?),
            <[u8; 32]>::try_from(*digest).map_err(|_| Error::Record)?,
        ))
    }
}

/// The text of `code`: [`CODE_CHARS`] ASCII bytes, the lowercase hexadecimal digits in groups of four.
fn text(code: &SecretBytes<CODE_BYTES>) -> Result<Vec<u8>, Error> {
    let digits = SecretBytes::<{ 2 * CODE_BYTES }>::try_fill_with(|digits| {
        rscodec::with_dit(|dit| {
            hex::encode_secret(dit, code.as_bytes(), digits).expect("32 digits hold the text of 16 bytes");
        })
        .map_err(|_| Error::Dit)
    })?;
    // The capacity is exact, so the text never moves, and the artifact clears its one allocation.
    let mut text = Vec::with_capacity(CODE_CHARS);
    for (at, group) in digits.as_bytes().as_chunks::<4>().0.iter().enumerate() {
        if at > 0 {
            text.push(b'-');
        }
        text.extend_from_slice(group);
    }
    Ok(text)
}
