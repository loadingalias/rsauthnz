//! The credentials of an agent under its grant: one audience, the current revision, and an end at the grant deadline
//! at most.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use rscodec::json::{self, Profile::Rfc8259, Slot};

use super::{Error, Failure, Grant, Grants, encode, key, read};
use crate::agent;
use crate::authz::Policy;
use crate::cbor::Value;
use crate::cose::{Key as CoseKey, PublicKey, TrustedKey};
use crate::credential::{self, Awaiting, Claims, Draft, Serial, Subject};
use crate::crypto::{self, Algorithm};
use crate::custody::Handle;
use crate::id::{Agent, Audience, Authority, Id, Kind as IdKind, Principal, Purpose};
use crate::limits::SignatureBudget;
use crate::store::Store;
use crate::store::driver::{Driver, Plan};
use crate::time::Reading;
use crate::transition::{Audit, Dependency, OperationId, Proposal};

/// The lifetime of an agent credential when the request names none.
pub const LIFETIME_DEFAULT: Duration = Duration::from_secs(900);

/// The longest lifetime of an agent credential. A request for a longer one refuses.
pub const LIFETIME_MAX: Duration = Duration::from_secs(3_600);

/// The first item of the statement of a request, and the domain of its operation identity.
const FORM: &str = "rsauthnz.grant.credential.1";

/// The limits of the JSON body of a request: the limits of each body of an agent, with a lifetime of at most 20
/// digits.
const BODY: json::Limits = json::Limits {
    number_digits_max: 20,
    ..agent::BODY
};

/// The action of the audit record of an issue.
const ISSUE: &str = "grant.credential";

/// The purpose of each agent credential: `rsauthnz:agent`. [`crate::authz::check_agent`] refuses another purpose.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn purpose() -> Id<Purpose> {
    Id::new("rsauthnz", "agent").expect("the purpose is a valid identifier")
}

/// The bytes that the proof of a request binds ([`Request::proof`]): the canonical CBOR form
/// `["rsauthnz.grant.credential.1", authority, agent, audience, lifetime]`, with `lifetime` in whole seconds, or null
/// for [`LIFETIME_DEFAULT`].
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn statement(
    authority: &Id<Authority>,
    agent: &Id<Agent>,
    audience: &Id<Audience>,
    lifetime: Option<Duration>,
) -> Vec<u8> {
    encode(&[
        Value::Text(FORM),
        authority.to_cbor(),
        agent.to_cbor(),
        audience.to_cbor(),
        lifetime.map_or(Value::Null, |lifetime| Value::Unsigned(lifetime.as_secs())),
    ])
}

/// The request of an agent for a credential of its grant at one audience: a first credential, or a refresh. The agent
/// proves its current key, so a refresh needs no earlier credential.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    /// The agent.
    pub agent: &'a Id<Agent>,
    /// The audience of the credential: one audience of the grant.
    pub audience: &'a Id<Audience>,
    /// The lifetime in whole seconds, or `None` for [`LIFETIME_DEFAULT`]. The credential ends at the grant deadline at
    /// the latest.
    pub lifetime: Option<Duration>,
    /// 32 random bytes of the agent, which name the operation ([`Self::operation`]). After a lost response, send the
    /// same request with the same nonce: it is the same operation.
    pub nonce: &'a [u8; 32],
    /// The proof of possession of the current key of the agent ([`credential::ProofDraft`]) over the bytes of
    /// [`statement`], for the audience of the request, with the nonce as its challenge.
    pub proof: &'a [u8],
}

impl Request<'_> {
    /// The identity of the operation of the request: the SHA-256 digest of `["rsauthnz.grant.credential.1", authority,
    /// agent, nonce]`. A second request with the same nonce and other values refuses with
    /// [`transition::Error::Reuse`](crate::transition::Error::Reuse).
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn operation(&self, authority: &Id<Authority>) -> OperationId {
        let form = encode(&[
            Value::Text(FORM),
            authority.to_cbor(),
            self.agent.to_cbor(),
            Value::Bytes(self.nonce),
        ]);
        OperationId::new(&crypto::sha256(&form)).expect("a digest of 32 bytes is a valid operation identity")
    }
}

/// The JSON body of a request of an agent: `{"agent","audience","lifetime","nonce","proof"}`, with the text form
/// `namespace:value` of each identifier, the lifetime in whole seconds or no member for the default, and the base64url
/// of the nonce and of the proof. The reader ignores each other member, so a member that names an owner names none.
#[derive(Debug)]
pub struct Body {
    /// The agent.
    pub agent: Id<Agent>,
    /// The audience of the credential.
    pub audience: Id<Audience>,
    /// The lifetime, or `None` for [`LIFETIME_DEFAULT`].
    pub lifetime: Option<Duration>,
    /// The nonce of the agent.
    pub nonce: [u8; 32],
    /// The proof of possession of the current key of the agent.
    pub proof: Vec<u8>,
}

impl Body {
    /// Reads the body `json`, of at most [`agent::BODY_BYTES_MAX`] bytes.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `json` is not a JSON object with an agent, an audience, a nonce of 32 bytes, and a
    /// proof, or has more than 8 members, or a lifetime that is not a whole number, or is longer than its bound.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let mut scratch = [Slot::EMPTY; agent::SLOTS];
        let (agent, audience, lifetime, nonce, proof) = json::read(json, &BODY, Rfc8259, &mut scratch, |reader| {
            let mut found = (None, None, None, None, None);
            let mut members = reader.value().members()?;
            while let Some((name, value)) = members.next()? {
                let known = ["agent", "audience", "lifetime", "nonce", "proof"];
                match known.iter().position(|known| name == *known) {
                    Some(0) => found.0 = Some(agent::text(value.str()?)?),
                    Some(1) => found.1 = Some(agent::text(value.str()?)?),
                    Some(2) => found.2 = Some(value.number()?.to_u64()?),
                    Some(3) => found.3 = Some(agent::text(value.str()?)?),
                    Some(4) => found.4 = Some(agent::text(value.str()?)?),
                    _ => {}
                }
            }
            Ok(found)
        })
        .map_err(|_| Error::Malformed)?;
        fn id<K: IdKind>(text: Option<String>) -> Result<Id<K>, Error> {
            let text = text.ok_or(Error::Malformed)?;
            let (namespace, value) = text.split_once(':').ok_or(Error::Malformed)?;
            Id::new(namespace, value).map_err(|_| Error::Malformed)
        }
        let bytes =
            |text: Option<String>| agent::base64url(&text.ok_or(Error::Malformed)?).map_err(|_| Error::Malformed);
        Ok(Self {
            agent: id(agent)?,
            audience: id(audience)?,
            lifetime: lifetime.map(Duration::from_secs),
            nonce: bytes(nonce)?.try_into().map_err(|_| Error::Malformed)?,
            proof: bytes(proof)?,
        })
    }

    /// The request of the body.
    #[must_use]
    pub fn request(&self) -> Request<'_> {
        Request {
            agent: &self.agent,
            audience: &self.audience,
            lifetime: self.lifetime,
            nonce: &self.nonce,
            proof: &self.proof,
        }
    }
}

// The proof gives no authority alone, but the output shows only its length, as for each artifact.
impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("agent", self.agent)
            .field("audience", self.audience)
            .field("lifetime", &self.lifetime)
            .field("proof_len", &self.proof.len())
            .finish_non_exhaustive()
    }
}

/// The issue of an agent credential that custody did not sign yet: the draft and the proposal of its transition.
#[derive(Debug)]
pub struct Pending {
    draft: Draft,
    proposal: Proposal,
    serial: Serial,
    issued: Duration,
    expires: Duration,
}

impl Pending {
    /// The bytes that custody signs with the issuer key: the `Sig_structure` of the credential
    /// ([`Draft::to_be_signed`]).
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        self.draft.to_be_signed()
    }

    /// Verifies `signature`, the signature of custody over [`Self::to_be_signed`], with the issuer key, and puts the
    /// credential into the proposal. Submit the proposal with the [`Plan`], and give the outcome of its commit to
    /// [`Awaiting::release`]. The check charges `budget`, the budget of the credential.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the signature does not verify with the issuer key, or if the check costs more than
    /// `budget` has, and [`Error::Transition`] if the proposal refuses the credential.
    pub fn finish(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<(Proposal, Plan, Awaiting), Error> {
        let Self {
            draft,
            mut proposal,
            serial,
            issued,
            expires,
        } = self;
        let prepared = draft.finish(signature, budget).map_err(Error::Credential)?;
        let awaiting = Awaiting::new(&proposal, &prepared, serial, issued, expires);
        proposal.prepare(prepared).map_err(Error::Transition)?;
        Ok((proposal, Plan::default(), awaiting))
    }
}

impl Grants {
    /// The issue of a credential of the grant of the agent of `request`: a first credential, or a refresh. The issuer
    /// key `issuer` signs it in custody. The request must prove the current key of the agent. The grant must not have
    /// ended, must name the audience, and must bind the current version of `policy`. The credential names the agent,
    /// its owner, the current revision, and the audience, with the key of the agent as its `cnf` key and the purpose
    /// [`purpose`]. It ends at the earlier of the issue plus the lifetime and the grant deadline, so a refresh never
    /// extends the grant. `driver` gives its serial.
    ///
    /// The proposal reads the identity, the grant, and the policy version, and writes the issuance record of the
    /// credential. Its audit names the agent and its owner. Its deadline is the grant deadline. So a revocation, a
    /// change, a rotation, or a relevant policy change before the commit refuses it, and so does the deadline.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). Two keyed lookups and the check of the proof.
    ///
    /// # Errors
    ///
    /// [`Error::Lifetime`] for a lifetime past [`LIFETIME_MAX`] or under one second, and [`Error::Time`] for a reading
    /// with no bound. [`Error::NotEnrolled`] if the store holds no identity of the agent, and [`Error::Credential`] if
    /// the proof does not verify with its current key, or if `issuer` is an SLH-DSA key, which signs no credential.
    /// [`Error::NoGrant`] if the agent has no grant, [`Error::Expired`] at or after its deadline, [`Error::Audience`]
    /// for an audience that it does not name, and [`Error::Policy`] if it binds another policy version.
    /// [`Error::Record`] for a record with no valid form, [`Error::Driver`] if the driver gives no serial,
    /// [`Error::Transition`] for the proposal, and [`Failure::Store`] if a read fails.
    pub async fn credential<S: Store>(
        &self,
        store: &mut S,
        request: Request<'_>,
        issuer: &Handle,
        policy: &impl Policy,
        now: Reading,
        driver: &mut Driver,
    ) -> Result<Pending, Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        let lifetime = Duration::from_secs(request.lifetime.unwrap_or(LIFETIME_DEFAULT).as_secs());
        (!lifetime.is_zero() && lifetime <= LIFETIME_MAX).ok_or(Error::Lifetime)?;
        let issuer = issuer.trusted().ok_or(Error::Credential(credential::Error::Profile))?;
        let Request {
            agent,
            audience,
            nonce,
            proof,
            ..
        } = request;
        let identity = self.identity(store, agent).await?;
        let public = PublicKey::MlDsa65Ed25519(&identity.key);
        let holder = CoseKey {
            kid: None,
            alg: None,
            public: public.clone(),
        };
        let holder = TrustedKey::new(Algorithm::MlDsa65Ed25519, &holder).map_err(|_| Error::Record)?;
        credential::check_proof(
            &holder,
            &statement(&self.authority, agent, audience, request.lifetime),
            &audience.to_string(),
            proof,
            nonce,
            self.limits,
            &mut SignatureBudget::new(&self.limits),
        )
        .map_err(Error::Credential)?;
        let grant_key = key(&self.authority, &identity.owner, agent);
        let record = read(store, &grant_key).await?.ok_or(Error::NoGrant)?;
        let grant = Grant::parse(&record, self.limits)
            .filter(|grant| grant.agent == *agent && grant.owner == identity.owner)
            .ok_or(Error::Record)?;
        (latest < grant.deadline).ok_or(Error::Expired)?;
        grant.audiences.contains(audience).ok_or(Error::Audience)?;
        (*policy.version() == grant.policy).ok_or(Error::Policy)?;
        // The draft keeps whole seconds. The reading is before the deadline, so the end is after the issue.
        let issued = Duration::from_secs(now.estimate().as_secs());
        let expires = issued.saturating_add(lifetime).min(grant.deadline);
        let serial = Serial(driver.allocate().map_err(Error::Driver)?);
        let subject = Subject::Agent {
            agent: agent.clone(),
            owner: identity.owner.clone(),
            revision: grant.revision,
        };
        let claims = Claims::new(
            self.authority.clone(),
            audience.clone(),
            subject,
            purpose(),
            serial,
            expires,
        );
        let draft = Draft::credential(&issuer, &claims, Some(public), now).map_err(Error::Credential)?;
        let audit = Audit {
            actor: Principal::Agent(agent.clone()),
            action: Id::new("rsauthnz", ISSUE).expect("the action is a valid identifier"),
            time: now,
        };
        let asked = Value::Array(vec![
            self.authority.to_cbor(),
            agent.to_cbor(),
            audience.to_cbor(),
            request
                .lifetime
                .map_or(Value::Null, |lifetime| Value::Unsigned(lifetime.as_secs())),
        ]);
        let operation = request.operation(&self.authority);
        let mut proposal = Proposal::start(operation, audit, &asked, self.limits).map_err(Error::Transition)?;
        proposal.attribute(identity.owner);
        let reads = [
            Dependency::Version(self.agents.identity_key(agent), identity.version),
            Dependency::Version(grant_key, record.version),
            Dependency::Policy(grant.policy),
        ];
        reads
            .into_iter()
            .try_for_each(|read| proposal.read(read))
            .map_err(Error::Transition)?;
        proposal.until(grant.deadline);
        draft.record(&mut proposal).map_err(Error::Transition)?;
        Ok(Pending {
            draft,
            proposal,
            serial,
            issued,
            expires,
        })
    }

    /// The profile that verifies the agent credentials of this authority at `audience`, with the issuer key `key`
    /// and the purpose [`purpose`]. Give its evidence to [`crate::authz::check_agent`]. During a rotation of the issuer
    /// key, add the previous key with [`credential::Profile::with_previous`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// The errors of [`credential::Profile::new`].
    pub fn profile(&self, key: TrustedKey, audience: &Id<Audience>) -> Result<credential::Profile, credential::Error> {
        credential::Profile::new(key, self.authority.clone(), audience.clone(), purpose(), self.limits)
    }
}
