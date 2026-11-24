//! A web application on axum that mounts `rsauthnz-http`: a sign-up with a passkey, the sign-in, the names, the
//! passkeys, and the sessions of an account, an invitation of a new account, and recovery with a code. It keeps each
//! record in the memory binding of `rsauthnz-conformance`, so a restart loses each account.
//!
//! [`router`] gives the routes. Each route reads the body within [`BODY_BYTES_MAX`] and gives an `http` request to its
//! handler, which runs the operations of rsauthnz under one lock of the [`App`]. `docs/content/web-example.md` gives
//! the journey and the commands.

mod cli;
#[path = "../../shared/keys.rs"]
mod keys;

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Request as AxumRequest;
use axum::routing::{any, get};
use http::{Request, Response};
use rsauthnz::account::{self, FRESH_MAX, Fresh, INVITATION_BYTES, Invite, Invitee};
use rsauthnz::authz::{self, Permit, Requirements};
use rsauthnz::cbor::Value;
use rsauthnz::id::{Action, Authority, AuthorityVersion, Human, Id, Principal, Resource};
use rsauthnz::limits::Limits;
use rsauthnz::local;
use rsauthnz::passkey::{self, Assertion, Decision, RelyingParty, User, UserHandle};
use rsauthnz::recovery::{Code, Passkeys};
use rsauthnz::session::{self, Access, Check, Revoker, Sessions};
use rsauthnz::store::driver::{Answer, Driver, Lookup, Plan};
use rsauthnz::store::{self, Profile, Store};
use rsauthnz::time::Reading;
use rsauthnz::transition::{self, Audit, Change, Dependency, OperationId, Outcome, Proposal, Receipt, Recovery};
use rsauthnz_conformance::memory::Memory;
use rsauthnz_conformance::suite;
use rsauthnz_http::{CookieName, Problem, Refusal, Site, json as json_reply};
use rscodec::base64::Profile::Url;
use rscodec::json::{self, Profile::Rfc8259, Slot};
use rscrypto::ChaCha20Rng;

/// The most bytes of a request body: a registration response with an RSA key fits.
pub const BODY_BYTES_MAX: usize = 16 * 1024;

/// The most bytes of an account name. A name has only lowercase ASCII letters, digits, and `.`, `-`, `_`, and `@`, so
/// it is also a path segment.
pub const NAME_BYTES_MAX: usize = 64;

/// The session cookie.
const SESSION: CookieName = CookieName::new("session").expect("a token");

/// The times of a session: a family lives 8 hours, a generation 30 minutes, and a replaced identifier serves 30 seconds
/// after its renewal.
const SESSION_POLICY: session::Policy = session::Policy {
    lifetime: Duration::from_secs(8 * 60 * 60),
    idle: Duration::from_secs(30 * 60),
    grace: Duration::from_secs(30),
};

/// The lifetime of an invitation.
const INVITATION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The clock of the host: a time reading with a known bound.
pub type Clock = Box<dyn Fn() -> Reading + Send + Sync>;

/// The application: its state under one lock, and its clock.
pub struct App {
    state: Mutex<State>,
    clock: Clock,
}

impl core::fmt::Debug for App {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The state holds secrets, such as the key of the relying party.
        f.debug_struct("App").finish_non_exhaustive()
    }
}

impl App {
    /// The application of the site `origin` on the store `memory`, with the clock `clock` and the generator `random`.
    /// It opens the CLI issuer key in `directory` and commits the invitation policy.
    ///
    /// # Errors
    ///
    /// Returns the cause if the site, issuer key, authority, or invitation policy cannot open.
    pub fn new(
        origin: &str,
        mut memory: Memory,
        clock: Clock,
        mut random: ChaCha20Rng,
        directory: &std::path::Path,
    ) -> Result<Self, String> {
        let issuer = keys::Keys::open(directory, "issuer", &mut random)
            .map_err(|error| format!("the CLI issuer key: {error}"))?;
        let site = Site::new(origin).map_err(|error| format!("the origin: {error}"))?;
        let rp_id = origin
            .split_once("://")
            .map(|(_, host)| host.split_once(':').map_or(host, |(host, _)| host))
            .ok_or("the origin has no scheme")?;
        let (mut key, mut recovery) = ([0; 32], [0; 32]);
        random.fill_bytes(&mut key);
        random.fill_bytes(&mut recovery);
        let rp = RelyingParty::new(authority(), rp_id, origin, "Web example", key, Limits::default())
            .map_err(|error| format!("the relying party: {error}"))?
            .with_recovery(recovery);
        let sessions = Sessions::new(authority(), id("app"), SESSION_POLICY, Limits::default())
            .map_err(|error| format!("the sessions: {error}"))?;
        let profile = Profile::new(memory.declaration()).map_err(|error| format!("the profile: {error}"))?;
        let mut driver = Driver::new(profile, Limits::default()).map_err(|error| format!("the driver: {error}"))?;
        let now = clock();
        driver.start(now);
        settle(&mut memory, &mut driver, now);
        let sign_in_not_before =
            ready(rp.sign_in_not_before(&mut memory)).map_err(|error| format!("the replay floor: {error}"))?;
        let grant = local::HostGrant {
            owner: id("owner"),
            origin: id("app"),
        };
        let cli = ready(local::Authority::open(
            &mut memory,
            &grant,
            id("cli"),
            issuer.handle.clone(),
            Limits::default(),
        ))
        .map_err(|error| format!("the CLI authority: {error}"))?;
        let version = AuthorityVersion::new(authority(), &[1]).map_err(|error| format!("the version: {error}"))?;
        let mut state = State {
            rp_id: rp_id.to_owned(),
            memory,
            driver,
            cli,
            issuer,
            sign_in_not_before,
            site,
            rp,
            sessions,
            random,
            accounts: BTreeMap::new(),
            policy: Invitations {
                version,
                expires: now.estimate() + Duration::from_secs(30 * 24 * 60 * 60),
            },
        };
        let proposal = state
            .policy_record(now)
            .map_err(|error| format!("the policy: {error}"))?;
        state
            .commit(proposal, now)
            .map_err(|problem| format!("the commit of the policy: {problem:?}"))?;
        Ok(Self {
            state: Mutex::new(state),
            clock,
        })
    }

    /// The response of `handler` to `request`, at the time of the clock.
    async fn handle(&self, handler: Handler, request: &Request<Bytes>) -> Response<Vec<u8>> {
        let respond = || {
            let now = (self.clock)();
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if request.uri().path() == "/sign-in/options"
                && let Ok(earliest) = now.earliest()
            {
                let delay = state.sign_in_not_before.saturating_sub(earliest);
                if !delay.is_zero() {
                    if let Err(error) = state.site.check_change(request) {
                        return Ok(error.response());
                    }
                    return Err(delay);
                }
            }
            Ok(handler(&mut state, request, now).unwrap_or_else(|problem| problem.response(&state.site)))
        };
        match respond() {
            Ok(response) => response,
            Err(delay) if delay <= passkey::SIGN_IN_LIFETIME => {
                tokio::time::sleep(delay).await;
                respond().unwrap_or_else(|_| rsauthnz_http::problem(Recovery::Restart))
            }
            Err(_) => rsauthnz_http::problem(Recovery::Restart),
        }
    }
}

/// A handler: the response to a request at a time, or the problem response of its refusal.
type Handler = fn(&mut State, &Request<Bytes>, Reading) -> Result<Response<Vec<u8>>, Problem>;

/// The routes of the application.
pub fn router(app: Arc<App>) -> Router {
    let routes: &[(&str, Handler)] = &[
        ("/cli/request", State::cli_request),
        ("/cli/approve", State::cli_approve),
        ("/cli/enroll", State::cli_enroll),
        ("/cli/poll", State::cli_poll),
        ("/cli/finish", State::cli_finish),
        ("/cli/credential", State::cli_credential),
        ("/cli/challenge", State::cli_challenge),
        ("/cli/status", State::cli_status),
        ("/account", State::account),
        ("/account/rename", State::rename_account),
        ("/sign-up/options", State::sign_up_options),
        ("/sign-up/finish", State::sign_up_finish),
        ("/sign-in/options", State::sign_in_options),
        ("/sign-in/finish", State::sign_in_finish),
        ("/sign-out", State::sign_out),
        ("/passkeys/rename", State::rename),
        ("/passkeys/remove", State::remove),
        ("/passkeys/add/options", State::add_options),
        ("/passkeys/add/finish", State::add_finish),
        ("/sessions/revoke", State::revoke),
        ("/invitations", State::invite),
        ("/invitation/options", State::activation_options),
        ("/invitation/finish/{name}", State::activate),
        ("/recovery-code", State::recovery_code),
        ("/recover/options", State::recovery_options),
        ("/recover/finish", State::recover),
        ("/rsauthnz.js", |_, _, _| Ok(rsauthnz_http::browser_module())),
    ];
    let mut router = Router::new()
        .route(
            "/",
            get(|| async { page("text/html; charset=utf-8", include_str!("../www/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async { page("text/javascript; charset=utf-8", include_str!("../www/app.js")) }),
        );
    router = router
        .route(
            "/cli",
            get(|| async { page("text/html; charset=utf-8", include_str!("../www/cli.html")) }),
        )
        .route(
            "/cli.js",
            get(|| async { page("text/javascript; charset=utf-8", include_str!("../www/cli.js")) }),
        );
    for &(path, handler) in routes {
        let app = Arc::clone(&app);
        let serve = move |request: AxumRequest| async move {
            let (parts, body) = request.into_parts();
            let response = match axum::body::to_bytes(body, BODY_BYTES_MAX).await {
                Ok(bytes) => app.handle(handler, &Request::from_parts(parts, bytes)).await,
                Err(_) => Refusal::BodyBytes.response(),
            };
            response.map(Body::from)
        };
        router = router.route(path, any(serve));
    }
    router
}

/// A static page of the application.
fn page(kind: &'static str, text: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(text));
    response
        .headers_mut()
        .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static(kind));
    response
}

/// The authority of the records.
fn authority() -> Id<Authority> {
    id("web")
}

/// The identifier `value` of the namespace `web`, which each caller gives in a valid form.
fn id<K: rsauthnz::id::Kind>(value: &str) -> Id<K> {
    Id::new("web", value).expect("an identifier of the example")
}

/// An account of the directory of the application: its identifier, its user handle, its name, and its display name.
/// The application owns the names, and it gives them to each ceremony, so the next options give a new name.
#[derive(Clone)]
struct Account {
    id: Id<Human>,
    handle: UserHandle,
    name: String,
    display_name: String,
}

/// The policy of the example: each account that signed in with user verification may invite on the site.
struct Invitations {
    version: AuthorityVersion,
    expires: Duration,
}

impl authz::Policy for Invitations {
    fn version(&self) -> &AuthorityVersion {
        &self.version
    }

    fn resolve(&self, request: &authz::Request<'_>) -> Option<Permit> {
        (*request.action == id("account.invite") && *request.resource == id("site")).then(|| Permit {
            principal: request.principal.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            version: self.version.clone(),
            requires: Requirements {
                user_verified: true,
                phishing_resistant: true,
                max_age: SESSION_POLICY.lifetime,
            },
            expires: self.expires,
        })
    }
}

/// The output of a future of the memory binding, which is ready at its first poll.
#[expect(
    clippy::unreachable,
    reason = "the memory binding does no I/O, so each of its futures is ready at its first poll"
)]
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("the memory binding does no I/O"),
    }
}

/// The most string members of the JSON body of a request.
const MEMBERS_MAX: u32 = 8;

/// The limits of the JSON body of a request: one object of at most [`MEMBERS_MAX`] string members.
const BODY: json::Limits = json::Limits {
    input_bytes_max: 4 * 1024,
    depth_max: 1,
    string_bytes_max: 1024,
    members_max: MEMBERS_MAX,
    elements_max: 0,
    number_digits_max: 1,
};

/// The string members `names` of the JSON object `body`. A missing member refuses.
fn fields<const N: usize>(body: &[u8], names: [&str; N]) -> Result<[String; N], Problem> {
    // The reader takes one slot for the object and one for each of its keys.
    let mut scratch = [Slot::EMPTY; 1 + MEMBERS_MAX as usize];
    let found = json::read(body, &BODY, Rfc8259, &mut scratch, |reader| {
        let mut found: [Option<String>; N] = [const { None }; N];
        let mut members = reader.value().members()?;
        while let Some((name, value)) = members.next()? {
            if let Some(at) = names.iter().position(|wanted| name == *wanted) {
                let mut buffer = [0; 1024];
                found[at] = Some(value.str()?.decode(&mut buffer)?.to_owned());
            }
        }
        Ok(found)
    })
    .map_err(|_| Problem::Recovery(Recovery::Refuse))?;
    let mut out = [const { String::new() }; N];
    for (out, found) in out.iter_mut().zip(found) {
        *out = found.ok_or(Problem::Recovery(Recovery::Refuse))?;
    }
    Ok(out)
}

/// A JSON response that `value` writes. A handler writes it after its commit, so a refused write gives
/// [`Recovery::Lookup`]: the client loads the current state, and never sends the request again.
fn reply(value: impl FnOnce(json::Place<'_>) -> Result<(), json::Error>) -> Result<Response<Vec<u8>>, Problem> {
    let mut out = vec![0; 64 * 1024];
    let len = json::write(&mut out, value).map_err(|_| Problem::Recovery(Recovery::Lookup))?;
    out.truncate(len);
    Ok(json_reply(out))
}

/// The bytes of the base64url text `text`.
fn base64url(text: &str) -> Result<Vec<u8>, Problem> {
    let text = text.as_bytes();
    let mut out = vec![0; Url.decoded_len(text).map_err(|_| Problem::Recovery(Recovery::Refuse))?];
    Url.decode(text, &mut out)
        .map_err(|_| Problem::Recovery(Recovery::Refuse))?;
    Ok(out)
}

/// A name of an account, which a path segment can hold.
fn name(text: &str) -> Result<&str, Problem> {
    let valid = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-_@".contains(&byte);
    (!text.is_empty() && text.len() <= NAME_BYTES_MAX && text.bytes().all(valid))
        .then_some(text)
        .ok_or(Problem::Recovery(Recovery::Refuse))
}

/// The state of the application: the relying party ID, the store and its commit driver, the site, the relying party,
/// the sessions, the generator, the directory of accounts by name, and the policy of invitations.
struct State {
    rp_id: String,
    memory: Memory,
    driver: Driver,
    cli: local::Authority,
    issuer: keys::Keys,
    sign_in_not_before: Duration,
    site: Site,
    rp: RelyingParty,
    sessions: Sessions,
    random: ChaCha20Rng,
    accounts: BTreeMap<String, Account>,
    policy: Invitations,
}

/// Gives each driver effect to the memory binding with the time of this request.
fn settle(memory: &mut Memory, driver: &mut Driver, now: Reading) {
    memory.set_clock(now);
    while let Some(effect) = driver.effect() {
        let output = ready(suite::execute(memory, effect));
        if driver.give(output).is_err() {
            break;
        }
    }
}

impl State {
    /// A start of the driver on the store: after a crash, and after a response that the store lost.
    fn start(&mut self, now: Reading) -> Result<(), Problem> {
        self.driver.start(now);
        settle(&mut self.memory, &mut self.driver, now);
        self.sign_in_not_before = ready(self.rp.sign_in_not_before(&mut self.memory))?;
        Ok(())
    }

    /// The receipt of the accepted commit of `proposal`. After a lost response, the driver starts again, and the
    /// receipt is the one of the lookup of the operation, which has no artifact.
    fn commit(&mut self, (proposal, plan): (Proposal, Plan), now: Reading) -> Result<Receipt, Problem> {
        let operation = proposal.operation().clone();
        let ticket = self.driver.submit(proposal, plan)?;
        settle(&mut self.memory, &mut self.driver, now);
        match self.driver.take(ticket) {
            Some(Answer::Outcome(Outcome::Accepted(receipt))) => return Ok(receipt),
            Some(Answer::Outcome(Outcome::Unknown(_))) => {}
            Some(Answer::Outcome(outcome)) => {
                return Err(Problem::Recovery(outcome.recovery().unwrap_or(Recovery::Restart)));
            }
            _ => return Err(Problem::Recovery(Recovery::Lookup)),
        }
        self.start(now)?;
        let ticket = self.driver.lookup(operation)?;
        settle(&mut self.memory, &mut self.driver, now);
        match self.driver.take(ticket) {
            Some(Answer::Lookup(Lookup::Committed(receipt))) => Ok(receipt),
            Some(Answer::Lookup(Lookup::Absent)) => Err(Problem::Recovery(Recovery::Restart)),
            Some(Answer::Lookup(Lookup::Refused(error))) => Err(error.into()),
            _ => Err(Problem::Recovery(Recovery::Lookup)),
        }
    }

    /// The artifact of the accepted commit of `proposal`. A lookup gives no artifact, so the client starts again.
    fn artifact(&mut self, proposal: (Proposal, Plan), now: Reading) -> Result<Vec<u8>, Problem> {
        let receipt = self.commit(proposal, now)?;
        receipt
            .artifact()
            .map(<[u8]>::to_vec)
            .ok_or(Problem::Recovery(Recovery::Restart))
    }

    /// The proposal of the policy record of invitations, at its version.
    fn policy_record(&mut self, now: Reading) -> Result<(Proposal, Plan), transition::Error> {
        let audit = Audit {
            actor: Principal::Human(id("operator")),
            action: id("policy.change"),
            time: now,
        };
        let mut operation = [0; 16];
        self.random.fill_bytes(&mut operation);
        let mut proposal = Proposal::new(OperationId::new(&operation)?, audit, &Value::Null, Limits::default())?;
        let key = store::policy_key(&authority());
        proposal.read(Dependency::Absent(key.clone()))?;
        proposal.change(Change::Write {
            key,
            version: self.policy.version.clone(),
            end: None,
            data: Box::from(*b"each account may invite"),
        })?;
        Ok((proposal, Plan::default()))
    }

    /// The session of `request`, which serves it. A request with no session refuses. A cookie that is not valid, an
    /// unknown or ended session, and a reused identifier also clear the cookie, and a reused identifier ends its
    /// family.
    fn access(&mut self, request: &Request<Bytes>, now: Reading) -> Result<(Access, Account), Problem> {
        let identifier = match SESSION.session(request.headers()) {
            Ok(Some(identifier)) => identifier,
            Ok(None) => return Err(Problem::Recovery(Recovery::Refuse)),
            Err(_) => return Err(Problem::SignedOut(SESSION)),
        };
        let access = match ready(self.sessions.check(&mut self.memory, &identifier, now)) {
            Ok(Check::Active(access)) => access,
            Ok(Check::Reused(proposal, plan)) => {
                self.commit((proposal, plan), now)?;
                return Err(Problem::SignedOut(SESSION));
            }
            Err(session::Failure::Refused(session::Error::Unknown | session::Error::Ended)) => {
                return Err(Problem::SignedOut(SESSION));
            }
            Err(failure) => return Err(failure.into()),
        };
        let account = self
            .accounts
            .values()
            .find(|account| account.id == *access.session().account())
            .cloned()
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        Ok((access, account))
    }

    /// The account and the fresh user verification of the session of `request`.
    fn fresh(&mut self, request: &Request<Bytes>, now: Reading) -> Result<(Access, Fresh, Account), Problem> {
        let (access, account) = self.access(request, now)?;
        let fresh = Fresh::check(&access, FRESH_MAX, now)?;
        Ok((access, fresh, account))
    }

    /// The account and its names, as the authenticator shows them.
    fn user<'a>(account: &'a Account) -> User<'a> {
        User {
            account: &account.id,
            handle: account.handle,
            name: &account.name,
            display_name: &account.display_name,
        }
    }

    /// A new account of the directory, with the name `name`, which is also its first display name.
    fn new_account(&mut self, name: &str) -> Result<Account, Problem> {
        (!self.accounts.contains_key(name)).ok_or(Problem::Recovery(Recovery::Refuse))?;
        let account = Account {
            id: id(&format!("u-{}", self.accounts.len())),
            handle: UserHandle::random(&mut self.random),
            name: name.to_owned(),
            display_name: name.to_owned(),
        };
        self.accounts.insert(name.to_owned(), account.clone());
        Ok(account)
    }

    /// The account, its passkeys, and its sessions. The current session is the one of the request. The relying party
    /// ID, the user handle, the names, and the IDs of the passkeys are the data of `signalRenamed` and
    /// `signalAccepted`, which the page calls at each load.
    fn account(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let (access, account) = self.access(request, now)?;
        let passkeys = ready(self.rp.passkeys(&mut self.memory, &account.handle))?;
        let page = ready(self.sessions.list(&mut self.memory, &access, None, now))?;
        reply(|place| {
            place.object(|object| {
                object.member("rpId").str(&self.rp_id)?;
                object.member("userId").base64url(&account.handle.to_bytes())?;
                object.member("name").str(&account.name)?;
                object.member("displayName").str(&account.display_name)?;
                object.member("passkeys").array(|items| {
                    for passkey in &passkeys {
                        items.item().object(|item| {
                            item.member("id").base64url(passkey.credential().id())?;
                            item.member("name").str(passkey.credential().name())
                        })?;
                    }
                    Ok(())
                })?;
                object.member("sessions").array(|items| {
                    for session in &page.sessions {
                        items.item().object(|item| {
                            item.member("key").base64url(session.key().as_bytes())?;
                            item.member("current").bool(session.key() == access.session().key())
                        })?;
                    }
                    Ok(())
                })
            })
        })
    }

    /// The options of the sign-up of a new account with the name of the request.
    fn sign_up_options(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [text] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["name"])?;
        let account = self.new_account(name(&text)?)?;
        let user = Self::user(&account);
        let start = self.rp.start(
            &mut self.memory,
            &user,
            Decision::SignUp(&[]),
            now,
            &mut self.random,
            &mut self.driver,
        );
        let proposal = ready(start)?;
        Ok(json_reply(self.artifact(proposal, now)?))
    }

    /// The first passkey of a new account.
    fn sign_up_finish(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let response = passkey::Response::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let registration = ready(self.rp.finish(&mut self.memory, &response, now, &mut self.driver))?;
        self.commit(registration.propose(Decision::SignUp(&[]))?, now)?;
        Ok(json_reply(b"{}".to_vec()))
    }

    /// The options of a sign-in. They name no passkey, so the browser offers each passkey of the site.
    fn sign_in_options(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        self.site.check_change(request)?;
        Ok(json_reply(self.rp.sign_in_options(now, &mut self.random)?))
    }

    /// A sign-in, which replaces the session of the request, and its session cookie.
    fn sign_in_finish(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let assertion = Assertion::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let replaces = self.access(request, now).ok().map(|(access, _)| access);
        let sign_in = ready(
            self.rp
                .sign_in(&mut self.memory, &assertion, now, &mut self.random, &mut self.driver),
        )?;
        let (proposal, plan, opening) =
            sign_in.open(&self.sessions, replaces.as_ref(), &mut self.random, &mut self.driver)?;
        let receipt = self.commit((proposal, plan), now)?;
        let opened = opening
            .release(&Outcome::Accepted(receipt))
            .ok_or(Problem::Recovery(Recovery::Lookup))?;
        let mut response = json_reply(b"{}".to_vec());
        let identifier = opened.session.identifier();
        self.site
            .set_session(response.headers_mut(), SESSION, identifier, opened.session.max_age(now))?;
        Ok(response)
    }

    /// The end of the session of the request.
    fn sign_out(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        self.site.check_change(request)?;
        let (access, _) = self.access(request, now)?;
        let proposal = self
            .sessions
            .revoke(access.session(), Revoker::Own(&access), &[], now, &mut self.random)?;
        self.commit(proposal, now)?;
        let mut response = json_reply(b"{}".to_vec());
        self.site.clear_cookie(response.headers_mut(), SESSION);
        Ok(response)
    }

    /// The passkey `id` (base64url) of `account`.
    fn passkey(&mut self, account: &Account, id: &str) -> Result<account::Passkey, Problem> {
        let id = base64url(id)?;
        let passkeys = ready(self.rp.passkeys(&mut self.memory, &account.handle))?;
        passkeys
            .into_iter()
            .find(|passkey| passkey.credential().id() == id)
            .ok_or(Problem::Recovery(Recovery::Refuse))
    }

    /// A new name of a passkey of the account. A rename needs no fresh user verification, and the page makes no
    /// Signals call: a provider keeps its own label of a passkey.
    fn rename(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [id, text] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["id", "name"])?;
        let (access, account) = self.access(request, now)?;
        let passkey = self.passkey(&account, &id)?;
        let proposal = self
            .rp
            .rename(&access, &passkey, &text, now, &mut self.random, &mut self.driver)?;
        self.commit(proposal, now)?;
        Ok(json_reply(b"{}".to_vec()))
    }

    /// The removal of a passkey of the account, with a fresh user verification. The page then calls `signalDeleted`
    /// with the ID of the passkey, and its next load calls `signalAccepted`.
    fn remove(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [id] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["id"])?;
        let (_, fresh, account) = self.fresh(request, now)?;
        let removed = self.passkey(&account, &id)?;
        let proposal = ready(self.rp.remove(
            &mut self.memory,
            &fresh,
            &removed,
            now,
            &mut self.random,
            &mut self.driver,
        ))?;
        self.commit(proposal, now)?;
        Ok(json_reply(b"{}".to_vec()))
    }

    /// A new name and a new display name of the account of the session. A new name needs a fresh user verification,
    /// because the name finds the account at a recovery. A new display name needs only the session. The next load of
    /// the page gives the new names to `signalRenamed`.
    fn rename_account(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [text, display_name] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["name", "displayName"])?;
        let new = name(&text)?;
        (1..=passkey::NAME_BYTES_MAX)
            .contains(&display_name.len())
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        let (access, account) = self.access(request, now)?;
        if new != account.name {
            Fresh::check(&access, FRESH_MAX, now)?;
            (!self.accounts.contains_key(new)).ok_or(Problem::Recovery(Recovery::Refuse))?;
        }
        self.accounts.remove(&account.name);
        let renamed = Account {
            name: new.to_owned(),
            display_name,
            ..account
        };
        self.accounts.insert(renamed.name.clone(), renamed);
        Ok(json_reply(b"{}".to_vec()))
    }

    /// The options of an additional passkey of the account, with a fresh user verification.
    fn add_options(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        self.site.check_change(request)?;
        let (_, fresh, account) = self.fresh(request, now)?;
        let user = Self::user(&account);
        let start = self.rp.start(
            &mut self.memory,
            &user,
            Decision::Add(&fresh, &[]),
            now,
            &mut self.random,
            &mut self.driver,
        );
        let proposal = ready(start)?;
        Ok(json_reply(self.artifact(proposal, now)?))
    }

    /// An additional passkey of the account. The verification must still hold at the commit.
    fn add_finish(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let response = passkey::Response::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let (_, fresh, _) = self.fresh(request, now)?;
        let registration = ready(self.rp.finish(&mut self.memory, &response, now, &mut self.driver))?;
        self.commit(registration.propose(Decision::Add(&fresh, &[]))?, now)?;
        Ok(json_reply(b"{}".to_vec()))
    }

    /// The end of a session of the account: the session of the request with no verification, and another one with a
    /// fresh user verification.
    fn revoke(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [key] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["key"])?;
        let key = base64url(&key)?;
        let (access, _account) = self.access(request, now)?;
        let page = ready(self.sessions.list(&mut self.memory, &access, None, now))?;
        let session = page
            .sessions
            .iter()
            .find(|session| session.key().as_bytes() == key)
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        let proposal = if session.key() == access.session().key() {
            self.sessions
                .revoke(session, Revoker::Own(&access), &[], now, &mut self.random)?
        } else {
            let fresh = Fresh::check(&access, FRESH_MAX, now)?;
            self.sessions
                .revoke(session, Revoker::Fresh(&fresh), &[], now, &mut self.random)?
        };
        self.commit(proposal, now)?;
        Ok(json_reply(b"{}".to_vec()))
    }

    /// An invitation of a new account with the name of the request, from the session of the request. Only the
    /// accepted commit gives its value.
    fn invite(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [text] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["name"])?;
        let (access, _) = self.access(request, now)?;
        let recipient = self.new_account(name(&text)?)?;
        let (action, resource): (Id<Action>, Id<Resource>) = (id("account.invite"), id("site"));
        let invite = Invite {
            recipient: &recipient.id,
            handle: recipient.handle,
            action: &action,
            resource: &resource,
            lifetime: INVITATION_LIFETIME,
        };
        let proposal = self.rp.invite(
            access.session().evidence(),
            &self.policy,
            &invite,
            now,
            &mut self.random,
            &mut self.driver,
        )?;
        let value = self.artifact(proposal, now)?;
        reply(|place| place.object(|object| object.member("invitation").base64url(&value)))
    }

    /// The options of the activation of an invitation by the account that it names.
    fn activation_options(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [value, text] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["invitation", "name"])?;
        let value = base64url(&value)?;
        (value.len() == INVITATION_BYTES).ok_or(Problem::Recovery(Recovery::Refuse))?;
        let account = self
            .accounts
            .get(name(&text)?)
            .cloned()
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        let invitee = Invitee {
            account: &account.id,
            name: &account.name,
            display_name: &account.display_name,
        };
        let options = ready(
            self.rp
                .activation_options(&mut self.memory, &value, &invitee, now, &mut self.random),
        )?;
        Ok(json_reply(options))
    }

    /// The activation of an invitation: its first passkey, in one commit that consumes the invitation. The path names
    /// the account.
    fn activate(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let text = request
            .uri()
            .path()
            .strip_prefix("/invitation/finish/")
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        let account = self
            .accounts
            .get(name(text)?)
            .cloned()
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        let response = passkey::Response::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let activate = self.rp.activate(
            &mut self.memory,
            &response,
            &account.id,
            &self.policy,
            now,
            &mut self.driver,
        );
        let activation = ready(activate)?;
        self.commit(activation.propose(&[])?, now)?;
        Ok(json_reply(b"{}".to_vec()))
    }

    /// A new recovery code of the account, with a fresh user verification. Only the accepted commit gives its text.
    fn recovery_code(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        self.site.check_change(request)?;
        let (_, fresh, account) = self.fresh(request, now)?;
        let code = ready(self.rp.recovery_code(
            &mut self.memory,
            &fresh,
            &account.handle,
            now,
            &mut self.random,
            &mut self.driver,
        ))?;
        let text = self.artifact(code, now)?;
        let text = core::str::from_utf8(&text).map_err(|_| Problem::Recovery(Recovery::Restart))?;
        reply(|place| place.object(|object| object.member("code").str(text)))
    }

    /// The options of a recovery of the account with the name of the request, with its code.
    fn recovery_options(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [text, code] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["name", "code"])?;
        let account = self
            .accounts
            .get(name(&text)?)
            .cloned()
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        let code = Code::parse(code.as_bytes())?;
        let user = Self::user(&account);
        let options = ready(
            self.rp
                .recovery_options(&mut self.memory, &user, &code, now, &mut self.random),
        )?;
        Ok(json_reply(options))
    }

    /// A recovery: one commit consumes the code, writes the new passkey, ends each other passkey and each session that
    /// fits, and opens a new session. The page offers a new code at once.
    fn recover(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let response = passkey::Response::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let recover = self.rp.recover(
            &mut self.memory,
            &response,
            &self.sessions,
            Passkeys::End,
            now,
            &mut self.random,
            &mut self.driver,
        );
        let attempt = ready(recover)?;
        let (proposal, plan, opening) = attempt.propose(&[])?;
        let receipt = self.commit((proposal, plan), now)?;
        let opened = opening
            .release(&Outcome::Accepted(receipt))
            .ok_or(Problem::Recovery(Recovery::Lookup))?;
        let mut response = json_reply(b"{}".to_vec());
        let identifier = opened.session.identifier();
        self.site
            .set_session(response.headers_mut(), SESSION, identifier, opened.session.max_age(now))?;
        Ok(response)
    }
}
