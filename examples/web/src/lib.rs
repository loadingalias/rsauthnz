//! A web application on axum that mounts `rsauthnz-http`: a sign-up with a passkey, the sign-in, the names, the
//! passkeys, and the sessions of an account, an invitation of a new account, and recovery with a code. It keeps each
//! record in a store of the storage contract. The binaries use the memory binding of `rsauthnz-conformance`, so a
//! restart loses each account.
//!
//! [`router`] gives the routes. Each route reads the body within [`BODY_BYTES_MAX`]. One thread owns the state of the
//! [`App`], and a request that needs the state waits for that thread in a queue of [`PENDING_MAX`] places. A request
//! over a limit gets its refusal on the request path. [`serve`] serves the routes until its shutdown, and then joins
//! the thread. `docs/content/web-example.md` gives the journey, the limits, and the commands.

mod cli;
#[path = "../../shared/keys.rs"]
mod keys;

use core::fmt;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::task::Wake;
use std::thread;

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
use rsauthnz::store::{self, Profile};
use rsauthnz::time::Reading;
use rsauthnz::transition::{self, Audit, Change, Dependency, OperationId, Outcome, Proposal, Receipt, Recovery};
use rsauthnz_conformance::suite::{self, Subject};
use rsauthnz_http::{CookieName, Problem, Refusal, Site, json as json_reply};
use rscodec::base64::Profile::Url;
use rscodec::json::{self, Profile::Rfc8259, Slot};
use rscrypto::ChaCha20Rng;
use tokio::sync::oneshot;

/// The most bytes of a request body: a registration response with an RSA key fits.
pub const BODY_BYTES_MAX: usize = 16 * 1024;

/// The most bytes of an account name. A name has only lowercase ASCII letters, digits, and `.`, `-`, `_`, and `@`, so
/// it is also a path segment.
pub const NAME_BYTES_MAX: usize = 64;

/// The most account drafts this local example keeps until registration expires.
const PENDING_SIGNUPS_MAX: usize = 128;

/// The most requests that wait for the application thread. The next one gets the overload response.
pub const PENDING_MAX: usize = 64;

/// The most waiting sign-ins of one credential. A flood with one credential thus leaves places for each other one.
pub const SHARE_MAX: usize = 8;

/// The time between two expiry passes.
pub const EXPIRY_INTERVAL: Duration = Duration::from_secs(1);

/// The most ended records of each kind that one expiry pass removes.
pub const EXPIRY_BATCH: NonZeroUsize = NonZeroUsize::new(256).expect("256 is not zero");

/// The commit budget: one commit in each interval, which is 20 commits in each second.
pub const COMMIT_INTERVAL: Duration = Duration::from_millis(50);

/// The most commits that the budget takes at one time.
pub const COMMIT_BURST: u32 = 100;

/// The most accounts of the directory, with each invited account.
pub const ACCOUNTS_MAX: usize = 1024;

/// The time that the store of the binaries keeps an audit record and an outcome record.
pub const RETENTION: Duration = Duration::from_secs(60 * 60);

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
pub type Clock = Arc<dyn Fn() -> Reading + Send + Sync>;

/// The waiting sign-ins of each credential ID. An entry lives while a sign-in of its credential waits, so the map has
/// at most [`PENDING_MAX`] entries. The map is ordered, so an ID of a peer selects no hash.
type Shares = Arc<Mutex<BTreeMap<Box<[u8]>, usize>>>;

/// The application. One thread owns its state, and a request that needs the state waits for that thread in one
/// bounded queue. The request path holds what a check before the queue needs.
pub struct App<S> {
    site: Site,
    rp: Arc<RelyingParty>,
    clock: Arc<dyn Fn() -> Reading + Send + Sync>,
    /// The generator of the sign-in options, which the request path makes.
    random: Mutex<ChaCha20Rng>,
    /// The earliest time of a sign-in challenge that the store accepts, in nanoseconds since the Unix epoch. The
    /// application thread writes it at each start of the driver.
    sign_in_not_before: Arc<AtomicU64>,
    /// The queue of the application thread, or `None` after [`App::stop`].
    jobs: Mutex<Option<mpsc::SyncSender<Job<S>>>>,
    shares: Shares,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl<S> fmt::Debug for App<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The application holds secrets, such as the key of the relying party.
        f.debug_struct("App").finish_non_exhaustive()
    }
}

/// A request in the queue of the application thread.
struct Job<S> {
    handler: Handler<S>,
    request: Request<Bytes>,
    reply: oneshot::Sender<Response<Vec<u8>>>,
    /// The place of a sign-in among the waiting sign-ins of its credential. It ends with the job.
    _share: Option<Share>,
}

/// One waiting sign-in of a credential. Its drop gives the place back.
struct Share {
    shares: Shares,
    id: Box<[u8]>,
}

impl Drop for Share {
    fn drop(&mut self) {
        let mut shares = self.shares.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = shares.get_mut(&self.id) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                shares.remove(&self.id);
            }
        }
    }
}

impl<S: Subject + Send + 'static> App<S> {
    /// The application of the site `origin` on `store`, with the clock `clock` and the generator `random`. It opens
    /// the CLI issuer key in `directory`, commits the invitation policy, and starts the application thread.
    ///
    /// # Errors
    ///
    /// Returns the cause if the site, issuer key, authority, invitation policy, or thread cannot start.
    pub fn new(
        origin: &str,
        mut store: S,
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
        let rp = Arc::new(rp);
        let sessions = Sessions::new(authority(), id("app"), SESSION_POLICY, Limits::default())
            .map_err(|error| format!("the sessions: {error}"))?;
        let profile = Profile::new(store.declaration()).map_err(|error| format!("the profile: {error}"))?;
        let mut driver = Driver::new(profile, Limits::default()).map_err(|error| format!("the driver: {error}"))?;
        let now = clock();
        driver.start(now);
        settle(&mut store, &mut driver);
        let grant = local::HostGrant {
            owner: id("owner"),
            origin: id("app"),
        };
        let cli = wait(local::Authority::open(
            &mut store,
            &grant,
            id("cli"),
            issuer.handle.clone(),
            Limits::default(),
        ))
        .map_err(|error| format!("the CLI authority: {error}"))?;
        let version = AuthorityVersion::new(authority(), &[1]).map_err(|error| format!("the version: {error}"))?;
        let sign_in_not_before = Arc::new(AtomicU64::new(0));
        let requests = random.child(b"requests", 0);
        let mut state = State {
            rp_id: rp_id.to_owned(),
            store,
            driver,
            cli,
            issuer,
            clock: Arc::clone(&clock),
            sign_in_not_before: Arc::clone(&sign_in_not_before),
            site: site.clone(),
            rp: Arc::clone(&rp),
            sessions,
            random,
            accounts: BTreeMap::new(),
            signups: BTreeMap::new(),
            next_account: 0,
            commit_next: Duration::ZERO,
            expiry_next: Duration::ZERO,
            policy: Invitations {
                version,
                expires: now.estimate() + Duration::from_secs(30 * 24 * 60 * 60),
            },
        };
        state
            .not_before()
            .map_err(|problem| format!("the replay floor: {problem:?}"))?;
        let proposal = state
            .policy_record(now)
            .map_err(|error| format!("the policy: {error}"))?;
        state
            .commit(proposal, now)
            .map_err(|problem| format!("the commit of the policy: {problem:?}"))?;
        let (jobs, queue) = mpsc::sync_channel(PENDING_MAX);
        let thread = thread::Builder::new()
            .name("web-application".to_owned())
            .spawn(move || state.work(&queue))
            .map_err(|error| format!("the application thread: {error}"))?;
        Ok(Self {
            site,
            rp,
            clock,
            random: Mutex::new(requests),
            sign_in_not_before,
            jobs: Mutex::new(Some(jobs)),
            shares: Shares::default(),
            thread: Mutex::new(Some(thread)),
        })
    }

    /// Closes the queue and joins the application thread, which first serves each request that waits. Each later
    /// request gets the overload response.
    ///
    /// # Errors
    ///
    /// Returns [`Stopped`] if the application thread stopped with a panic.
    pub fn stop(&self) -> Result<(), Stopped> {
        drop(self.jobs.lock().unwrap_or_else(PoisonError::into_inner).take());
        let thread = self.thread.lock().unwrap_or_else(PoisonError::into_inner).take();
        thread.map_or(Ok(()), |thread| thread.join().map_err(|_| Stopped))
    }

    /// The response of `handler` to `request`. The request waits for the application thread, or it gets the overload
    /// response at once if the queue or the share of its credential is full.
    async fn handle(&self, handler: Handler<S>, mut request: Request<Bytes>) -> Response<Vec<u8>> {
        let share = match self.share(&mut request) {
            Ok(share) => share,
            Err(problem) => return problem.response(&self.site),
        };
        let (reply, response) = oneshot::channel();
        let job = Job {
            handler,
            request,
            reply,
            _share: share,
        };
        let queued = self
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|jobs| jobs.try_send(job).is_ok());
        if !queued {
            return Problem::Busy.response(&self.site);
        }
        // The application thread drops a job with no response only when it stops.
        response.await.unwrap_or_else(|_| Problem::Busy.response(&self.site))
    }

    /// The place of the sign-in `request` among the waiting sign-ins of its credential, and `None` for each other
    /// request. The parsed assertion goes with the request, so the application thread does not parse it again.
    fn share(&self, request: &mut Request<Bytes>) -> Result<Option<Share>, Problem> {
        if request.uri().path() != "/sign-in/finish" {
            return Ok(None);
        }
        let assertion = Assertion::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let id: Box<[u8]> = assertion.id().into();
        {
            let mut shares = self.shares.lock().unwrap_or_else(PoisonError::into_inner);
            let held = shares.get(&id).copied().unwrap_or(0);
            (held < SHARE_MAX).ok_or(Problem::Busy)?;
            shares.insert(id.clone(), held.saturating_add(1));
        }
        request.extensions_mut().insert(assertion);
        Ok(Some(Share {
            shares: Arc::clone(&self.shares),
            id,
        }))
    }

    /// The options of a sign-in. They name no passkey, so the browser offers each passkey of the site. They need no
    /// state of the application, so the request path makes them. After a start of the store, the request first waits
    /// until the clock can give a challenge that the store accepts.
    async fn sign_in_options(&self, request: &Request<Bytes>) -> Response<Vec<u8>> {
        if let Err(refusal) = self.site.check_change(request) {
            return refusal.response();
        }
        let delay = self.early();
        if !delay.is_zero() {
            if delay > passkey::SIGN_IN_LIFETIME {
                return rsauthnz_http::problem(Recovery::Restart);
            }
            tokio::time::sleep(delay).await;
            if !self.early().is_zero() {
                return rsauthnz_http::problem(Recovery::Restart);
            }
        }
        let mut random = self.random.lock().unwrap_or_else(PoisonError::into_inner);
        match self.rp.sign_in_options((self.clock)(), &mut random) {
            Ok(options) => json_reply(options),
            Err(error) => Problem::from(error).response(&self.site),
        }
    }

    /// The time from the earliest time of the clock to the first sign-in challenge that the store accepts.
    fn early(&self) -> Duration {
        let not_before = Duration::from_nanos(self.sign_in_not_before.load(Ordering::Relaxed));
        (self.clock)()
            .earliest()
            .map_or(Duration::ZERO, |earliest| not_before.saturating_sub(earliest))
    }
}

/// The application thread stopped with a panic, so [`App::stop`] joined no complete work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stopped;

impl fmt::Display for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the application thread stopped with a panic")
    }
}

impl core::error::Error for Stopped {}

/// A handler: the response to a request at a time, or the problem response of its refusal.
type Handler<S> = fn(&mut State<S>, &Request<Bytes>, Reading) -> Result<Response<Vec<u8>>, Problem>;

/// The request with its body, or `None` for a body over [`BODY_BYTES_MAX`].
async fn bounded(request: AxumRequest) -> Option<Request<Bytes>> {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, BODY_BYTES_MAX).await.ok()?;
    Some(Request::from_parts(parts, bytes))
}

/// The routes of the application. The pages, the browser module, and the sign-in options need no state, so the
/// request path serves them. Each other route waits for the application thread.
pub fn router<S: Subject + Send + 'static>(app: Arc<App<S>>) -> Router {
    let routes: &[(&str, Handler<S>)] = &[
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
        ("/sign-in/finish", State::sign_in_finish),
        ("/sign-out", State::sign_out),
        ("/passkeys/rename", State::rename),
        ("/passkeys/remove", State::remove),
        ("/passkeys/add/options", State::add_options),
        ("/passkeys/add/finish", State::add_finish),
        ("/sessions/renew", State::renew),
        ("/sessions/revoke", State::revoke),
        ("/invitations", State::invite),
        ("/invitation/options", State::activation_options),
        ("/invitation/finish/{name}", State::activate),
        ("/recovery-code", State::recovery_code),
        ("/recover/options", State::recovery_options),
        ("/recover/finish", State::recover),
    ];
    let mut router = Router::new()
        .route(
            "/",
            get(|| async { page("text/html; charset=utf-8", include_str!("../www/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async { page("text/javascript; charset=utf-8", include_str!("../www/app.js")) }),
        )
        .route(
            "/cli",
            get(|| async { page("text/html; charset=utf-8", include_str!("../www/cli.html")) }),
        )
        .route(
            "/cli.js",
            get(|| async { page("text/javascript; charset=utf-8", include_str!("../www/cli.js")) }),
        )
        .route(
            "/rsauthnz.js",
            get(|| async { rsauthnz_http::browser_module().map(Body::from) }),
        );
    let options = Arc::clone(&app);
    router = router.route(
        "/sign-in/options",
        any(move |request: AxumRequest| async move {
            match bounded(request).await {
                Some(request) => options.sign_in_options(&request).await,
                None => Refusal::BodyBytes.response(),
            }
            .map(Body::from)
        }),
    );
    for &(path, handler) in routes {
        let app = Arc::clone(&app);
        let serve = move |request: AxumRequest| async move {
            match bounded(request).await {
                Some(request) => app.handle(handler, request).await,
                None => Refusal::BodyBytes.response(),
            }
            .map(Body::from)
        };
        router = router.route(path, any(serve));
    }
    router
}

/// Serves `router` on `listener` until `shutdown` completes. Then it takes no new connection, waits for the response
/// of each request that it took, and joins the application thread of `app`.
///
/// # Errors
///
/// Returns the error of the listener, or [`Stopped`] as an error if the application thread stopped with a panic.
pub async fn serve<S: Subject + Send + 'static>(
    listener: tokio::net::TcpListener,
    router: Router,
    app: &App<S>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router).with_graceful_shutdown(shutdown).await?;
    app.stop().map_err(std::io::Error::other)
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

/// Wakes the thread that waits for a future of the store.
struct Unpark(thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// The output of `future`. A future of the memory binding is ready at its first poll. For a store that does not
/// answer at once, the thread parks until the store wakes it.
fn wait<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    if let Poll::Ready(output) = future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        return output;
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::park(),
        }
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

/// The state of the application, which its one thread owns: the relying party ID, the store and its commit driver, the
/// site, the relying party, the sessions, the generator, the directory of accounts by name, the policy of
/// invitations, and the times of the next commit of the budget and of the next expiry pass.
struct State<S> {
    rp_id: String,
    store: S,
    driver: Driver,
    cli: local::Authority,
    issuer: keys::Keys,
    clock: Arc<dyn Fn() -> Reading + Send + Sync>,
    sign_in_not_before: Arc<AtomicU64>,
    site: Site,
    rp: Arc<RelyingParty>,
    sessions: Sessions,
    random: ChaCha20Rng,
    accounts: BTreeMap<String, Account>,
    signups: BTreeMap<Id<Human>, (Account, Duration)>,
    next_account: u64,
    /// The time of the next commit at the rate of the budget. The budget is empty while this time is
    /// [`COMMIT_BURST`] intervals after the clock.
    commit_next: Duration,
    expiry_next: Duration,
    policy: Invitations,
}

/// Gives each effect of the driver to the store. The store reads its own clock for each commit with a deadline.
fn settle<S: Subject>(store: &mut S, driver: &mut Driver) {
    while let Some(effect) = driver.effect() {
        let output = wait(suite::execute(store, effect));
        if driver.give(output).is_err() {
            break;
        }
    }
}

impl<S: Subject> State<S> {
    /// Serves each request of `jobs`, one at a time, until the queue closes. Before each request, and at least once in
    /// each [`EXPIRY_INTERVAL`], it makes the expiry pass that is due.
    fn work(mut self, jobs: &mpsc::Receiver<Job<S>>) {
        loop {
            let job = match jobs.recv_timeout(EXPIRY_INTERVAL) {
                Ok(job) => Some(job),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
            let now = (self.clock)();
            self.expire(now);
            if let Some(job) = job {
                let response =
                    (job.handler)(&mut self, &job.request, now).unwrap_or_else(|problem| problem.response(&self.site));
                // A client that left takes no response.
                let _sent = job.reply.send(response);
            }
        }
    }

    /// One expiry pass, if one is due at `now`: it removes at most [`EXPIRY_BATCH`] ended records of each kind.
    fn expire(&mut self, now: Reading) {
        if now.estimate() >= self.expiry_next {
            self.expiry_next = now.estimate().saturating_add(EXPIRY_INTERVAL);
            // A pass that fails removes nothing, and the next pass tries again.
            let _pass = wait(store::expire(&mut self.store, now, EXPIRY_BATCH));
        }
    }

    /// A start of the driver on the store: after a crash, and after a response that the store lost.
    fn start(&mut self, now: Reading) -> Result<(), Problem> {
        self.driver.start(now);
        settle(&mut self.store, &mut self.driver);
        self.not_before()
    }

    /// Gives the request path the earliest time of a sign-in challenge that the store accepts.
    fn not_before(&mut self) -> Result<(), Problem> {
        let not_before = wait(self.rp.sign_in_not_before(&mut self.store))?;
        let nanos = u64::try_from(not_before.as_nanos()).unwrap_or(u64::MAX);
        self.sign_in_not_before.store(nanos, Ordering::Relaxed);
        Ok(())
    }

    /// The receipt of the accepted commit of `proposal`. A commit over the budget gets the overload response before
    /// the store does work for it. After a lost response, the driver starts again, and the receipt is the one of the
    /// lookup of the operation, which has no artifact.
    fn commit(&mut self, (proposal, plan): (Proposal, Plan), now: Reading) -> Result<Receipt, Problem> {
        let next = self.commit_next.max(now.estimate()).saturating_add(COMMIT_INTERVAL);
        (next.saturating_sub(now.estimate()) <= COMMIT_INTERVAL.saturating_mul(COMMIT_BURST)).ok_or(Problem::Busy)?;
        self.commit_next = next;
        let operation = proposal.operation().clone();
        let ticket = self.driver.submit(proposal, plan)?;
        settle(&mut self.store, &mut self.driver);
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
        settle(&mut self.store, &mut self.driver);
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
        let access = match wait(self.sessions.check(&mut self.store, &identifier, now)) {
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

    /// A draft for an available name. Only a committed registration or invitation claims the name.
    fn new_account(&mut self, name: &str) -> Result<Account, Problem> {
        (self.accounts.len() < ACCOUNTS_MAX).ok_or(Problem::Busy)?;
        (!self.accounts.contains_key(name)).ok_or(Problem::Recovery(Recovery::Refuse))?;
        let serial = self.next_account;
        self.next_account = serial.checked_add(1).ok_or(Problem::Recovery(Recovery::Refuse))?;
        Ok(Account {
            id: id(&format!("u-{serial}")),
            handle: UserHandle::random(&mut self.random),
            name: name.to_owned(),
            display_name: name.to_owned(),
        })
    }

    /// The account, its passkeys, and its sessions. The current session is the one of the request. The relying party
    /// ID, the user handle, the names, and the IDs of the passkeys are the data of `signalRenamed` and
    /// `signalAccepted`, which the page calls at each load.
    fn account(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let (access, account) = self.access(request, now)?;
        let passkeys = wait(self.rp.passkeys(&mut self.store, &account.handle))?;
        let page = wait(self.sessions.list(&mut self.store, &access, None, now))?;
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
        if self.signups.len() >= PENDING_SIGNUPS_MAX {
            self.signups.retain(|_, (_, end)| *end > now.estimate());
            (self.signups.len() < PENDING_SIGNUPS_MAX).ok_or(Problem::Recovery(Recovery::Restart))?;
        }
        let end = now
            .estimate()
            .checked_add(passkey::REGISTRATION_LIFETIME)
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        let account = self.new_account(name(&text)?)?;
        let user = Self::user(&account);
        let start = self.rp.start(
            &mut self.store,
            &user,
            Decision::SignUp(&[]),
            now,
            &mut self.random,
            &mut self.driver,
        );
        let proposal = wait(start)?;
        let options = self.artifact(proposal, now)?;
        self.signups.insert(account.id.clone(), (account, end));
        Ok(json_reply(options))
    }

    /// The first passkey of a new account.
    fn sign_up_finish(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let response = passkey::Response::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let registration = wait(self.rp.finish(&mut self.store, &response, now, &mut self.driver))?;
        let account = self
            .signups
            .get(registration.account())
            .map(|(account, _)| account)
            .filter(|account| !self.accounts.contains_key(&account.name))
            .cloned()
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        (self.accounts.len() < ACCOUNTS_MAX).ok_or(Problem::Busy)?;
        self.commit(registration.propose(Decision::SignUp(&[]))?, now)?;
        self.signups.remove(&account.id);
        self.accounts.insert(account.name.clone(), account);
        Ok(json_reply(b"{}".to_vec()))
    }

    /// A sign-in, which replaces the session of the request, and its session cookie.
    fn sign_in_finish(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        // The request path checked the request and parsed its assertion ([`App::share`]).
        let assertion = request
            .extensions()
            .get::<Assertion>()
            .cloned()
            .ok_or(Problem::Recovery(Recovery::Refuse))?;
        let replaces = self.access(request, now).ok().map(|(access, _)| access);
        let records = wait(self.rp.sign_in_read(&mut self.store, assertion, now))?;
        let (proposal, plan, opening) =
            records
                .verify()?
                .open(&self.sessions, replaces.as_ref(), &mut self.random, &mut self.driver)?;
        let receipt = self.commit((proposal, plan), now)?;
        let opened = opening
            .release(&Outcome::Accepted(receipt))
            .ok_or(Problem::Recovery(Recovery::Lookup))?;
        self.session_response(&opened.session, now)
    }

    fn session_response(&self, issued: &session::Issued, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let mut response = json_reply(b"{}".to_vec());
        self.site.set_session(
            response.headers_mut(),
            SESSION,
            issued.identifier(),
            issued.max_age(now),
        )?;
        Ok(response)
    }

    /// Rotates the current session cookie after the renewal commits.
    fn renew(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        self.site.check_change(request)?;
        let (access, _) = self.access(request, now)?;
        let (proposal, plan, renewal) = self.sessions.renew(&access, now, &mut self.random, &mut self.driver)?;
        let receipt = self.commit((proposal, plan), now)?;
        let issued = renewal
            .release(&Outcome::Accepted(receipt))
            .ok_or(Problem::Recovery(Recovery::Lookup))?;
        self.session_response(&issued, now)
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
        let passkeys = wait(self.rp.passkeys(&mut self.store, &account.handle))?;
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
        let proposal = wait(self.rp.remove(
            &mut self.store,
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
            &mut self.store,
            &user,
            Decision::Add(&fresh, &[]),
            now,
            &mut self.random,
            &mut self.driver,
        );
        let proposal = wait(start)?;
        Ok(json_reply(self.artifact(proposal, now)?))
    }

    /// An additional passkey of the account. The verification must still hold at the commit.
    fn add_finish(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let response = passkey::Response::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let (_, fresh, _) = self.fresh(request, now)?;
        let registration = wait(self.rp.finish(&mut self.store, &response, now, &mut self.driver))?;
        self.commit(registration.propose(Decision::Add(&fresh, &[]))?, now)?;
        Ok(json_reply(b"{}".to_vec()))
    }

    /// The end of a session of the account: the session of the request with no verification, and another one with a
    /// fresh user verification.
    fn revoke(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let [key] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["key"])?;
        let key = base64url(&key)?;
        let (access, _account) = self.access(request, now)?;
        let page = wait(self.sessions.list(&mut self.store, &access, None, now))?;
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
        self.accounts.insert(recipient.name.clone(), recipient);
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
        let options = wait(
            self.rp
                .activation_options(&mut self.store, &value, &invitee, now, &mut self.random),
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
            &mut self.store,
            &response,
            &account.id,
            &self.policy,
            now,
            &mut self.driver,
        );
        let activation = wait(activate)?;
        self.commit(activation.propose(&[])?, now)?;
        Ok(json_reply(b"{}".to_vec()))
    }

    /// A new recovery code of the account, with a fresh user verification. Only the accepted commit gives its text.
    fn recovery_code(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        self.site.check_change(request)?;
        let (_, fresh, account) = self.fresh(request, now)?;
        let code = wait(self.rp.recovery_code(
            &mut self.store,
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
        let options = wait(
            self.rp
                .recovery_options(&mut self.store, &user, &code, now, &mut self.random),
        )?;
        Ok(json_reply(options))
    }

    /// A recovery: one commit consumes the code, writes the new passkey, ends each other passkey and each session that
    /// fits, and opens a new session. The page offers a new code at once.
    fn recover(&mut self, request: &Request<Bytes>, now: Reading) -> Result<Response<Vec<u8>>, Problem> {
        let response = passkey::Response::parse(self.site.json_change(request, BODY_BYTES_MAX)?)?;
        let recover = self.rp.recover(
            &mut self.store,
            &response,
            &self.sessions,
            Passkeys::End,
            now,
            &mut self.random,
            &mut self.driver,
        );
        let attempt = wait(recover)?;
        let (proposal, plan, opening) = attempt.propose(&[])?;
        let receipt = self.commit((proposal, plan), now)?;
        let opened = opening
            .release(&Outcome::Accepted(receipt))
            .ok_or(Problem::Recovery(Recovery::Lookup))?;
        self.session_response(&opened.session, now)
    }
}
