//! The OpenID Connect relying-party engine: a login transaction, its callback, the token request, and the
//! verification of the ID token, against two providers whose keys the tests hold. Issuer A answers in the query and
//! advertises the `iss` response parameter. Issuer B answers with form_post and does not advertise it.

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::cbor::Value;
use rsauthnz::crypto::Algorithm;
use rsauthnz::id::{Human, Id, Principal, Workload};
use rsauthnz::jose;
use rsauthnz::limits::Limits;
use rsauthnz::oidc::{
    Binding, Callback, ClientAuth, Config, Error, Exchange, Federated, FetchError, Fetched, IssParameter, Issuer,
    LOGIN_LIFETIME, RelyingParty, ResponseMode,
};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{Profile, Store as _};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite;
use rscodec::base64::Profile::{Standard, Url};
use rscrypto::ChaCha20Rng;
use rscrypto::auth::{EcdsaP256SecretKey, Ed25519SecretKey};

const START: u64 = 1_800_000_000;
const A: &str = "https://a.example";
const B: &str = "https://b.example";
const REDIRECT_A: &str = "https://app.example/oidc/a";
const REDIRECT_B: &str = "https://app.example/oidc/b";

/// The reading at `seconds` past [`START`], with an uncertainty of one second.
fn at(seconds: u64) -> Reading {
    Reading::new(
        Duration::from_secs(START + seconds),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The output of `future`. The futures of the memory binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the memory binding does no I/O"),
    }
}

fn b64(bytes: &[u8]) -> String {
    let mut out = vec![0; Url.encoded_len(bytes.len()).expect("a length")];
    let text = Url.encode(bytes, &mut out).expect("base64url");
    String::from_utf8(text.to_vec()).expect("ASCII")
}

/// The signing key of the provider of `issuer`, and its JWK.
fn provider(issuer: &str) -> (Ed25519SecretKey, String) {
    let key = Ed25519SecretKey::from_bytes(if issuer == A { [1; 32] } else { [2; 32] });
    let x = b64(&key.public_key().to_bytes());
    (key, format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}"#))
}

/// The configuration of issuer A or B, with the ID token algorithms `algorithms` and the key set `set`.
fn config<'a>(issuer: &'a str, algorithms: &'a [Algorithm], set: &'a str) -> Config<'a> {
    let a = issuer == A;
    Config {
        issuer,
        client_id: if a { "client-a" } else { "client-b" },
        client_auth: if a {
            ClientAuth::Basic("secret a")
        } else {
            ClientAuth::Post("secret-b")
        },
        authorization_endpoint: if a {
            "https://a.example/authorize"
        } else {
            "https://b.example/auth?tenant=1"
        },
        token_endpoint: if a {
            "https://a.example/token"
        } else {
            "https://b.example/token"
        },
        redirect_uri: if a { REDIRECT_A } else { REDIRECT_B },
        response_mode: if a { ResponseMode::Query } else { ResponseMode::FormPost },
        iss_parameter: if a {
            IssParameter::Required
        } else {
            IssParameter::Optional
        },
        algorithms,
        key_set: set.as_bytes(),
    }
}

fn issuer(issuer: &str) -> Issuer {
    let set = format!(r#"{{"keys":[{}]}}"#, provider(issuer).1);
    Issuer::new(&config(issuer, &[Algorithm::Ed25519], &set), Limits::default()).expect("an issuer")
}

/// The memory binding, the commit driver on it, and the relying party of issuers A and B.
struct World {
    memory: Memory,
    driver: Driver,
    rp: RelyingParty,
    random: ChaCha20Rng,
}

/// A started login: its binding, and the parameters of its authorization request.
struct Started {
    binding: Binding,
    url: String,
}

impl Started {
    /// The value of the parameter `name` of the authorization request.
    fn param(&self, name: &str) -> String {
        let (_, query) = self.url.split_once('?').expect("a query");
        let prefix = format!("{name}=");
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("no parameter {name}"))
            .replace("%3A", ":")
            .replace("%2F", "/")
    }
}

impl World {
    fn new() -> Self {
        Self::with(vec![issuer(A), issuer(B)])
    }

    fn with(issuers: Vec<Issuer>) -> Self {
        let memory = Memory::new(Schedule::None);
        let driver = Driver::new(
            Profile::new(memory.declaration()).expect("a profile"),
            Limits::default(),
        )
        .expect("a driver");
        let rp = RelyingParty::new(
            Id::new("acme", "oidc").expect("an identifier"),
            issuers,
            Limits::default(),
        )
        .expect("a relying party");
        let mut world = Self {
            memory,
            driver,
            rp,
            random: ChaCha20Rng::from_seed([5; 32]),
        };
        world.driver.start(at(0));
        world.run();
        world
    }

    fn run(&mut self) {
        while let Some(effect) = self.driver.effect() {
            let output = ready(suite::execute(&mut self.memory, effect));
            self.driver.give(output).expect("the driver takes the output");
        }
    }

    fn commit(&mut self, proposal: Proposal, plan: Plan) -> Outcome {
        let ticket = self.driver.submit(proposal, plan).expect("a submission");
        self.run();
        match self.driver.take(ticket) {
            Some(Answer::Outcome(outcome)) => outcome,
            answer => panic!("the commit gave {answer:?}"),
        }
    }

    /// Commits a login with `issuer` at `seconds`, which asks for an authentication no older than `max_age`.
    fn start(&mut self, issuer: &str, max_age: Option<Duration>, seconds: u64) -> Started {
        let site = Principal::Workload(Id::<Workload>::new("acme", "app").expect("an identifier"));
        let (proposal, plan, login) = self
            .rp
            .start(issuer, site, max_age, at(seconds), &mut self.random)
            .expect("a start");
        let outcome = self.commit(proposal, plan);
        let (binding, url) = login.release(&outcome).expect("an accepted start");
        Started { binding, url }
    }

    fn callback(
        &mut self,
        redirect_uri: &str,
        callback: Callback<'_>,
        binding: &Binding,
        seconds: u64,
    ) -> Result<Exchange<'_>, Error> {
        let callback = self
            .rp
            .callback(&mut self.memory, redirect_uri, callback, binding, at(seconds));
        ready(callback).map_err(|failure| match failure {
            rsauthnz::oidc::Failure::Refused(error) => error,
            rsauthnz::oidc::Failure::Store(error) => panic!("the read failed: {error:?}"),
        })
    }

    /// The callback of issuer A for `login`, with the code `code`, at `seconds`.
    fn callback_a(&mut self, login: &Started, seconds: u64) -> Result<Exchange<'_>, Error> {
        let query = format!("code=code-a&state={}&iss=https%3A%2F%2Fa.example", login.param("state"));
        self.callback(REDIRECT_A, Callback::Query(&query), &login.binding, seconds)
    }
}

/// The claims of a valid ID token of issuer A for `login` at `seconds`: `sub`, `aud`, `iat`, `exp`, `nonce`,
/// `auth_time`, `acr`, `amr`, and an `email`, which no evidence takes.
fn claims(login: &Started, seconds: u64) -> serde_like::Claims {
    serde_like::Claims {
        iss: A.into(),
        sub: Some("248289761001".into()),
        aud: vec!["client-a".into()],
        azp: None,
        iat: START + seconds,
        exp: START + seconds + 300,
        nonce: Some(login.param("nonce")),
        auth_time: Some(START + seconds - 5),
    }
}

/// A small JSON writer of the claims of the tests.
mod serde_like {
    pub(super) struct Claims {
        pub(super) iss: String,
        pub(super) sub: Option<String>,
        pub(super) aud: Vec<String>,
        pub(super) azp: Option<String>,
        pub(super) iat: u64,
        pub(super) exp: u64,
        pub(super) nonce: Option<String>,
        pub(super) auth_time: Option<u64>,
    }

    impl Claims {
        pub(super) fn json(&self) -> String {
            let aud: Vec<String> = self.aud.iter().map(|aud| format!(r#""{aud}""#)).collect();
            let mut out = format!(
                r#"{{"iss":"{}","aud":[{}],"iat":{},"exp":{},"acr":"urn:mace:incommon:iap:silver","amr":["pwd","otp"],"email":"alice@example.com""#,
                self.iss,
                aud.join(","),
                self.iat,
                self.exp
            );
            for (name, value) in [("sub", &self.sub), ("azp", &self.azp), ("nonce", &self.nonce)] {
                if let Some(value) = value {
                    out.push_str(&format!(r#","{name}":"{value}""#));
                }
            }
            if let Some(auth_time) = self.auth_time {
                out.push_str(&format!(r#","auth_time":{auth_time}"#));
            }
            out.push('}');
            out
        }
    }
}

/// The ID token of `claims`, signed by `key`.
fn id_token(key: &Ed25519SecretKey, claims: &serde_like::Claims) -> String {
    let input = jose::signing_input(Algorithm::Ed25519, None, None, claims.json().as_bytes()).expect("an input");
    jose::compact(&input, &key.sign(input.as_bytes()).to_bytes())
}

/// The token response of the ID token `token`.
fn response(token: &str) -> String {
    format!(r#"{{"access_token":"at-1","token_type":"Bearer","expires_in":3600,"id_token":"{token}"}}"#)
}

/// The result of the finish of `exchange` with the response that the provider of A signs for `claims` at `seconds`.
fn finish(exchange: Exchange<'_>, claims: &serde_like::Claims, seconds: u64) -> Result<Federated, Error> {
    let body = response(&id_token(&provider(A).0, claims));
    let fetched = Fetched {
        status: 200,
        body: body.as_bytes(),
    };
    exchange
        .finish(Ok(fetched), at(seconds))
        .map(|sign_in| sign_in.evidence().clone())
}

#[test]
fn a_valid_callback_gives_evidence_with_exactly_the_verified_claims_and_consumes_its_transaction() {
    let mut world = World::new();
    let login = world.start(A, Some(Duration::from_secs(600)), 10);
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", "client-a"),
        ("redirect_uri", REDIRECT_A),
        ("scope", "openid"),
        ("code_challenge_method", "S256"),
    ] {
        assert_eq!(login.param(name), value);
    }
    assert!(login.url.starts_with("https://a.example/authorize?response_type=code&"));
    assert_eq!(login.param("max_age"), "600");

    let exchange = world.callback_a(&login, 20).expect("a callback");
    let request = exchange.request();
    assert_eq!(request.url(), "https://a.example/token");
    // client_secret_basic: the base64 of the form encodings of the client ID and the secret.
    let mut basic = vec![0; Standard.encoded_len(17).expect("a length")];
    let basic = Standard
        .encode(b"client-a:secret+a", &mut basic)
        .expect("base64")
        .to_vec();
    assert_eq!(
        request.authorization(),
        Some([b"Basic ".as_slice(), &basic].concat().as_slice())
    );
    let body = core::str::from_utf8(request.body()).expect("ASCII");
    let verifier = body
        .split('&')
        .find_map(|pair| pair.strip_prefix("code_verifier="))
        .expect("a verifier");
    assert_eq!(
        body,
        format!(
            "grant_type=authorization_code&code=code-a&redirect_uri=https%3A%2F%2Fapp.example%2Foidc%2Fa&code_verifier={verifier}"
        )
    );
    // PKCE S256: the challenge of the request is the base64url of the SHA-256 digest of the verifier.
    assert_eq!(
        login.param("code_challenge"),
        b64(&rscrypto::Sha256::digest(verifier.as_bytes()))
    );

    let body = response(&id_token(&provider(A).0, &claims(&login, 19)));
    let fetched = Fetched {
        status: 200,
        body: body.as_bytes(),
    };
    let sign_in = exchange.finish(Ok(fetched), at(20)).expect("a sign-in");
    assert_eq!(
        sign_in.evidence(),
        &Federated {
            issuer: A.into(),
            subject: "248289761001".into(),
            auth_time: Some(Duration::from_secs(START + 14)),
            acr: Some("urn:mace:incommon:iap:silver".into()),
            amr: vec!["pwd".into(), "otp".into()],
            time: at(20),
        }
    );

    let alice: Id<Human> = Id::new("acme", "alice").expect("an identifier");
    let audit = Audit {
        actor: Principal::Human(alice),
        action: Id::new("acme", "sign-in").expect("an identifier"),
        time: at(20),
    };
    let mut proposal = Proposal::new(
        OperationId::new(b"sign-in").expect("an identity"),
        audit,
        &Value::Text("sign-in"),
        Limits::default(),
    )
    .expect("a proposal");
    sign_in.consume(&mut proposal).expect("the consumption");
    assert!(matches!(world.commit(proposal, Plan::default()), Outcome::Accepted(_)));
    // A replayed callback finds no transaction.
    assert_eq!(world.callback_a(&login, 21).err(), Some(Error::Transaction));
}

/// The mix-up defense: the issuer of a callback comes from its transaction. A response of issuer A that comes to the
/// redirect URI of a transaction of issuer B refuses before the code goes to the token endpoint of B, and so does a
/// response of A that has no `iss` while A advertises it.
#[test]
fn a_mix_up_callback_refuses_before_its_token_request() {
    let mut world = World::new();
    let login = world.start(B, None, 10);
    let form = format!("code=code-a&state={}&iss=https%3A%2F%2Fa.example", login.param("state"));
    assert_eq!(
        world
            .callback(REDIRECT_B, Callback::Form(form.as_bytes()), &login.binding, 20)
            .err(),
        Some(Error::Mixup)
    );
    // Issuer B does not advertise `iss`, so its own response with no `iss` passes.
    let form = format!("code=code-b&state={}", login.param("state"));
    let exchange = world
        .callback(REDIRECT_B, Callback::Form(form.as_bytes()), &login.binding, 20)
        .expect("a callback");
    assert_eq!(exchange.request().url(), "https://b.example/token");
    assert!(
        core::str::from_utf8(exchange.request().body())
            .expect("ASCII")
            .ends_with("&client_id=client-b&client_secret=secret-b")
    );
    assert!(
        login
            .url
            .starts_with("https://b.example/auth?tenant=1&response_type=code&")
    );
    assert_eq!(login.param("response_mode"), "form_post");

    let login = world.start(A, None, 10);
    let query = format!("code=code-a&state={}", login.param("state"));
    assert_eq!(
        world
            .callback(REDIRECT_A, Callback::Query(&query), &login.binding, 20)
            .err(),
        Some(Error::Mixup)
    );
    // The response of A at the redirect URI of B refuses, also with the `iss` of A.
    let query = format!("{query}&iss=https%3A%2F%2Fa.example");
    assert_eq!(
        world
            .callback(REDIRECT_B, Callback::Query(&query), &login.binding, 20)
            .err(),
        Some(Error::RedirectUri)
    );
}

#[test]
fn each_wrong_claim_of_the_id_token_refuses_with_its_outcome() {
    let mut world = World::new();
    let login = world.start(A, Some(Duration::from_secs(60)), 10);
    let other = provider(B).0;
    type Change = fn(&mut serde_like::Claims);
    let cases: [(&str, Change, Error); 9] = [
        ("nonce", |claims| claims.nonce = Some("another".into()), Error::Nonce),
        ("no nonce", |claims| claims.nonce = None, Error::Nonce),
        (
            "audience",
            |claims| claims.aud = vec!["client-b".into()],
            Error::IdToken(jose::Error::Audience),
        ),
        (
            "two audiences",
            |claims| claims.aud.push("client-b".into()),
            Error::AuthorizedParty,
        ),
        (
            "azp",
            |claims| claims.azp = Some("client-b".into()),
            Error::AuthorizedParty,
        ),
        (
            "expired",
            |claims| claims.exp = START + 20,
            Error::IdToken(jose::Error::Expired),
        ),
        (
            "issuer",
            |claims| claims.iss = B.into(),
            Error::IdToken(jose::Error::Issuer),
        ),
        // The start is the earliest time of its reading: 10 seconds, less its bound of 1.
        (
            "iat before the start",
            |claims| claims.iat = START + 9 - 61,
            Error::IssuedAt,
        ),
        (
            "old auth_time",
            |claims| claims.auth_time = Some(START + 20 - 121),
            Error::AuthTime,
        ),
    ];
    for (name, change, expected) in cases {
        let mut claims = claims(&login, 19);
        change(&mut claims);
        let exchange = world.callback_a(&login, 20).expect("a callback");
        assert_eq!(finish(exchange, &claims, 20), Err(expected), "{name}");
    }
    let mut claims = claims(&login, 19);
    claims.sub = None;
    let exchange = world.callback_a(&login, 20).expect("a callback");
    assert_eq!(finish(exchange, &claims, 20), Err(Error::Claims), "no sub");
    // Two audiences with the client as the authorized party pass.
    let mut claims = self::claims(&login, 19);
    claims.aud.push("client-b".into());
    claims.azp = Some("client-a".into());
    let exchange = world.callback_a(&login, 20).expect("a callback");
    finish(exchange, &claims, 20).unwrap();

    // A token of another key refuses at its signature.
    let body = response(&id_token(&other, &self::claims(&login, 19)));
    let exchange = world.callback_a(&login, 20).expect("a callback");
    let fetched = Fetched {
        status: 200,
        body: body.as_bytes(),
    };
    assert_eq!(
        exchange.finish(Ok(fetched), at(20)).err(),
        Some(Error::IdToken(jose::Error::Signature))
    );
}

/// The algorithm list comes from the trusted metadata of the issuer: an ID token of an algorithm outside it refuses,
/// also when the key set of the issuer holds its key.
#[test]
fn an_id_token_of_an_algorithm_outside_the_list_of_its_issuer_refuses() {
    let p256 = EcdsaP256SecretKey::from_bytes([3; 32]).expect("a P-256 scalar");
    let point = p256.public_key().to_sec1_bytes();
    let ec = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
        b64(&point[1..33]),
        b64(&point[33..])
    );
    let set = format!(r#"{{"keys":[{ec},{}]}}"#, provider(A).1);
    let only_es256 = Issuer::new(&config(A, &[Algorithm::Es256], &set), Limits::default()).expect("an issuer");
    let mut world = World::with(vec![only_es256]);
    let login = world.start(A, None, 10);
    let exchange = world.callback_a(&login, 20).expect("a callback");
    assert_eq!(
        finish(exchange, &claims(&login, 19), 20),
        Err(Error::IdToken(jose::Error::Algorithm))
    );
}

#[test]
fn an_expired_transaction_refuses() {
    let mut world = World::new();
    let login = world.start(A, None, 10);
    assert_eq!(
        world.callback_a(&login, 10 + LOGIN_LIFETIME.as_secs()).err(),
        Some(Error::Expired)
    );
}

/// A fetch gives a complete body or a typed failure. A failure gives no evidence, and a complete JSON prefix with more
/// bytes after it is no token response.
#[test]
fn a_failed_token_fetch_gives_no_evidence_even_after_a_complete_json_prefix() {
    let mut world = World::new();
    let login = world.start(A, None, 10);
    let exchange = world.callback_a(&login, 20).expect("a callback");
    assert_eq!(
        exchange.finish(Err(FetchError::Truncated), at(20)).err(),
        Some(Error::Fetch(FetchError::Truncated))
    );

    let body = response(&id_token(&provider(A).0, &claims(&login, 19)));
    for (status, body) in [(200, format!("{body}{{")), (400, body)] {
        let exchange = world.callback_a(&login, 20).expect("a callback");
        let fetched = Fetched {
            status,
            body: body.as_bytes(),
        };
        assert_eq!(
            exchange.finish(Ok(fetched), at(20)).err(),
            Some(Error::Token),
            "{status}"
        );
    }
}

/// The state of a response is the state of the binding of the browser that started the transaction, in the response
/// mode of its issuer, so a response in another browser or another mode refuses.
#[test]
fn a_callback_in_another_browser_or_mode_or_with_an_error_refuses() {
    let mut world = World::new();
    let login = world.start(A, None, 10);
    let other = world.start(A, None, 10);
    let query = format!("code=code-a&state={}&iss=https%3A%2F%2Fa.example", login.param("state"));
    for (callback, binding, expected) in [
        (Callback::Query(&query), &other.binding, Error::State),
        (Callback::Form(query.as_bytes()), &login.binding, Error::ResponseMode),
    ] {
        assert_eq!(world.callback(REDIRECT_A, callback, binding, 20).err(), Some(expected));
    }
    let denied = format!(
        "error=access_denied&state={}&iss=https%3A%2F%2Fa.example",
        login.param("state")
    );
    let twice = format!("{query}&code=code-b");
    for (query, expected) in [(denied, Error::Provider), (twice, Error::Malformed)] {
        assert_eq!(
            world
                .callback(REDIRECT_A, Callback::Query(&query), &login.binding, 20)
                .err(),
            Some(expected)
        );
    }
}

/// The PKCE verifier, the `state`, the `nonce`, the code, and the client secret never enter `Debug`.
#[test]
fn the_secrets_of_a_transaction_never_enter_debug() {
    let mut world = World::new();
    let login = world.start(A, None, 10);
    let (state, nonce) = (login.param("state"), login.param("nonce"));
    let binding = format!("{:?}", login.binding);
    let rp = format!("{:?}", world.rp);
    let exchange = world.callback_a(&login, 20).expect("a callback");
    let body = core::str::from_utf8(exchange.request().body())
        .expect("ASCII")
        .to_owned();
    let verifier = body.rsplit_once("code_verifier=").expect("a verifier").1.to_owned();
    let output = format!("{exchange:?} {rp} {binding} {:?}", exchange.request());
    for secret in [
        &state,
        &nonce,
        &verifier,
        &"code-a".to_owned(),
        &"secret".to_owned(),
        &b64(login.binding.as_bytes()),
    ] {
        assert!(!output.contains(secret.as_str()), "{secret}");
    }
}

/// Each issuer has its own redirect URI, so a response at a redirect URI names one issuer.
#[test]
fn a_relying_party_refuses_two_issuers_with_one_redirect_uri() {
    let set = format!(r#"{{"keys":[{}]}}"#, provider(B).1);
    let mut shared = config(B, &[Algorithm::Ed25519], &set);
    shared.redirect_uri = REDIRECT_A;
    let shared = Issuer::new(&shared, Limits::default()).expect("an issuer");
    let authority = Id::new("acme", "oidc").expect("an identifier");
    assert_eq!(
        RelyingParty::new(authority, vec![issuer(A), shared], Limits::default()).err(),
        Some(Error::Config)
    );
}
