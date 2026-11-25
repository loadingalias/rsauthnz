//! OpenID Connect sign-in: one sans-I/O relying-party engine for the authorization code flow
//! ([OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)), with PKCE S256, `state`,
//! `nonce`, and the mix-up defense of [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) and
//! [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700). A provider is configuration ([`Config`]), not code.
//!
//! The engine does no I/O. The host makes each fetch, with its own deadline, and gives back a complete payload or a
//! typed failure:
//!
//! 1. [`RelyingParty::start`] proposes a one-use login transaction. Its commit writes the transaction record, and
//!    [`Login::release`] then gives the [`Binding`] for a cookie of the browser and the address of the authorization
//!    request. Send the browser there.
//! 2. The provider sends the browser to the redirect URI of the issuer. [`RelyingParty::callback`] checks the response
//!    against the transaction of the cookie: the `state`, the redirect URI, the response mode, and the `iss` response
//!    parameter. It gives the [`TokenRequest`]. The host sends it to the token endpoint.
//! 3. [`Exchange::finish`] takes the completed token response, verifies the ID token with the keys and the algorithm
//!    list of the issuer, and gives the [`SignIn`]: the [`Federated`] evidence, and the consumption of the transaction,
//!    which the commit of the sign-in adds ([`SignIn::consume`]).
//!
//! The issuer of a callback comes only from its transaction, never from the response or the ID token. Each issuer has
//! its own redirect URI. Implicit and hybrid flows have no API. The transaction record holds no secret: `state`,
//! `nonce`, and the PKCE verifier each come from the 32 secret bytes of the binding, which only the browser holds, so a
//! callback in another browser refuses.
//!
//! ```
//! use rsauthnz::crypto::Algorithm;
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::Limits;
//! use rsauthnz::oidc::{ClientAuth, Config, Error, IssParameter, Issuer, RelyingParty, ResponseMode};
//!
//! // The JWK set of the provider: here the Ed25519 key of RFC 8037, appendix A.
//! let key_set = br#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;
//! let config = Config {
//!     issuer: "https://accounts.example",
//!     client_id: "app-client",
//!     client_auth: ClientAuth::Basic("the client secret"),
//!     authorization_endpoint: "https://accounts.example/authorize",
//!     token_endpoint: "https://accounts.example/token",
//!     redirect_uri: "https://app.example/oidc/accounts",
//!     response_mode: ResponseMode::Query,
//!     iss_parameter: IssParameter::Required,
//!     algorithms: &[Algorithm::Ed25519],
//!     key_set,
//! };
//! let issuer = Issuer::new(&config, Limits::default())?;
//! let rp = RelyingParty::new(Id::new("acme", "oidc")?, vec![issuer], Limits::default())?;
//!
//! // An algorithm with no key in the key set refuses the configuration.
//! let es256 = Config { algorithms: &[Algorithm::Es256], ..config };
//! assert!(matches!(Issuer::new(&es256, Limits::default()), Err(Error::Keys(_))));
//! # let _ = rp;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use rscodec::base64::Profile::{Standard, Url};
use rscodec::json::{self, Profile::IJson, Slot, Str};
use rscrypto::{ChaCha20Rng, SecretBytes, SecretVec};

use crate::cbor::{self, Value};
use crate::crypto::{self, Algorithm};
use crate::id::{Authority, AuthorityVersion, Id, Principal};
use crate::jose;
use crate::limits::Limits;
use crate::store::driver::Plan;
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{self, Audit, Change, Dependency, Key, OperationId, Proposal, Recover, Recovery};

/// The lifetime of a login transaction: 10 minutes from its start.
pub const LOGIN_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// The most time that the clock of a provider can differ from the reading, for `iat` and `auth_time`.
pub const CLOCK_SKEW_MAX: Duration = Duration::from_secs(60);

/// The most issuers of a relying party.
pub const ISSUERS_MAX: usize = 32;

/// The most algorithms in the list of an issuer.
pub const ALGORITHMS_MAX: usize = 4;

/// The most bytes of each address and each client value of the configuration.
pub const CONFIG_BYTES_MAX: usize = 2048;

/// The most bytes of the parameters of a callback.
pub const CALLBACK_BYTES_MAX: usize = 4096;

/// The most bytes of a token response. An ID token has at most [`jose::TOKEN_BYTES_MAX`] bytes.
pub const TOKEN_RESPONSE_BYTES_MAX: usize = TOKEN_RESPONSE.input_bytes_max as usize;

/// The most values of `amr`.
pub const AMR_MAX: usize = 8;

/// The most bytes of `sub` (OpenID Connect Core 1.0, section 2).
pub const SUBJECT_BYTES_MAX: usize = 255;

/// The first item of the CBOR form of a login transaction. The number changes with the form.
const LOGIN_FORM: &str = "rsauthnz.oidc.login.1";

/// The labels of the values that the secret of a binding gives.
const STATE: &[u8] = b"rsauthnz.oidc.state.1";
const NONCE: &[u8] = b"rsauthnz.oidc.nonce.1";
const VERIFIER: &[u8] = b"rsauthnz.oidc.pkce.1";

/// The action of the audit of a start.
const START: &str = "oidc.start";

/// The limits of a token response.
const TOKEN_RESPONSE: json::Limits = json::Limits {
    input_bytes_max: 32 * 1024,
    depth_max: 3,
    string_bytes_max: 16 * 1024,
    members_max: 32,
    elements_max: 16,
    number_digits_max: 20,
};

/// The limits of the claims of an ID token, as [`jose`] reads them.
const CLAIMS: json::Limits = json::Limits {
    input_bytes_max: 12 * 1024,
    depth_max: 8,
    string_bytes_max: 4096,
    members_max: 64,
    elements_max: 64,
    number_digits_max: 32,
};

/// The slots of the reader: each open container, and each key of each open object.
const SLOTS: usize = 8 * (64 + 1);

/// The response mode of an issuer: how the provider gives the authorization response to the redirect URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseMode {
    /// The query of a `GET` of the redirect URI.
    Query,
    /// The `application/x-www-form-urlencoded` body of a `POST` of the redirect URI
    /// ([OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)).
    FormPost,
}

/// Whether the metadata of an issuer advertises the `iss` response parameter
/// (`authorization_response_iss_parameter_supported`, RFC 9207).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IssParameter {
    /// The issuer advertises it: a response with no `iss` refuses.
    Required,
    /// The issuer does not advertise it. A response that has one still compares it.
    Optional,
}

/// The client authentication at the token endpoint, with the client secret (RFC 6749, section 2.3.1).
#[derive(Clone, Copy)]
pub enum ClientAuth<'a> {
    /// `client_secret_basic`: the HTTP Basic authentication of the client ID and the secret. The default of OpenID
    /// Connect.
    Basic(&'a str),
    /// `client_secret_post`: the client ID and the secret in the body of the token request.
    Post(&'a str),
}

// The secret never enters `Debug`.
impl fmt::Debug for ClientAuth<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Basic(_) => "Basic(..)",
            Self::Post(_) => "Post(..)",
        })
    }
}

/// The configuration of an issuer. Each value comes from the configuration of the host, never from a request.
#[derive(Clone, Copy, Debug)]
pub struct Config<'a> {
    /// The issuer identifier: `https://`, a host, and an optional path, with no query and no fragment.
    pub issuer: &'a str,
    /// The client ID that the provider registered.
    pub client_id: &'a str,
    /// The client authentication at the token endpoint.
    pub client_auth: ClientAuth<'a>,
    /// The authorization endpoint: `https://`, with an optional query and no fragment.
    pub authorization_endpoint: &'a str,
    /// The token endpoint: `https://`, with an optional query and no fragment.
    pub token_endpoint: &'a str,
    /// The redirect URI of this issuer alone: `https://`, with no fragment. No other issuer of the relying party has it.
    pub redirect_uri: &'a str,
    /// The response mode.
    pub response_mode: ResponseMode,
    /// Whether the issuer advertises the `iss` response parameter.
    pub iss_parameter: IssParameter,
    /// The algorithms of the ID tokens of the issuer, from its trusted metadata. An ID token of another algorithm
    /// refuses.
    pub algorithms: &'a [Algorithm],
    /// The JWK set of the issuer ([`jose::Profile::with_key_set`]).
    pub key_set: &'a [u8],
}

/// A checked issuer: its configuration, and one JOSE profile for each algorithm of its list.
pub struct Issuer {
    id: Box<str>,
    client_id: Box<str>,
    secret: SecretVec,
    post: bool,
    authorization: Box<str>,
    token: Box<str>,
    redirect: Box<str>,
    mode: ResponseMode,
    iss: IssParameter,
    profiles: Vec<jose::Profile>,
}

impl Issuer {
    /// Checks `config`, and reads the keys of its key set for each algorithm of its list. `limits` bound the signature
    /// checks of each ID token.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). A P-256 key checks its point, and an RSA key its modulus.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] if an address is not of its form, a client value is empty, longer than
    /// [`CONFIG_BYTES_MAX`], or has a byte that is not visible ASCII or a space, or the algorithm list is empty, longer than
    /// [`ALGORITHMS_MAX`], or names an algorithm twice. [`Error::Keys`] if the key set refuses, or gives no key for an
    /// algorithm of the list.
    pub fn new(config: &Config<'_>, limits: Limits) -> Result<Self, Error> {
        let id = address(config.issuer, Part::Issuer)?;
        // A client ID and a secret are VSCHAR (RFC 6749, appendix A): visible ASCII and the space.
        let visible = |text: &str| {
            (1..=CONFIG_BYTES_MAX).contains(&text.len()) && text.bytes().all(|byte| matches!(byte, b' '..=b'~'))
        };
        let (secret, post) = match config.client_auth {
            ClientAuth::Basic(secret) => (secret, false),
            ClientAuth::Post(secret) => (secret, true),
        };
        (visible(config.client_id) && visible(secret)).ok_or(Error::Config)?;
        let algorithms = config.algorithms;
        let distinct = algorithms
            .iter()
            .enumerate()
            .all(|(at, algorithm)| !algorithms[..at].contains(algorithm));
        ((1..=ALGORITHMS_MAX).contains(&algorithms.len()) && distinct).ok_or(Error::Config)?;
        let mut profiles = Vec::with_capacity(algorithms.len());
        for &algorithm in algorithms {
            let profile = jose::Profile::new(algorithm, jose::Kind::Jwt, &id, config.client_id, limits)
                .map_err(|_| Error::Config)?
                .with_key_set(config.key_set)
                .map_err(Error::Keys)?;
            profile.has_keys().ok_or(Error::Keys(jose::Error::Key))?;
            profiles.push(profile);
        }
        Ok(Self {
            id,
            client_id: config.client_id.into(),
            secret: SecretVec::from_vec(secret.as_bytes().to_vec()),
            post,
            authorization: address(config.authorization_endpoint, Part::Endpoint)?,
            token: address(config.token_endpoint, Part::Endpoint)?,
            redirect: address(config.redirect_uri, Part::Redirect)?,
            mode: config.response_mode,
            iss: config.iss_parameter,
            profiles,
        })
    }

    /// The issuer identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The redirect URI of the issuer.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect
    }
}

// The client secret never enters `Debug`.
impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issuer")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field("redirect", &self.redirect)
            .field("mode", &self.mode)
            .field("iss", &self.iss)
            .finish_non_exhaustive()
    }
}

/// The part of the configuration that an address is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Issuer,
    Endpoint,
    Redirect,
}

/// The address `text` of `part`: `https://`, a host with no user information, and an optional path, with at most
/// [`CONFIG_BYTES_MAX`] visible ASCII bytes and no fragment. An endpoint and a redirect URI can have a query.
fn address(text: &str, part: Part) -> Result<Box<str>, Error> {
    let rest = text.strip_prefix("https://").ok_or(Error::Config)?;
    let host = rest.split(['/', '?']).next().unwrap_or_default();
    let valid = text.len() <= CONFIG_BYTES_MAX
        && text.bytes().all(|byte| byte.is_ascii_graphic())
        && !host.is_empty()
        && !host.contains('@')
        && !text.contains('#')
        && (part != Part::Issuer || !text.contains('?'));
    valid.ok_or(Error::Config)?;
    Ok(text.into())
}

/// The relying party: its issuers, under one authority, which separates the transactions of two sites in one store.
#[derive(Debug)]
pub struct RelyingParty {
    authority: Id<Authority>,
    issuers: Vec<Issuer>,
    limits: Limits,
}

impl RelyingParty {
    /// The relying party of `issuers` under `authority`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Config`] if there are no issuers or more than [`ISSUERS_MAX`], or two issuers have one issuer
    /// identifier or one redirect URI: a response at a redirect URI then names one issuer.
    pub fn new(authority: Id<Authority>, issuers: Vec<Issuer>, limits: Limits) -> Result<Self, Error> {
        (1..=ISSUERS_MAX).contains(&issuers.len()).ok_or(Error::Config)?;
        let distinct = issuers.iter().enumerate().all(|(at, issuer)| {
            issuers[..at]
                .iter()
                .all(|other| other.id != issuer.id && other.redirect != issuer.redirect)
        });
        distinct.ok_or(Error::Config)?;
        Ok(Self {
            authority,
            issuers,
            limits,
        })
    }

    /// Proposes a login transaction with the issuer `issuer`, which asks for an authentication no older than `max_age`
    /// when it is set. The commit writes the transaction record, which ends after [`LOGIN_LIFETIME`], and its audit
    /// names `actor`: the signed-in human of a link, or the workload of the site for a sign-in with no session. Only
    /// after the commit is accepted does [`Login::release`] give the binding and the address of the authorization
    /// request.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse), and its commit. Limit the rate of starts of one client.
    ///
    /// # Errors
    ///
    /// [`Error::Issuer`] if the relying party has no issuer `issuer`. [`Error::Time`] if `now` has no bound or a time
    /// overflows, and [`Error::Transition`] for the proposal.
    pub fn start(
        &self,
        issuer: &str,
        actor: Principal,
        max_age: Option<Duration>,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan, Login), Error> {
        let issuer = self
            .issuers
            .iter()
            .find(|known| *known.id == *issuer)
            .ok_or(Error::Issuer)?;
        now.latest().map_err(Error::Time)?;
        let end = now
            .estimate()
            .checked_add(LOGIN_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let mut secret = [0; 32];
        random.fill_bytes(&mut secret);
        let binding = Binding::from_bytes(secret);
        let state = binding.value(STATE);
        let key = self.login_key(&state);
        let audit = Audit {
            actor,
            action: Id::new("rsauthnz", START).expect("the action is a valid identifier"),
            time: now,
        };
        let request = Value::Array(vec![self.authority.to_cbor(), Value::Bytes(key.as_bytes())]);
        let operation = OperationId::random(random);
        let mut proposal = Proposal::new(operation.clone(), audit, &request, self.limits).map_err(Error::Transition)?;
        proposal
            .read(Dependency::Absent(key.clone()))
            .map_err(Error::Transition)?;
        let data = cbor::encode(
            &Value::Array(vec![
                Value::Text(LOGIN_FORM),
                Value::Text(&issuer.id),
                max_age.map_or(Value::Null, |max_age| Value::Unsigned(max_age.as_secs())),
                Value::Unsigned(now.earliest().map_err(Error::Time)?.as_secs()),
            ]),
            Limits::FORM,
        )
        .expect("the form has no map and no simple value");
        let version = AuthorityVersion::new(self.authority.clone(), &crypto::sha256(key.as_bytes()))
            .expect("a coordinate of 32 bytes is valid");
        proposal
            .change(Change::Write {
                key,
                version,
                end: Some(end),
                data: data.into_boxed_slice(),
            })
            .map_err(Error::Transition)?;
        let url = issuer.authorization_url(&binding, max_age);
        Ok((
            proposal,
            Plan::default(),
            Login {
                operation,
                binding,
                url,
            },
        ))
    }

    /// Checks the authorization response `callback`, which the browser of `binding` brought to the redirect URI
    /// `redirect_uri` of the route, and gives the token request. In order: the `state` of the response is the state of
    /// `binding`, the transaction of the state is open, `redirect_uri` and the response mode are the ones of the issuer of
    /// the transaction, the `iss` parameter names that issuer, and the response holds no `error` and one `code`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One HMAC-SHA256 tag and one keyed lookup.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] if the parameters are not form encoding within [`CALLBACK_BYTES_MAX`], repeat a
    ///   parameter, or have no `code`.
    /// - [`Error::State`] if the `state` is missing or is not the state of `binding`: the response is not for this
    ///   browser.
    /// - [`Error::Transaction`] if no transaction has the state: it is unknown, or a sign-in consumed it.
    ///   [`Error::Expired`] after its end.
    /// - [`Error::RedirectUri`], [`Error::ResponseMode`], and [`Error::Mixup`] if the response came to the redirect URI
    ///   of another issuer, in another response mode, or with no `iss` or the `iss` of another issuer.
    /// - [`Error::Provider`] if the response is an error of the provider, such as `access_denied`.
    /// - [`Error::Record`] if the record has no valid form or names an issuer that the relying party has no longer,
    ///   [`Error::Time`] if `now` has no bound, and [`Failure::Store`] if the read fails.
    pub async fn callback<S: Store>(
        &self,
        store: &mut S,
        redirect_uri: &str,
        callback: Callback<'_>,
        binding: &Binding,
        now: Reading,
    ) -> Result<Exchange<'_>, Failure<S::Error>> {
        let (params, mode) = match callback {
            Callback::Query(query) => (query.as_bytes(), ResponseMode::Query),
            Callback::Form(body) => (body, ResponseMode::FormPost),
        };
        let [code, state, iss, error] = parameters(params, ["code", "state", "iss", "error"])?;
        let state = state.ok_or(Error::State)?;
        let expected = binding.value(STATE);
        (state.as_bytes() == expected.as_slice()).ok_or(Error::State)?;
        let latest = now.latest().map_err(Error::Time)?;
        let key = self.login_key(&expected);
        let record = store
            .read(&key)
            .await
            .map_err(Failure::Store)?
            .ok_or(Error::Transaction)?;
        let end = record.end.ok_or(Error::Record)?;
        (latest < end).ok_or(Error::Expired)?;
        let (issuer, max_age, created) = self.parse(&record).ok_or(Error::Record)?;
        (*issuer.redirect == *redirect_uri).ok_or(Error::RedirectUri)?;
        (issuer.mode == mode).ok_or(Error::ResponseMode)?;
        match iss {
            Some(iss) => (*iss == *issuer.id).ok_or(Error::Mixup)?,
            None => (issuer.iss == IssParameter::Optional).ok_or(Error::Mixup)?,
        }
        error.is_none().ok_or(Error::Provider)?;
        let code = code.ok_or(Error::Malformed)?;
        let request = issuer.token_request(&code, binding);
        Ok(Exchange {
            issuer,
            request,
            nonce: binding.value(NONCE),
            max_age,
            created,
            key,
            version: record.version,
            end,
        })
    }

    /// The issuer, the maximum age, and the start in whole seconds of the transaction record `record`.
    fn parse(&self, record: &Record) -> Option<(&Issuer, Option<Duration>, u64)> {
        let value = cbor::decode(&record.data, self.limits).ok()?;
        let Value::Array(items) = &value else {
            return None;
        };
        let [
            Value::Text(LOGIN_FORM),
            Value::Text(issuer),
            max_age,
            Value::Unsigned(created),
        ] = items.as_slice()
        else {
            return None;
        };
        let max_age = match max_age {
            Value::Null => None,
            Value::Unsigned(seconds) => Some(Duration::from_secs(*seconds)),
            _ => return None,
        };
        let issuer = self.issuers.iter().find(|known| *known.id == **issuer)?;
        Some((issuer, max_age, *created))
    }

    /// The key of the transaction of `state`: [`Kind::Login`] with the SHA-256 digest of the canonical CBOR form
    /// `["rsauthnz.oidc.login.1", authority, state]`.
    fn login_key(&self, state: &[u8; 43]) -> Key {
        let form = Value::Array(vec![
            Value::Text(LOGIN_FORM),
            self.authority.to_cbor(),
            Value::Bytes(state),
        ]);
        let form = cbor::encode(&form, Limits::FORM).expect("the form has no map and no simple value");
        Kind::Login
            .key(&crypto::sha256(&form))
            .expect("a key of 33 bytes is valid")
    }
}

impl Issuer {
    /// The address of the authorization request of `binding`.
    fn authorization_url(&self, binding: &Binding, max_age: Option<Duration>) -> String {
        let challenge = base64url(&crypto::sha256(&binding.value(VERIFIER)));
        let mut url = String::from(&*self.authorization);
        url.push(if url.contains('?') { '&' } else { '?' });
        let mut form = Form(url);
        form.pair("response_type", "code");
        form.pair("client_id", &self.client_id);
        form.pair("redirect_uri", &self.redirect);
        form.pair("scope", "openid");
        form.pair("state", ascii(&binding.value(STATE)));
        form.pair("nonce", ascii(&binding.value(NONCE)));
        form.pair("code_challenge", ascii(&challenge));
        form.pair("code_challenge_method", "S256");
        if self.mode == ResponseMode::FormPost {
            form.pair("response_mode", "form_post");
        }
        if let Some(max_age) = max_age {
            form.pair("max_age", &max_age.as_secs().to_string());
        }
        form.0
    }

    /// The token request of the authorization code `code`, with the PKCE verifier of `binding`.
    fn token_request(&self, code: &str, binding: &Binding) -> TokenRequest {
        let mut form = Form(String::new());
        form.pair("grant_type", "authorization_code");
        form.pair("code", code);
        form.pair("redirect_uri", &self.redirect);
        form.pair("code_verifier", ascii(&binding.value(VERIFIER)));
        let secret = core::str::from_utf8(self.secret.as_bytes()).expect("the secret is ASCII");
        let authorization = if self.post {
            form.pair("client_id", &self.client_id);
            form.pair("client_secret", secret);
            None
        } else {
            // RFC 6749, section 2.3.1: the form encoding of each value, then base64 of `id:secret`.
            let mut pair = Form(String::new());
            pair.value(&self.client_id);
            pair.0.push(':');
            pair.value(secret);
            let credentials = pair.0.into_bytes();
            let mut out = vec![
                0;
                Standard
                    .encoded_len(credentials.len())
                    .expect("a bounded length encodes")
            ];
            let len = Standard
                .encode(&credentials, &mut out)
                .expect("the buffer has the encoded length")
                .len();
            out.truncate(len);
            Some(SecretVec::from_vec([b"Basic ".as_slice(), &out].concat()))
        };
        TokenRequest {
            url: self.token.clone(),
            authorization,
            body: SecretVec::from_vec(form.0.into_bytes()),
        }
    }
}

/// The secret of a login transaction: 32 random bytes in a cookie of the browser. `state`, `nonce`, and the PKCE
/// verifier each are an HMAC-SHA256 tag of it, so the store keeps no secret, and only the browser that started the
/// transaction can finish it. `Debug` does not show it, and its memory is cleared when it drops.
pub struct Binding(SecretBytes<32>);

impl Binding {
    /// The binding of `bytes`, such as the value of the cookie.
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

    /// The bytes of the binding, for the cookie.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// The base64url of the HMAC-SHA256 tag of `label` under the secret.
    fn value(&self, label: &[u8]) -> [u8; 43] {
        let tag = crypto::hmac_sha256(self.0.as_bytes(), label);
        let mut out = [0; 43];
        Url.encode(&tag, &mut out)
            .expect("32 bytes have 43 base64url characters");
        out
    }
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Binding(..)")
    }
}

/// A started login transaction: its binding and the address of its authorization request. The address holds the
/// `state`, so `Debug` shows neither.
pub struct Login {
    operation: OperationId,
    binding: Binding,
    url: String,
}

impl Login {
    /// The binding and the address of the authorization request, if `outcome` is the accepted commit of the start.
    /// Set the binding in a cookie of the browser, then send the browser to the address. A conflict, a refusal, and an
    /// unknown outcome release nothing: start again.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn release(self, outcome: &transition::Outcome) -> Option<(Binding, String)> {
        match outcome {
            transition::Outcome::Accepted(receipt) if *receipt.operation() == self.operation => {
                Some((self.binding, self.url))
            }
            _ => None,
        }
    }
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Login(..)")
    }
}

/// The authorization response at the redirect URI, in the response mode that it came in.
#[derive(Clone, Copy, Debug)]
pub enum Callback<'a> {
    /// The query of a `GET`, with no `?`.
    Query(&'a str),
    /// The `application/x-www-form-urlencoded` body of a `POST`.
    Form(&'a [u8]),
}

/// The token request of a callback ([RFC 6749, section 4.1.3](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3)).
/// Send it as a `POST` to its address, with `Content-Type: application/x-www-form-urlencoded`, `Accept:
/// application/json`, and its `Authorization` field when it has one. Its body and its field hold secrets: the code, the
/// PKCE verifier, and the client secret. So `Debug` shows only the address. Never log them.
pub struct TokenRequest {
    url: Box<str>,
    authorization: Option<SecretVec>,
    body: SecretVec,
}

impl TokenRequest {
    /// The token endpoint of the issuer.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The value of the `Authorization` field, for `client_secret_basic`.
    #[must_use]
    pub fn authorization(&self) -> Option<&[u8]> {
        self.authorization.as_ref().map(SecretVec::as_bytes)
    }

    /// The form body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_bytes()
    }
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// A completed fetch: the status and the complete body. The host gives it only after the end of the body and each
/// framing and checksum check, within the deadline of the fetch, and after it decoded each content coding within its
/// bounds.
#[derive(Clone, Copy, Debug)]
pub struct Fetched<'a> {
    /// The HTTP status.
    pub status: u16,
    /// The complete body, with its content coding removed.
    pub body: &'a [u8],
}

/// The typed failure of a fetch of the host. A fetch that failed gives no payload, also when a part of the body
/// arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FetchError {
    /// The deadline of the fetch passed, also during the body or its decoding.
    Deadline,
    /// The body ended before its end, or a framing or checksum check failed.
    Truncated,
    /// The body, or its decoded form, is longer than the bound of the host.
    TooLarge,
    /// The connection or the TLS session failed.
    Transport,
}

/// A callback that passed its checks: the token request, and the transaction that the ID token must fit.
pub struct Exchange<'a> {
    issuer: &'a Issuer,
    request: TokenRequest,
    nonce: [u8; 43],
    max_age: Option<Duration>,
    /// The start of the transaction, in whole seconds.
    created: u64,
    key: Key,
    version: AuthorityVersion,
    end: Duration,
}

impl Exchange<'_> {
    /// The token request. The host sends it, and gives the result to [`Self::finish`].
    #[must_use]
    pub const fn request(&self) -> &TokenRequest {
        &self.request
    }

    /// Verifies the token response `fetched` at `now`, and gives the sign-in. The response is `200` with a JSON
    /// object that has an `id_token` and a `token_type` of `Bearer`. The ID token is verified with the keys of the
    /// issuer, under its algorithm list, before any claim is used: `iss`, `aud` (with `azp` for more than one
    /// audience), `exp`, `nbf`, `iat` within [`CLOCK_SKEW_MAX`] of the transaction and of `now`, the `nonce` of the
    /// transaction, `sub`, and `auth_time` against the maximum age of the start. The engine keeps no provider token.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One signature check, after the checks of the header.
    ///
    /// # Errors
    ///
    /// - [`Error::Fetch`] if the fetch failed: no part of its body is read.
    /// - [`Error::Token`] if the status is not `200`, or the body is not a token response within
    ///   [`TOKEN_RESPONSE_BYTES_MAX`].
    /// - [`Error::IdToken`] if the ID token refuses: another algorithm than the list of the issuer, another key, a
    ///   signature that does not verify, another issuer or audience, or a token that expired.
    /// - [`Error::AuthorizedParty`], [`Error::Nonce`], [`Error::IssuedAt`], [`Error::AuthTime`], and [`Error::Claims`]
    ///   for the claims of the ID token. [`Error::Time`] if `now` has no bound.
    pub fn finish(self, fetched: Result<Fetched<'_>, FetchError>, now: Reading) -> Result<SignIn, Error> {
        let fetched = fetched.map_err(Error::Fetch)?;
        (fetched.status == 200).ok_or(Error::Token)?;
        let token = id_token(fetched.body)?;
        let jwt = self.verify(&token, now)?;
        let claims = jwt.claims();
        let extra = Extra::parse(jwt.jws().payload())?;
        let client_id = &*self.issuer.client_id;
        match extra.azp.as_deref() {
            Some(azp) => (azp == client_id).ok_or(Error::AuthorizedParty)?,
            None => (claims.aud.len() == 1).ok_or(Error::AuthorizedParty)?,
        }
        (extra.nonce.as_deref().map(str::as_bytes) == Some(self.nonce.as_slice())).ok_or(Error::Nonce)?;
        let iat = Duration::from_secs(claims.iat.ok_or(Error::Claims)?);
        let latest = now.latest().map_err(Error::Time)?;
        let created = Duration::from_secs(self.created);
        let skewed = |time: Duration| time.checked_add(CLOCK_SKEW_MAX).ok_or(Error::Time(TimeError::Overflow));
        (skewed(iat)? >= created && iat <= skewed(latest)?).ok_or(Error::IssuedAt)?;
        let subject = claims.sub.clone().ok_or(Error::Claims)?;
        (!subject.is_empty() && subject.len() <= SUBJECT_BYTES_MAX && subject.is_ascii()).ok_or(Error::Claims)?;
        let auth_time = extra.auth_time.map(Duration::from_secs);
        if let Some(max_age) = self.max_age {
            let auth_time = auth_time.ok_or(Error::AuthTime)?;
            let fresh = auth_time
                .checked_add(max_age)
                .and_then(|end| end.checked_add(CLOCK_SKEW_MAX))
                .is_some_and(|end| latest <= end);
            fresh.ok_or(Error::AuthTime)?;
        }
        Ok(SignIn {
            evidence: Federated {
                issuer: self.issuer.id.clone(),
                subject,
                auth_time,
                acr: extra.acr,
                amr: extra.amr,
                time: now,
            },
            key: self.key,
            version: self.version,
            end: self.end,
        })
    }

    /// The ID token `token` under the profile of its algorithm, or the refusal of the first profile that took its
    /// algorithm. Each other profile refuses before signature work.
    fn verify(&self, token: &str, now: Reading) -> Result<jose::Jwt, Error> {
        let mut refusal = jose::Error::Algorithm;
        for profile in &self.issuer.profiles {
            match profile.verify_jwt(token, now) {
                Ok(jwt) => return Ok(jwt),
                Err(jose::Error::Algorithm) => {}
                Err(error) => {
                    refusal = error;
                    break;
                }
            }
        }
        Err(Error::IdToken(refusal))
    }
}

impl fmt::Debug for Exchange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("issuer", &self.issuer.id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// The claims of an ID token that [`jose::Claims`] does not read.
#[derive(Default)]
struct Extra {
    nonce: Option<String>,
    azp: Option<String>,
    auth_time: Option<u64>,
    acr: Option<Box<str>>,
    amr: Vec<Box<str>>,
}

impl Extra {
    /// Reads the claims of the verified payload `payload`.
    fn parse(payload: &[u8]) -> Result<Self, Error> {
        let mut scratch = [Slot::EMPTY; SLOTS];
        json::read(payload, &CLAIMS, IJson, &mut scratch, |reader| {
            let mut extra = Self::default();
            let mut members = reader.value().members()?;
            while let Some((name, mut value)) = members.next()? {
                if name == "nonce" {
                    extra.nonce = Some(text(value.str()?)?);
                } else if name == "azp" {
                    extra.azp = Some(text(value.str()?)?);
                } else if name == "acr" {
                    extra.acr = Some(text(value.str()?)?.into());
                } else if name == "auth_time" {
                    extra.auth_time = Some(value.number()?.to_u64()?);
                } else if name == "amr" && value.kind()? == json::Kind::Array {
                    let mut items = value.elements()?;
                    while let Some(item) = items.next()? {
                        extra.amr.push(text(item.str()?)?.into());
                    }
                }
            }
            Ok(extra)
        })
        .map_err(|_| Error::Claims)
        .and_then(|extra| (extra.amr.len() <= AMR_MAX).then_some(extra).ok_or(Error::Claims))
    }
}

/// The ID token of the token response `body`, whose `token_type` is `Bearer`.
fn id_token(body: &[u8]) -> Result<String, Error> {
    let mut scratch = [Slot::EMPTY; SLOTS];
    let (token, kind) = json::read(body, &TOKEN_RESPONSE, IJson, &mut scratch, |reader| {
        let (mut token, mut kind) = (None, None);
        let mut members = reader.value().members()?;
        while let Some((name, value)) = members.next()? {
            if name == "id_token" {
                token = Some(text(value.str()?)?);
            } else if name == "token_type" {
                kind = Some(text(value.str()?)?);
            }
        }
        Ok((token, kind))
    })
    .map_err(|_| Error::Token)?;
    kind.is_some_and(|kind| kind.eq_ignore_ascii_case("bearer"))
        .ok_or(Error::Token)?;
    token.ok_or(Error::Token)
}

/// The text of a JSON string, with its escapes read.
fn text(value: Str<'_>) -> Result<String, json::Error> {
    let mut out = vec![0; value.len()];
    Ok(value.decode(&mut out)?.into())
}

/// A verified sign-in: the federated evidence, and the transaction that its commit consumes.
#[derive(Debug)]
pub struct SignIn {
    evidence: Federated,
    key: Key,
    version: AuthorityVersion,
    end: Duration,
}

impl SignIn {
    /// The federated evidence.
    #[must_use]
    pub const fn evidence(&self) -> &Federated {
        &self.evidence
    }

    /// Adds the consumption of the transaction to `proposal`, the commit of the sign-in: the read of the transaction
    /// record at the version of the callback, its end, and the end of the transaction as a deadline. So a second
    /// commit with the same transaction conflicts, and a callback after the commit refuses with
    /// [`Error::Transaction`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`transition::Error`] if the proposal reaches its limits or already changes the record.
    pub fn consume(&self, proposal: &mut Proposal) -> Result<(), transition::Error> {
        proposal.read(Dependency::Version(self.key.clone(), self.version.clone()))?;
        proposal.change(Change::End(self.key.clone()))?;
        proposal.until(self.end);
        Ok(())
    }
}

/// The evidence of a verified ID token: the statements of the provider, and nothing that the engine derived from them.
/// The `acr` and the `amr` are statements of the provider: no strength and no phishing resistance comes from them. A
/// provider identity is the pair of the issuer and the subject. An email address, a name, or a group never names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Federated {
    /// The issuer identifier, from the configuration of the transaction.
    pub issuer: Box<str>,
    /// The subject (`sub`) of the issuer.
    pub subject: Box<str>,
    /// The time of the authentication (`auth_time`), as the time since the Unix epoch.
    pub auth_time: Option<Duration>,
    /// The authentication context class (`acr`).
    pub acr: Option<Box<str>>,
    /// The authentication methods (`amr`).
    pub amr: Vec<Box<str>>,
    /// The reading of the verification.
    pub time: Reading,
}

/// A form encoding (`application/x-www-form-urlencoded`) under construction.
struct Form(String);

impl Form {
    /// Adds `name=value`, after a `&` when the form has a pair.
    fn pair(&mut self, name: &str, value: &str) {
        if !self.0.is_empty() && !self.0.ends_with(['?', '&']) {
            self.0.push('&');
        }
        self.value(name);
        self.0.push('=');
        self.value(value);
    }

    /// Adds the form encoding of `value`: a space as `+`, and each byte other than a letter, a digit, `*`, `-`, `.`,
    /// and `_` as `%XX` (the `application/x-www-form-urlencoded` serializer of the WHATWG URL Standard).
    fn value(&mut self, value: &str) {
        for byte in value.bytes() {
            if byte == b' ' {
                self.0.push('+');
            } else if byte.is_ascii_alphanumeric() || b"*-._".contains(&byte) {
                self.0.push(char::from(byte));
            } else {
                let digit = |nibble: u8| char::from(b"0123456789ABCDEF"[usize::from(nibble)]);
                self.0.extend(['%', digit(byte >> 4), digit(byte & 0xf)]);
            }
        }
    }
}

/// The values of the parameters `names` of the form encoding `params`, in order. Each other parameter is ignored. A
/// parameter of `names` that is there twice refuses (RFC 6749, section 3.1).
fn parameters<const N: usize>(params: &[u8], names: [&str; N]) -> Result<[Option<String>; N], Error> {
    (params.len() <= CALLBACK_BYTES_MAX).ok_or(Error::Malformed)?;
    let mut found = [const { None }; N];
    for pair in params.split(|&byte| byte == b'&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once(|&byte| byte == b'=').unwrap_or((pair, b""));
        let name = decode(name)?;
        if let Some(at) = names.iter().position(|known| *known == name) {
            found[at].is_none().ok_or(Error::Malformed)?;
            found[at] = Some(decode(value)?);
        }
    }
    Ok(found)
}

/// The text of the form-encoded value `value`: `+` is a space, and `%XX` is the byte `XX`. The text is UTF-8.
fn decode(value: &[u8]) -> Result<String, Error> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.iter();
    while let Some(&byte) = bytes.next() {
        out.push(match byte {
            b'+' => b' ',
            b'%' => {
                let mut digit = || {
                    bytes
                        .next()
                        .and_then(|digit| char::from(*digit).to_digit(16))
                        .ok_or(Error::Malformed)
                };
                let (high, low) = (digit()?, digit()?);
                u8::try_from(high * 16 + low).map_err(|_| Error::Malformed)?
            }
            byte => byte,
        });
    }
    String::from_utf8(out).map_err(|_| Error::Malformed)
}

/// The base64url text of 32 bytes.
fn base64url(bytes: &[u8; 32]) -> [u8; 43] {
    let mut out = [0; 43];
    Url.encode(bytes, &mut out)
        .expect("32 bytes have 43 base64url characters");
    out
}

/// The text of base64url bytes.
fn ascii(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).expect("base64url is ASCII")
}

/// The cause of a refused operation of the relying party. No error holds a secret, a code, or a byte of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A value of the configuration is not of its form. Correct the configuration.
    Config,
    /// The key set of an issuer refuses, or gives no key for an algorithm of its list. The error gives the cause.
    Keys(jose::Error),
    /// The relying party has no such issuer.
    Issuer,
    /// The parameters of the callback are not form encoding within their bound, repeat a parameter, or have no code.
    Malformed,
    /// The `state` of the callback is missing, or is not the state of the binding of the browser.
    State,
    /// No open transaction has the state: it is unknown, or a sign-in consumed it. Start again.
    Transaction,
    /// The end of the transaction passed. Start again.
    Expired,
    /// The callback came to the redirect URI of another issuer.
    RedirectUri,
    /// The callback came in another response mode than the mode of its issuer.
    ResponseMode,
    /// The `iss` of the callback is missing while the issuer advertises it, or names another issuer: a mix-up.
    Mixup,
    /// The provider answered with an error, such as `access_denied`. Start again if the human asks.
    Provider,
    /// The fetch of the token response failed. No part of its body counts.
    Fetch(FetchError),
    /// The token response is not `200`, or is not a JSON object with an `id_token` and a `token_type` of `Bearer`.
    Token,
    /// The ID token refuses. The error gives the cause.
    IdToken(jose::Error),
    /// The ID token has more than one audience and no `azp`, or an `azp` that is not the client ID.
    AuthorizedParty,
    /// The `nonce` of the ID token is missing, or is not the nonce of the transaction.
    Nonce,
    /// The `iat` of the ID token is more than [`CLOCK_SKEW_MAX`] before the start of the transaction or after the
    /// reading.
    IssuedAt,
    /// The start asked for a maximum age, and the `auth_time` of the ID token is missing or older.
    AuthTime,
    /// A claim of the ID token is missing, has another type, or passes its bound.
    Claims,
    /// A transaction record has no valid form, or names an issuer that the relying party no longer has.
    Record,
    /// The reading of the time has no bound, or a time overflows. Use a reading with a bound.
    Time(TimeError),
    /// The proposal refuses. The error gives the recovery.
    Transition(transition::Error),
}

impl Recover for Error {
    /// Start again for each refusal of a transaction or a response: nothing committed. Refuse an error of the
    /// configuration.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Config | Self::Keys(_) | Self::Issuer | Self::Record | Self::Time(_) => Recovery::Refuse,
            Self::Transition(error) => error.recovery(),
            Self::Malformed
            | Self::State
            | Self::Transaction
            | Self::Expired
            | Self::RedirectUri
            | Self::ResponseMode
            | Self::Mixup
            | Self::Provider
            | Self::Fetch(_)
            | Self::Token
            | Self::IdToken(_)
            | Self::AuthorizedParty
            | Self::Nonce
            | Self::IssuedAt
            | Self::AuthTime
            | Self::Claims => Recovery::Restart,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config => f.write_str("a value of the configuration of the issuer is not valid"),
            Self::Keys(error) => write!(f, "the key set of the issuer refused: {error}"),
            Self::Issuer => f.write_str("the relying party has no such issuer"),
            Self::Malformed => f.write_str("the parameters of the callback are not valid"),
            Self::State => f.write_str("the state of the callback is not the state of this browser"),
            Self::Transaction => f.write_str("no open login transaction has the state"),
            Self::Expired => f.write_str("the login transaction expired"),
            Self::RedirectUri => f.write_str("the callback came to the redirect URI of another issuer"),
            Self::ResponseMode => f.write_str("the callback came in another response mode"),
            Self::Mixup => f.write_str("the iss of the callback does not name the issuer of the transaction"),
            Self::Provider => f.write_str("the provider answered with an error"),
            Self::Fetch(error) => write!(f, "the fetch of the token response failed: {error:?}"),
            Self::Token => f.write_str("the token response is not valid"),
            Self::IdToken(error) => write!(f, "the ID token refused: {error}"),
            Self::AuthorizedParty => f.write_str("the authorized party of the ID token is not the client"),
            Self::Nonce => f.write_str("the nonce of the ID token is not the nonce of the transaction"),
            Self::IssuedAt => f.write_str("the ID token was issued outside the transaction"),
            Self::AuthTime => f.write_str("the authentication is older than the maximum age"),
            Self::Claims => f.write_str("a claim of the ID token is missing or not valid"),
            Self::Record => f.write_str("a login transaction record is not valid"),
            Self::Time(error) => write!(f, "the time refused: {error}"),
            Self::Transition(error) => write!(f, "the proposal refused: {error}"),
        }
    }
}

impl core::error::Error for Error {}

/// The failure of an operation that reads the store: a refusal, or a failed read.
pub type Failure<E> = crate::store::Failure<Error, E>;
