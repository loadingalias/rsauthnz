# Sign in with an identity provider

A human signs in through an external OpenID Connect provider. The relying party of module `rsauthnz::oidc` verifies
the answer of the provider and gives federated evidence: the issuer, the subject, and the statements of the provider
about the authentication. The engine does no I/O: your host sends each request, with its own deadline, and gives back
the complete result or a typed failure.

The engine verifies the provider. The commit that opens a session or links an account takes the evidence.

## The flow

The flow is the authorization code flow of [OpenID Connect Core
1.0](https://openid.net/specs/openid-connect-core-1_0.html), with PKCE S256, `state`, and `nonce`. Implicit and
hybrid flows have no API.

1. **Start.** The commit writes a one-use login transaction. The browser gets a cookie with the 32-byte secret of the
   transaction, and goes to the authorization endpoint of the provider.
2. **Callback.** The provider sends the browser back to the redirect URI of the issuer. The engine checks the response
   against the transaction of the cookie, and gives the token request.
3. **Token request.** Your host sends the token request to the token endpoint, and gives the response to the engine.
4. **Finish.** The engine verifies the ID token with the keys and the algorithm list of the issuer, and gives the
   evidence. The commit of the sign-in consumes the transaction.

The issuer of a callback comes only from its transaction, never from the response or the ID token. Each issuer has its
own redirect URI, and the `iss` response parameter ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)) must name the
issuer of the transaction. These two checks stop a mix-up: a response of one provider that comes to the transaction of
another provider refuses before its code goes to a token endpoint.

The transaction record holds no secret. `state`, `nonce`, and the PKCE verifier each are an HMAC-SHA256 tag of the
secret in the cookie. So a response in another browser refuses, which stops a login cross-site request forgery.

## Before you start

- A commit driver on a storage binding ([Storage contract](storage.md)).
- For each provider: its issuer identifier, a client ID and a client secret that the provider registered, its
  authorization and token endpoints, the algorithms of its ID tokens, and its JWK set. Each value comes from your
  configuration, never from a request.
- A redirect URI for each issuer, which no other issuer of the relying party has.

## Configure the issuers

Make each issuer from a `Config`, then make the relying party. This example is also the example of the
`rsauthnz::oidc` module documentation, and `cargo xtask test` runs it:

```rust
use rsauthnz::crypto::Algorithm;
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::oidc::{ClientAuth, Config, Error, IssParameter, Issuer, RelyingParty, ResponseMode};

// The JWK set of the provider: here the Ed25519 key of RFC 8037, appendix A.
let key_set = br#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;
let config = Config {
    issuer: "https://accounts.example",
    client_id: "app-client",
    client_auth: ClientAuth::Basic("the client secret"),
    authorization_endpoint: "https://accounts.example/authorize",
    token_endpoint: "https://accounts.example/token",
    redirect_uri: "https://app.example/oidc/accounts",
    response_mode: ResponseMode::Query,
    iss_parameter: IssParameter::Required,
    algorithms: &[Algorithm::Ed25519],
    key_set,
};
let issuer = Issuer::new(&config, Limits::default())?;
let rp = RelyingParty::new(Id::new("acme", "oidc")?, vec![issuer], Limits::default())?;

// An algorithm with no key in the key set refuses the configuration.
let es256 = Config { algorithms: &[Algorithm::Es256], ..config };
assert!(matches!(Issuer::new(&es256, Limits::default()), Err(Error::Keys(_))));
```

| Field | Value |
| --- | --- |
| `issuer` | `https://`, a host, and an optional path, with no query and no fragment |
| `client_id` | The client ID: 1 to 2,048 bytes of visible ASCII or the space |
| `client_auth` | `ClientAuth::Basic(secret)` for `client_secret_basic`, the default of OpenID Connect, or `ClientAuth::Post(secret)` for `client_secret_post` |
| `authorization_endpoint`, `token_endpoint` | `https://`, with an optional query and no fragment |
| `redirect_uri` | `https://`, with no fragment. Each issuer has its own |
| `response_mode` | `ResponseMode::Query`, or `ResponseMode::FormPost` for a `POST` of the response |
| `iss_parameter` | `IssParameter::Required` if the metadata of the provider has `authorization_response_iss_parameter_supported`, else `IssParameter::Optional`. A response that has `iss` is compared in both cases |
| `algorithms` | The algorithms of the ID tokens, from the trusted metadata of the provider: 1 to `ALGORITHMS_MAX` (4). An ID token of another algorithm refuses, also when the key set holds its key |
| `key_set` | The JWK set of the provider ([Verify and sign JOSE tokens](jose.md)). It must give a key for each algorithm of the list |

`RelyingParty::new` refuses two issuers with one issuer identifier or one redirect URI. A relying party has at most
`ISSUERS_MAX` (32) issuers.

## Start a sign-in

1. Call `rp.start(issuer, actor, max_age, now, random)`. `actor` is the principal that the audit of the start names:
   the signed-in human of a link, or the workload of your site for a sign-in with no session. `max_age` asks for an
   authentication no older than it, or `None`.
2. Commit the proposal with its plan. Call `login.release(&outcome)`. For the accepted commit it gives the `Binding` and
   the address of the authorization request. Another outcome releases nothing: start again.
3. Set the 32 bytes of `binding.as_bytes()` in a `__Host-` cookie of the browser, for example in base64url with
   `site.set_cookie` ([Cookies](http-binding.md#cookies)). Send the browser to the address with a `303 See Other`.

The transaction ends after `LOGIN_LIFETIME` (10 minutes). The address asks for the scope `openid`, the code challenge
`S256`, and the `response_mode` and the `max_age` that you chose.

## Handle the callback

At the redirect URI of each issuer, read the binding from the cookie with `Binding::from_bytes(bytes)`, and call
`rp.callback(store, redirect_uri, callback, &binding, now)`:

- `redirect_uri` is the redirect URI of the route, from your configuration, never from the request.
- `callback` is `Callback::Query(query)` for the query of a `GET` with no `?`, or `Callback::Form(body)` for the
  form body of a `POST`.

The engine checks, in order: the `state` is the state of the binding; the transaction of the state is open; the redirect
URI and the response mode are the ones of its issuer; the `iss` names that issuer; and the response holds no `error`
and one `code`. It gives an `Exchange`.

## Send the token request

`exchange.request()` gives the `TokenRequest`. Send a `POST` to `request.url()`, with `Content-Type:
application/x-www-form-urlencoded`, `Accept: application/json`, `Authorization: request.authorization()` when it is
`Some`, and the body `request.body()`. The body and the field hold the code, the PKCE verifier, and the client secret:
never log them.

Give the result to `exchange.finish(fetched, now)`:

- `Ok(Fetched { status, body })` only after the complete body arrived, each framing and checksum check passed, each
  content coding was decoded within your bounds, and within the deadline of the fetch.
- `Err(FetchError::Deadline)`, `Err(FetchError::Truncated)`, `Err(FetchError::TooLarge)`, or
  `Err(FetchError::Transport)` for each other end. A failed fetch gives no evidence, also when a part of the body
  arrived.

## Finish and commit the sign-in

`exchange.finish` verifies the ID token before it uses a claim, and gives a `SignIn`:

- The signature, under the profile of its algorithm in the list of the issuer, and the issuer, the audience, `exp`,
  and `nbf` ([Verify and sign JOSE tokens](jose.md)).
- `azp`: for more than one audience, it must be there, and it must be the client ID.
- `iat`: not more than `CLOCK_SKEW_MAX` (60 seconds) before the start of the transaction, or after the reading.
- `nonce`: the nonce of the transaction.
- `sub`: 1 to 255 bytes of ASCII.
- `auth_time`: when the start set `max_age`, it must be there and no older than `max_age` plus `CLOCK_SKEW_MAX`.

`sign_in.evidence()` gives the `Federated` evidence: `issuer`, `subject`, `auth_time`, `acr`, `amr`, and `time`, the
reading of the verification. A provider identity is the pair of the issuer and the subject. The `acr` and the `amr` are
statements of the provider: the evidence derives no strength and no phishing resistance from them. No other claim, such
as an email address, enters the evidence.

The commit of the sign-in adds `sign_in.consume(&mut proposal)`: the read of the transaction at the version of the
callback, its end, and the end of the transaction as a deadline. After the commit, the same callback refuses with
`Error::Transaction`. The engine keeps no provider token.

## Outcomes

Each `oidc::Error` implements `transition::Recover`, so `?` gives a `rsauthnz_http::Problem`. Each refusal of a
response or a transaction has the recovery `Restart`: nothing committed, and the human starts again.

| Error | Cause |
| --- | --- |
| `Error::Config` | A value of the configuration is not of its form, or two issuers share an identifier or a redirect URI |
| `Error::Keys` | The key set refuses, or gives no key for an algorithm of the list |
| `Error::Issuer` | The relying party has no such issuer |
| `Error::Malformed` | The parameters of the callback are not form encoding within `CALLBACK_BYTES_MAX` (4,096 bytes), repeat a parameter, or have no code |
| `Error::State` | The `state` is missing, or is not the state of the binding: the response is for another browser |
| `Error::Transaction` | No open transaction has the state: it is unknown, or a sign-in consumed it |
| `Error::Expired` | The end of the transaction passed |
| `Error::RedirectUri` | The response came to the redirect URI of another issuer |
| `Error::ResponseMode` | The response came in another response mode than the mode of its issuer |
| `Error::Mixup` | The `iss` is missing while the issuer advertises it, or names another issuer |
| `Error::Provider` | The provider answered with an error, such as `access_denied` |
| `Error::Fetch` | The fetch of the token response failed |
| `Error::Token` | The token response is not `200`, or is not a JSON object within `TOKEN_RESPONSE_BYTES_MAX` (32 KiB) with an `id_token` and a `token_type` of `Bearer` |
| `Error::IdToken` | The ID token refuses: the `jose::Error` gives the cause, such as `Algorithm`, `Signature`, `Issuer`, `Audience`, or `Expired` |
| `Error::AuthorizedParty` | More than one audience and no `azp`, or an `azp` that is not the client ID |
| `Error::Nonce` | The `nonce` is missing, or is not the nonce of the transaction |
| `Error::IssuedAt` | The `iat` is outside the transaction |
| `Error::AuthTime` | The start asked for a maximum age, and the `auth_time` is missing or older |
| `Error::Claims` | A claim is missing, has another type, or passes its bound, such as more than `AMR_MAX` (8) `amr` values |
| `Error::Record` | A transaction record is not valid, or names an issuer that the relying party no longer has |
| `Error::Time` | The reading has no bound, or a time overflows |
| `Error::Transition` | The proposal of the start refuses |

## Limits

- A start is one commit, from a browser that is not signed in. Limit the rate of starts of one client with the
  admission of your host ([Admit rsauthnz work](admission.md)).
- A callback is one HMAC-SHA256 tag and one keyed read. A finish is one signature check, after the cheap checks of the
  header: a profile of another algorithm refuses before signature work.
- The secret of the binding, the `state`, the `nonce`, the PKCE verifier, the code, and the client secret never enter
  `Debug`, an error, or a log of the engine.
- The key set and the algorithm list come from your configuration. Discovery and key set refresh are not part of this
  engine yet, and neither are PAR, `private_key_jwt`, DPoP, the native and device flows, or logout.

## Support

The engine runs in the tests on this Mac (macOS aarch64), on the memory binding, against two in-test providers with
Ed25519 keys: one that answers in the query and advertises `iss`, and one that answers with form_post and does not. They
cover the authorization request and PKCE S256, `client_secret_basic` and `client_secret_post`, the evidence of a valid
ID token, the consumption, a mix-up, each refused claim, an algorithm outside the list, an expired transaction, a failed
fetch, another browser and response mode, and the `Debug` output. No real provider has run it yet.
