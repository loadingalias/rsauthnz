# Mount the HTTP binding

`rsauthnz-http` checks the browser requests of a site, and it writes the cookies and the error responses of the site.
It works on `http` 1.x values: `http::Request`, `http::Response`, and `http::HeaderMap`. It depends on no web
framework, server, or runtime. A framework that gives `http::Request` values, such as axum or hyper, calls it with no
conversion.

The binding gives no ceremony of its own. A ceremony, such as a [passkey registration](passkeys.md), gives the body to
its verifier and commits its transition ([Propose a transition](transitions.md)). The binding checks the request
before that work, and it writes the response after the commit. It writes and reads the cookie of a [browser
session](sessions.md).

## Before you start

- Know the origin of the site: `https://` and a domain name, with an optional port. For development, `http://localhost`
  with an optional port is also an origin. The origin comes from the configuration of the host, never from a request.
- Read each request body with the body limit of your framework before you give the request to the binding. The
  binding takes a body that is in memory: `Request<B>` with `B: AsRef<[u8]>`, for example `Vec<u8>` or `bytes::Bytes`.
- Serve the site to browsers that send `Origin` and `Sec-Fetch-Site` with each state change. Current Chrome, Edge,
  Firefox, and Safari send both. A state change from a client with no `Sec-Fetch-Site` refuses.

## Mount it

1. At startup, build one `Site` with `Site::new(origin)`. Its cookies have `SameSite=Lax`. Call
   `.same_site(SameSite::Strict)` to change it.
2. Before each state change, and before other work, call `site.check_change(&request)`. For a JSON body, call
   `site.json_change(&request, bytes_max)` in its place: it also checks the body and gives its bytes. A refusal is
   a `Problem` ([Return a problem](#return-a-problem)).
3. Commit the transition of the ceremony. For each outcome other than an accepted one, return
   `problem(recovery)` with the recovery of the outcome (`Outcome::recovery`).
4. After the commit accepts, write the response. Release a session with `site.set_session` on the headers of the
   response, and end it with `site.clear_cookie`. Read the session of a request with `name.session(request.headers())`,
   and another cookie with `name.find(request.headers())`. Write another cookie with `site.set_cookie`.
5. To send the browser to another page of the site, return `redirect(path)`.
6. Each response has a `Vec<u8>` body. Give it to your framework with `Response::map`, which converts the body into
   the body type of the framework.

[Run the web example](web-example.md) mounts the binding on axum, with each ceremony of a site.

This example is also the example of the `rsauthnz_http` crate documentation, and `cargo xtask test` runs it:

```rust
use core::time::Duration;

use http::Request;
use rsauthnz::transition::Recovery;
use rsauthnz_http::{CookieName, Site};

const SESSION: CookieName = CookieName::new("session").expect("a token");

// The origin comes from the configuration of the host, never from a request.
let site = Site::new("https://app.example")?;

// A ceremony of the browser adapter, with the body that the framework read within its body limit.
let finish = Request::post("/passkey/finish")
    .header("origin", "https://app.example")
    .header("sec-fetch-site", "same-origin")
    .header("content-type", "application/json")
    .body(br#"{"id":"AQID"}"#.to_vec())?;
let body = site.json_change(&finish, 16 * 1024)?;
assert_eq!(body, br#"{"id":"AQID"}"#);

// After its transition commits, the response releases the session in a cookie.
let mut response = rsauthnz_http::json(b"{}".to_vec());
site.set_cookie(response.headers_mut(), SESSION, b"c2Vzc2lvbg", Duration::from_secs(8 * 60 * 60))?;
assert_eq!(
    response.headers()["set-cookie"],
    "__Host-session=c2Vzc2lvbg; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Lax"
);

// A form of another site refuses before any work. The body holds only the recovery.
let forged = Request::post("/sign-out")
    .header("origin", "https://attacker.example")
    .header("sec-fetch-site", "cross-site")
    .body(())?;
let response = site.check_change(&forged).unwrap_err().response();
assert_eq!(response.status(), 403);
assert_eq!(response.body(), br#"{"recovery":"refuse"}"#);

// The server looked up a commit whose response was lost, and its outcome stays unknown. The browser loads the current
// state, and does not send the request again.
assert_eq!(rsauthnz_http::problem(Recovery::Lookup).body(), br#"{"recovery":"check"}"#);
```

## The state change check

A browser sends the cookies of the site also with a request that another site makes, such as a form post. This is a
cross-site request forgery (CSRF). `check_change` admits a state change only from a page of the site:

- The method is not safe. `GET`, `HEAD`, `OPTIONS`, `TRACE`, and `QUERY` refuse, because a link of another site can
  send them. A safe request never changes state.
- `Origin` is in the request once, and it is equal to the origin of the site.
- `Sec-Fetch-Site` is in the request once, and it is `same-origin`. A sibling subdomain is `same-site`, so it refuses.

The browser sets both headers, and no script can set them. Thus the check needs no token, no key, and no state. It
costs two header comparisons. `json_change` also refuses each body that is not `application/json`, with no parameter
or with `charset=utf-8`. A form of another site cannot send that type, and a script of another site can send it
only with a CORS permission of the site.

The binding compares `Origin` with the origin of the site in the form that a browser sends: lowercase, with no
default port and no final `/`. Thus `Site::new("https://App.Example:443/")` admits `Origin: https://app.example`.
`Site::new` refuses an origin with a path, a query, user information, or an IP address, and an `http://` origin other
than `http://localhost`.

## Cookies

Each cookie of the binding is a `__Host-` cookie: `CookieName::new("session")` is the cookie `__Host-session`. A
browser takes a `__Host-` cookie only from a secure origin, with `Secure`, `Path=/`, and no `Domain`. Thus another
host, such as another subdomain, cannot set it. `set_cookie` writes each attribute:

```text
__Host-session=c2Vzc2lvbg; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Lax
```

- `SameSite` is the value of the site. With `Lax`, a link from another site, such as a link in an email, arrives
  with the session. With `Strict`, it arrives with no session. `None` is not a value.
- `Max-Age` is the lifetime that you give, in whole seconds. `clear_cookie` writes an empty value with `Max-Age=0`.
- The value is your text: visible ASCII other than `"`, `,`, `;`, and `\`. A value with another byte refuses with
  `Error::CookieValue`, so a value cannot add an attribute.
- `set_cookie` and `clear_cookie` also set `Cache-Control: no-store`, so that no cache gives the cookie to another
  user.
- The field is sensitive: the debug output of the headers shows `Sensitive` in place of the value.

`find` reads each `cookie` field of the request, because HTTP/2 and HTTP/3 can split the cookies into several fields.
A cookie with no prefix, or with another prefix such as `__host-`, is not the cookie of the site. A cookie that is in
the request twice refuses with `Refusal::Cookie`.

### The session cookie

`site.set_session(headers, name, identifier, max_age)` writes a session identifier as 86 base64url characters, with
the attributes above. `name.session(headers)` reads it back as an `Identifier`, or `None` when the request has no
such cookie. Both encode with the base64url kernels of rscodec that have data-independent timing, because the
identifier is a bearer value. A value that is not the base64url text of 64 bytes refuses with `Refusal::Cookie`.
After a refusal, clear the cookie with `clear_cookie` and treat the request as signed out: the browser cannot change
an `HttpOnly` cookie. `set_session` refuses with `Error::Dit` when the build cannot encode with data-independent
timing, as on Windows aarch64 without `-C target-feature=+dit`.

No browser run of rsauthnz checks a `__Host-` cookie on `http://localhost` yet. A browser that does not treat
`http://localhost` as a secure origin does not keep the cookie.

## Responses

Each response of the binding has `Cache-Control: no-store`.

| Operation | Response |
| --- | --- |
| `json(body)` | `200 OK`, `Content-Type: application/json` |
| `redirect(path)` | `303 See Other` to `path` |
| `related_origins(&rp)` | `200 OK`, the document of the related origins of a relying party, for `RELATED_ORIGINS` (`/.well-known/webauthn`) ([Serve several domains](browser-adapter.md#serve-several-domains)) |
| `browser_module()` | `200 OK`, `Content-Type: text/javascript; charset=utf-8`: the [browser adapter](browser-adapter.md) |
| `problem(recovery)` and `Refusal::response` | A problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)), `Content-Type: application/problem+json` |

`redirect` takes only a path of the site. A target that does not start with one `/`, or that has a `\`, a space, or a
byte that is not visible ASCII, refuses with `Refusal::Redirect`. A browser reads `//host`, `/\host`, and a path with
a tab or a line break as another host.

A problem body holds only its recovery, never a byte of the request:

| Recovery | Status | Body | The client |
| --- | --- | --- | --- |
| `Restart` | `409 Conflict` | `{"recovery":"restart"}` | Starts the ceremony again as a new operation |
| `Lookup` | `500 Internal Server Error` | `{"recovery":"check"}` | Loads the current state, such as the account page. It never sends the request again: the first attempt can have committed |
| `Verify` | `403 Forbidden` | `{"recovery":"verify"}` | Signs in again with a passkey, then starts the change again ([Fresh user verification](accounts.md#fresh-user-verification)) |
| `Refuse` | `403 Forbidden` | `{"recovery":"refuse"}` | Stops. The same request refuses again |

`Lookup` is not `503 Service Unavailable`, because a client can send a request again after a `503`.

Each refusal of a request has the body `{"recovery":"refuse"}`:

| Refusal | Cause | Status |
| --- | --- | --- |
| `Refusal::Method` | A state change has a safe method | `403 Forbidden` |
| `Refusal::Origin` | `Origin` is missing, repeated, or not the origin of the site | `403 Forbidden` |
| `Refusal::FetchSite` | `Sec-Fetch-Site` is missing, repeated, or not `same-origin` | `403 Forbidden` |
| `Refusal::ContentType` | The body is not `application/json` | `415 Unsupported Media Type` |
| `Refusal::BodyBytes` | The body is longer than `bytes_max` | `413 Content Too Large` |
| `Refusal::Cookie` | A cookie of the site is repeated, or its value is not valid | `400 Bad Request` |
| `Refusal::Redirect` | The target of a redirect is not a path of the site | `400 Bad Request` |

The cost class of each check is `Parse` ([Admit rsauthnz work](admission.md)). Its work is linear in the bytes of the
fields that it reads, which the server bounds.

### Return a problem

A handler returns `Result<Response<Vec<u8>>, Problem>`. `?` gives a `Problem` from each `Refusal` of the binding and
from each error of rsauthnz with a recovery (the trait `transition::Recover`), so the handler converts no error
itself. On `Err(problem)`, return `problem.response(&site)`.

| `Problem` | Response |
| --- | --- |
| `Refusal(refusal)` | `refusal.response()` |
| `Recovery(recovery)` | `problem(recovery)` |
| `SignedOut(name)` | `problem(Recovery::Refuse)`, and the cookie `name` cleared: give it when the session cookie is not valid, or its session is unknown, ended, or reused ([Check each request](sessions.md#check-each-request)) |

The example of the `Problem` documentation, which `cargo xtask test` runs, returns a stale verification as
`{"recovery":"verify"}`, a failed read as `409`, and a signed-out session with its cookie cleared.

### Lost responses

The server owns `Recovery::Lookup`, because only the server holds the operation of the proposal (`Outcome::Unknown`).
The browser does not know the operation, so it cannot resolve the outcome itself. After a lost response, look up the
operation with `Driver::lookup` when the driver serves again, within the time that the request can wait. A lookup
that the driver refuses is a `driver::InDoubt`, and `?` gives it `Recovery::Lookup`. Then answer the same request with
the result of the lookup:

| `Lookup` | Response |
| --- | --- |
| `Committed(receipt)` | The response of the commit, such as the session cookie of `opening.release(&Outcome::Accepted(receipt))` |
| `Absent` | `problem(Recovery::Restart)`: nothing committed |
| `Refused(error)` | `problem(error.recovery())` |
| `Unknown`, or the driver does not serve in time | `problem(Recovery::Lookup)` |

After `{"recovery":"check"}`, the current state shows what committed. For a sign-in, the user is not signed in, and
signs in again with a new challenge.
