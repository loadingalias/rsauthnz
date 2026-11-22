# Use the browser adapter

The browser adapter is one JavaScript module, `rsauthnz-http/browser/rsauthnz.js`, with no dependency and no build
step. It runs the passkey ceremonies of [Register a passkey and sign in](passkeys.md) in the browser. It fetches the
options from the server and calls the WebAuthn API. Then it sends `credential.toJSON()` back as a JSON state change. It also
calls the Signals API, so that a password manager stays in step with the passkeys of the server. The browser runs each
ceremony, and the server checks and commits it. The page of the [web example](web-example.md) uses the module.

The module is under 8 KiB. The adapter needs no WebAssembly, local database, or framework.

## Before you start

- Mount the HTTP binding ([Mount the HTTP binding](http-binding.md)). Each request of the module is a same-origin
  `POST` with `Content-Type: application/json`. Thus `site.json_change` admits it.
- Give the server one path for the options and one path for the finish of each ceremony. Each path answers with JSON:
  the options, or the result of the finish. Answer a refusal or an outcome with `problem(recovery)` or
  `refusal.response()`.

## Serve the module

Serve `rsauthnz_http::browser_module()` at a path of the site, such as `/rsauthnz.js`. It is a `200 OK` response with
`Content-Type: text/javascript; charset=utf-8`. Load it as a module:

```html
<script type="module">
  import { signIn, Problem } from "/rsauthnz.js";
</script>
```

## Sign in

Call `signIn({ options, finish })` from the click of a sign-in button. `options` and `finish` are the paths of the
server. The call fetches new options, calls `navigator.credentials.get()`, and sends the credential to `finish`. It
gives the JSON of the finish response, or throws a `Problem`.

For the autofill of conditional mediation, give the username input `autocomplete="username webauthn"`. On page load,
call `signIn({ options, finish, conditional: true, signal })`. The browser offers each passkey of the site in the
autofill, and the call waits until the user picks one. A challenge ends after 300 seconds, so the call gets new
options when the challenge of the earlier ones ends. Before an explicit sign-in, abort the conditional call with its
`AbortController`. In a browser with no conditional mediation, the call gives `null` at once: show the explicit
sign-in.

## Register

Call `register({ options, finish, body })`. `body` is the JSON of the start request, such as the invitation value of
an activation ([Activate an invitation](accounts.md#activate-an-invitation)), or the account name and the code of a
recovery ([Recover](recovery.md#recover)). The call calls `navigator.credentials.create()` and sends the credential to `finish`.

With `conditional: true`, the browser can create a passkey with no prompt, for a user who just signed in another way
(conditional create, an upgrade). In a browser with no conditional create, the call gives `null`. Conditional create
can register with no user verification, and the passkey profile requires it: the server then refuses the
registration with `Error::UserVerification`. Offer the explicit registration after such a refusal.

`consent(publicKey)` is an optional function of each call. The module calls it with the parsed options before the
authenticator, and a result of `false` stops the ceremony with `null`.

## Make a change

Call `change(path, body)` for a state change with no ceremony, such as a rename, the removal of a passkey, or a
sign-out. It sends a same-origin `POST` with the JSON `body`, and gives the JSON of the response, or throws a
`Problem`. A request that gets no response can have committed, so its recovery is `check`. Give
`{ signal }` as the third argument to abort it.

## Handle a problem

Each refusal of the server, and each request that gets no response, throws a `Problem`. Its `recovery` names the
action of the page, and its `status` is the HTTP status, or 0 when no response arrived:

| `recovery` | Cause | The page |
| --- | --- | --- |
| `restart` | Nothing committed, such as a conflict or a challenge that ended | Starts the ceremony again |
| `check` | The outcome is unknown: the server could not resolve it, or the finish got no response | Loads the current state, such as the account page. It never sends the request again |
| `verify` | The change needs a fresh user verification ([Manage accounts](accounts.md#fresh-user-verification)) | Calls `signIn` again, which replaces the session, then starts the change again |
| `refuse` | The server refused the request | Stops, and shows the refusal |

A finish that gets no response can have committed, so its recovery is `check`. An abort of the `signal` of a request
that commits nothing, such as the options of a conditional sign-in, stays an `AbortError`.

## Keep the password manager in step

The Signals API of WebAuthn Level 3 tells the password manager what the server holds. Each function gives `false` in
a browser with no Signals API, and `true` after the call. Give each ID as base64url text.

| Function | When | Signals API call |
| --- | --- | --- |
| `signalDeleted({ rpId, credentialId })` | After the deletion of a passkey | `signalUnknownCredential` |
| `signalAccepted({ rpId, userId, credentialIds })` | After a change of the passkeys of an account. `userId` is the user handle | `signalAllAcceptedCredentials` |
| `signalRenamed({ rpId, userId, name, displayName })` | After a rename of the account | `signalCurrentUserDetails` |

`capabilities()` gives the client capabilities of the browser, such as `conditionalGet` and `conditionalCreate`.

## Serve several domains

An application on several domains uses one relying party ID, such as `app.example`, also from `https://app.example.de`.
WebAuthn Level 3 calls these related origins.

1. List the other origins: `RelyingParty::new(...)?.with_related(&["https://app.example.de"])?`. Each one is
   `https://` and a domain name in lowercase, with a port only when it is not 443. A response from a related origin
   then verifies, and a response from an origin that the relying party does not list refuses with `Error::Origin`.
2. At the host of the relying party ID, serve `rsauthnz_http::related_origins(&rp)` for a `GET` of
   `RELATED_ORIGINS` (`/.well-known/webauthn`). The document is `{"origins":["https://app.example.de"]}`. The browser
   of a related origin fetches it before it accepts the relying party ID.

`with_related` takes at most `RELATED_MAX` (32) origins. It refuses the origin of the site and a repeated origin. A
browser takes the related origins of at least five registrable domains, and it can ignore the others.

## Support

A test on this Mac checks that the module imports nothing and stays under 8 KiB. Another test checks the document of
related origins in the format of WebAuthn Level 3. The ceremony tests on this Mac verify a registration and a
sign-in from a related origin. No browser has run the module yet, so its behavior in Chrome, Safari, and Firefox is
not verified.
