# Run the web example

The web example is a web application on [axum](https://docs.rs/axum/0.8.9) that mounts the [HTTP
binding](http-binding.md). A person signs up with a passkey, signs in, names, adds, and removes passkeys, ends
sessions, invites a new account, and recovers the account with a code. A person can also approve a native CLI. The page calls the server through the [browser
adapter](browser-adapter.md).

The server keeps accounts, sessions, and CLI bindings in memory. A server restart ends them.
The CLI issuer key stays in file custody. The default key directory is `.rsauthnz-web-example` in your home directory.
To select a separate directory, run `cargo run --locked -p web -- ./web-issuer`. Give a new directory on the first run.

## Run the example

You need a checkout of the repository and the toolchain that `rust-toolchain.toml` pins. Run it from the root of the
repository:

```sh
cargo run --locked -p web
```

The server prints one line and serves until you stop it:

```text
Serving http://localhost:8080. The store is in memory: a restart of this process loses each account.
```

Open `http://localhost:8080` in a browser with a passkey provider. The origin is `http://localhost:8080`, and the
relying party ID is `localhost`. The session cookie is a `__Host-` cookie with `Secure`, so a browser keeps it on
`http://localhost` when it treats `localhost` as a secure context. The server serves HTTP/1.1 and HTTP/2 with no TLS. A browser uses HTTP/2 only with TLS, so it uses HTTP/1.1 here.

After the memory store starts, the server waits until its clock can issue a usable sign-in challenge.
Other requests can proceed during this wait.

## Approve a CLI

Start enrollment in the terminal. Follow the printed address to `/cli`. You can also select **Connect a CLI** on the account page.
Review the account, device name, and key fingerprint. Approval requires passkey verification within five minutes.
If the account changes after review, review the request again. [Connect a CLI to your account](native-cli-example.md#connect-a-cli-to-your-account).

## The steps

Each browser change uses a same-origin `POST` with a JSON body. The router reads the body within `BODY_BYTES_MAX` (16 KiB),
and the handler checks it with `site.json_change` or `site.check_change` before other work.

| Step | Routes | Operations |
| --- | --- | --- |
| Sign up | `/sign-up/options`, `/sign-up/finish` | `rp.start` with `Decision::SignUp`, `rp.finish`, `registration.propose` ([Register](passkeys.md#register)) |
| Sign in | `/sign-in/options`, `/sign-in/finish` | `rp.sign_in_options`, `rp.sign_in`, `sign_in.open`, `opening.release`, and the session cookie ([Sign in](passkeys.md#sign-in)) |
| The account page | `GET /account` | `sessions.check`, `rp.passkeys`, and `sessions.list`. The response gives the data of `signalRenamed` and `signalAccepted`: `rpId`, `userId`, `name`, `displayName`, and the `id` of each passkey |
| Rename the account | `/account/rename` | A change of the directory of the example, with `name` and `displayName` ([Rename an account](accounts.md#rename-an-account)). A new name needs a `Fresh`, and a new display name needs only the session. A name of another account refuses |
| Rename a passkey | `/passkeys/rename` | `rp.rename`. It needs no fresh user verification |
| Add a passkey | `/passkeys/add/options`, `/passkeys/add/finish` | `rp.start` and `registration.propose` with `Decision::Add` ([Add a passkey](accounts.md#add-a-passkey)) |
| Remove a passkey | `/passkeys/remove` | `rp.remove` with a `Fresh`. Its commit writes the removal mark of the passkey ([Remove a passkey](accounts.md#remove-a-passkey)) |
| End a session | `/sessions/revoke` | `sessions.revoke` with `Revoker::Own` for the session of the request, and `Revoker::Fresh` for another one |
| Invite | `/invitations` | `rp.invite` under the policy of the example: each account that signed in with user verification may invite ([Issue an invitation](accounts.md#issue-an-invitation)) |
| Activate an invitation | `/invitation/options`, `/invitation/finish/{name}` | `rp.activation_options`, `rp.activate`, and `activation.propose`. The path names the account, so a name has only lowercase ASCII letters, digits, `.`, `-`, `_`, and `@` |
| Make a recovery code | `/recovery-code` | `rp.recovery_code` with a `Fresh`. Only the accepted commit gives the code, and the page shows it once |
| Recover | `/recover/options`, `/recover/finish` | `rp.recovery_options`, `rp.recover` with `Passkeys::End`, and one `attempt.propose` ([Recover](recovery.md#recover)) |
| Review or approve a CLI | `/cli/request`, `/cli/approve` | `authority.request` shows the device. `authority.approve` checks fresh verification and commits the approval. |
| Sign out | `/sign-out` | `sessions.revoke` with `Revoker::Own`, and `site.clear_cookie` |

A sensitive change, such as a removal, a new code, a new account name, or the end of another session, needs a fresh
user verification: a sign-in with user verification at most 5 minutes old. After it, the server answers `403` with
`{"recovery":"verify"}`, and the page asks for a new sign-in.

At each load of the account, also after each sign-in, the page calls `signalRenamed` and `signalAccepted` with the
data of `/account`. Thus a provider on another device learns a rename or a removal at the next sign-in there. After
the removal of a passkey, the page also calls `signalDeleted`. After a rename of a passkey, it makes no Signals call: a
provider keeps its own label of a passkey.

A sign-in with a removed passkey, such as from a provider that no call reached, gets `410` with
`{"recovery":"forget"}`. `signIn` of the browser module then calls `signalDeleted` for it, and the page asks for a
sign-in with another passkey.

## Failures and recovery

The native CLI sends CBOR to `/cli/enroll`, `/cli/poll`, `/cli/finish`, `/cli/credential`, `/cli/challenge`, and `/cli/status`.
These routes take `POST` requests on loopback. The device code stays in the request body. A signed proof admits the `status` call.

Browser handlers return `rsauthnz_http::Problem` when the request fails. An ended session clears the session cookie on the account page.
On the CLI approval page, an absent or ended session asks for fresh sign-in. [HTTP problem responses](http-binding.md#return-a-problem).

After a commit whose response is lost (`Outcome::Unknown`), the server starts the driver again and looks up the
operation. A sign-in or a recovery then answers the same request with its session. A start of a ceremony has no
options in the receipt of a lookup, so it answers `{"recovery":"restart"}`. Each other result of the lookup gives its
recovery ([Lost responses](http-binding.md#lost-responses)).

## The mount on axum

The `router` function mounts the handlers on axum. The binary starts the listener with `axum::serve`. The router performs these steps.

1. Read the body with `axum::body::to_bytes`. Return `Refusal::BodyBytes` if it exceeds `BODY_BYTES_MAX`.
2. Pass the handler an `http::Request<Bytes>`.
3. Convert the handler response with `response.map(Body::from)`.

The handlers share one application lock. The memory binding completes each storage request at its first poll.
CLI credential issuance also reads the issuer key from file custody. A store that does I/O needs its own executor. [Write a storage binding](storage-binding.md).

## Check the example

```sh
cargo xtask test -p web
```

The tests drive the routes in process with the responses of the test authenticator of the core: each step of the
journey, the rename of an account, a commit whose response is lost, a request of another site, and a change after the
verification window.
One test serves the router on a loopback port and sends the same request over HTTP/1.1 and HTTP/2.

## Support

| Profile | Evidence |
| --- | --- |
| macOS aarch64, HTTP/1.1 and HTTP/2 | The tests pass, and the server serves the page and the sign-in options to `curl` over both protocols |
| Windows x86_64 | Not run yet |
| Chrome 158 on macOS aarch64, virtual passkey | Sign-up, passkey sign-in on the approval page, matching fingerprints, and native CLI approval passed. |

The example serves cleartext HTTP on loopback. A host with persistent accounts needs its own storage binding.
