# Enroll an agent

An agent enrolls its own key, and its human owner approves the enrollment in a browser with a passkey. The result is
an agent identity: the agent identifier, the account of its owner, and the public key of the agent. The agent never
receives the session or a credential of its owner, and no value from the agent names its owner. Module
`rsauthnz::agent` gives the operations, and `rsauthnz-http` gives the check of the routes of the agent.

An enrolled agent has no access yet. A grant gives it access to named resource actions until a deadline.

## The model

The enrollment has the shape of OAuth device authorization ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)). It
has three commits:

1. **Request.** The agent sends its public key and a name. The commit writes an enrollment request. The agent gets its
   agent identifier, a user code such as `WDJB-MJHT`, and a secret device code.
2. **Approval.** The human signs in on the approval page, gives the user code, and compares the key fingerprint with
   the fingerprint on the screen of the agent. The approval needs a fresh user verification. The commit writes the
   account of the human into the request.
3. **Finish.** The agent sends its user code and its device code. One commit consumes the request and writes the agent
   identity, with the account of the approval as its owner.

A local agent can give a loopback address, such as `http://127.0.0.1:49152/agent`. After the approval, the browser of
the human goes to that address with a one-use redirect code, and the agent finishes only with that code. A human who
approves the request of a remote agent by mistake then binds no key: the remote agent never gets the redirect code.

An agent identity is not an authority anchor. A restore ends each pending request, and a restore from a snapshot
before an enrollment loses the identity. The agent then enrolls again.

## Before you start

- A passkey site with browser sessions ([Keep a browser session](sessions.md)), so that the approval page has a fresh
  user verification ([Fresh user verification](accounts.md#fresh-user-verification)).
- A commit driver on a storage binding ([Storage contract](storage.md)).
- An `Agents` value: `Agents::new(authority, limits)`. The authority separates the records of two sites in one store,
  and its namespace is the namespace of each agent identifier.
- An agent key in custody: a composite ML-DSA-65 + Ed25519 key of 1,984 bytes, from
  `custody.enroll(id, Algorithm::MlDsa65Ed25519, random)` ([Hold keys in custody](custody.md)).

## Enroll with the user code

1. The agent stores its key in custody, then sends the enrollment body to the request route:

   ```json
   {"name":"build-agent","key":"<base64url of the 1,984-byte public key>"}
   ```

   The route reads the body with `rsauthnz_http::machine_json(&request, agent::BODY_BYTES_MAX)` and
   `agent::Enrollment::parse(body)`. It calls `agents.enroll(&enrollment.key, &enrollment.name, None, now, random)`,
   and commits the proposal with its plan. The name has 1 to `NAME_BYTES_MAX` (64) bytes and no control character.
2. The artifact of the accepted commit is the 32 bytes of the device code: `DeviceCode::from_bytes(bytes)`. The route
   answers with `rsauthnz_http::json(started.json(&device, "https://app.example/agent"))`:

   ```json
   {"agent":"acme:<22 base64url characters>","user_code":"WDJB-MJHT","device_code":"<base64url>",
    "verification_uri":"https://app.example/agent","verification_uri_complete":"https://app.example/agent?code=WDJB-MJHT",
    "expires_in":600,"interval":5}
   ```

   The agent keeps the device code secret, and keeps its agent identifier. The request ends after
   `ENROLLMENT_LIFETIME` (10 minutes).
3. The agent shows the user code, the address of the approval page, and the SHA-256 digest of its public key.
4. The human signs in on the approval page and gives the code. The page reads it with `UserCode::parse(text)`, and
   calls `agents.request(store, &access, &code, now, random)` with the `Access` of the session check. The call gives
   `(proposal, plan, checked)`. Commit the proposal and its plan, then call `checked.release(&outcome)`:
   - `Some(request)`: show `request.name` as text, never as markup, and `request.fingerprint`. The human compares the
     fingerprint with the one on the screen of the agent.
   - `None`: the code is wrong, or the commit did not accept. Show nothing of the request, and ask the human to give
     the code again. A wrong code counts against the bound.
5. To approve, get a fresh user verification with `Fresh::check(&access, max_age, now)`, and call
   `agents.approve(store, &fresh, &code, now, random)`. Commit its proposal and plan as in step 4. `checked.release(&outcome)`
   gives `Some(loopback)` when the approval committed, and `None` for a wrong code or another outcome.
6. The agent sends its finish body to the finish route every `interval` seconds:

   ```json
   {"user_code":"WDJB-MJHT","device_code":"<base64url>"}
   ```

   The route reads it with `machine_json` and `agent::Finish::parse(body)`, and calls
   `agents.finish(store, &finish.code, &finish.device, finish.redirect.as_ref(), now, operation)`:
   - `Status::Waiting`: answer with `rsauthnz_http::waiting()`, which is `202 Accepted` with `Retry-After: 5` and
     `{"interval":5}`. Nothing commits.
   - `Status::Approved(proposal, plan)`: commit it. Then read the identity with `agents.identity(store, &agent)`, and
     answer with `rsauthnz_http::json(identity.json())`: `{"agent":"acme:…","owner":"acme:alice"}`.

`agents.identity(store, &agent)` gives the current `Identity`: `agent`, `owner`, `key`, `name`, `created`, and the
`version` of its record. Each check of a request of the agent reads it, so a key that no enrollment bound refuses.

## Enroll a local agent with a loopback address

A local agent also starts a listener on the loopback interface, and gives its address in the enrollment body:

```json
{"name":"desktop-agent","key":"<base64url>","loopback":"http://127.0.0.1:49152/agent"}
```

1. The agent opens `verification_uri_complete` in the browser of the human, so the human does not type the code.
2. The approval page shows `request.loopback`. After the approval of step 5 commits, `checked.release(&outcome)` gives
   `Some(Some(loopback))`, and the artifact of the receipt is the 32 bytes of the redirect code:
   `RedirectCode::from_bytes(bytes)`. The page sends the browser to `loopback.redirect(&redirect)`, which is the loopback
   address with the query `code=` and the base64url of the code.
3. The listener of the agent reads the code, and the agent sends the finish body with it:

   ```json
   {"user_code":"WDJB-MJHT","device_code":"<base64url>","redirect_code":"<base64url>"}
   ```

A loopback address is `http://127.0.0.1:<port>/<path>` or `http://[::1]:<port>/<path>`, with at most
`LOOPBACK_BYTES_MAX` (128) bytes. The path has only letters, digits, `-`, `.`, `_`, `~`, and `/`, so it has no query
and no fragment. The name `localhost` refuses, because a resolver can give another address. The redirect code alone
admits nothing: the finish also needs the device code.

## The routes of the agent

The agent is no browser. `rsauthnz_http::machine_json` admits a request only with an unsafe method, with no `Origin`,
no `Sec-Fetch-Site`, and no `Cookie`, with `Content-Type: application/json`, and within its bound. A browser sends
`Origin` and `Sec-Fetch-Site` with each state change, and no script can remove them. Thus no page of any site can send
a request of an agent with the cookies of a human, and no route of an agent takes a session.

The JSON readers ignore each member that they do not name. A member such as `"owner"` names no owner.

## Lost responses and restore

- **A lost response of a request.** The agent makes a new request. The earlier request ends unused.
- **A lost response of a check or an approval.** The server looks up the operation, and `checked.release` takes the
  receipt of the lookup. For a loopback request whose redirect code is lost, the agent makes a new request.
- **A lost response of a finish.** The agent reads its identity: `agents.identity(store, &agent)` with the agent
  identifier of step 2. `Error::NotEnrolled` shows that the finish did not commit.
- **A restore.** A restore ends each pending request: a finish refuses with `Error::Request`. A restore from a snapshot
  before a finish loses the identity: `agents.identity` refuses with `Error::NotEnrolled`, and the agent enrolls
  again.

## Operations

| Operation | Side | Result |
| --- | --- | --- |
| `Agents::new(authority, limits)` | Server | The enrollment of agents under one authority |
| `agents.enroll(&key, name, loopback, now, random)` | Server | `(Proposal, Plan, Started)`. `started.code` and `started.agent` at once. The receipt gives the 32 bytes of the `DeviceCode` |
| `agents.request(store, &access, &code, now, random)` | Server | `(Proposal, Plan, Checked<Request>)`. The `Request` has `name`, `fingerprint`, `loopback`, `created`, `ends`, and `approved` |
| `agents.approve(store, &fresh, &code, now, random)` | Server | `(Proposal, Plan, Checked<Option<Loopback>>)`. For a loopback request, the receipt gives the 32 bytes of the `RedirectCode` |
| `checked.release(&outcome)` | Server | The answer of a right code from the accepted commit of its check, also after a lookup. `None` for a wrong code and each other outcome |
| `agents.finish(store, &code, &device, redirect, now, operation)` | Server | `Status::Waiting`, or `Status::Approved(proposal, plan)` |
| `agents.identity(store, &agent)` | Server | The current `Identity` of the agent |
| `Enrollment::parse(json)`, `Finish::parse(json)` | Server | The bodies of the agent |
| `started.json(&device, verification)`, `identity.json()` | Server | The JSON answers to the agent |
| `UserCode::parse(text)`, `code.text()` | Both | The user code, and its text |
| `DeviceCode::from_bytes(bytes)`, `RedirectCode::from_bytes(bytes)`, `as_bytes()` | Both | The codes, and their bytes. `Debug` shows no code |
| `Loopback::parse(text)`, `loopback.redirect(&code)` | Both | The loopback address, and the address of the redirect |
| `rsauthnz_http::machine_json(&request, bytes_max)`, `rsauthnz_http::waiting()` | Server | The check of a request of an agent, and the answer to a finish that waits |

A request, a check, an approval, and a finish each read the request with one keyed lookup. A check and an approval
also commit. A finish of an approved
request also reads the account revision of the approval, so a recovery of the account between the approval and the
finish stops the finish. An identity read is one keyed lookup.

## Errors

Each `agent::Error` implements `transition::Recover`, so `?` gives a `rsauthnz_http::Problem`.

| Error | Cause | Recovery |
| --- | --- | --- |
| `Error::Malformed` | A body is not of its form, or is longer than `BODY_BYTES_MAX` (4,096 bytes) | Refuse |
| `Error::Name` | The name is empty, longer than 64 bytes, or holds a control character | Give another name |
| `Error::Loopback` | The text is not a loopback address | Give a loopback address |
| `Error::Request` | No open request has the codes: it ended, a finish consumed it, a restore ended it, or a recovery of the account of the approval ended the approval | Make a new request |
| `Error::Expired` | The end of the request passed | Make a new request |
| `Error::Locked` | The request had `ATTEMPTS_MAX` (5) wrong checks of its user code | Make a new request |
| `Error::Approved` | An account approved the request already | Show the approval |
| `Error::Redirect` | A loopback request has no redirect code or another one, or a request with no loopback address has one | Refuse |
| `Error::NotEnrolled` | The store holds no identity of the agent | Enroll again |
| `Error::Record` | A record has no valid form | Restore the store from a snapshot |
| `Error::Time` | The time reading has no bound, or a time overflows | Use a reading with a bound |
| `Error::Transition` | The proposal refuses | Follow its recovery |

## Limits

- The first 4 letters of a user code find the request, and the last 4 check it. Only a signed-in human makes a check.
  Each check is a commit at the version of the request, whose audit names the account, and a wrong check counts. Of
  the checks that read one version, only one commits, and only its answer releases. Thus checks at the same time get
  no more answers than one at a time. After `ATTEMPTS_MAX` (5) wrong checks, the request is locked, and one request
  admits a guess with a chance of at most 5 in 160,000.
- A check of an approved request writes its next version too. A finish that read the earlier version conflicts: the
  agent sends the finish again.
- A signed-in human can lock the request of another agent with wrong checks. That agent makes a new request.
- Two open requests whose user codes have the same first 4 letters conflict at the commit of the second. The agent
  asks again.
- A request authenticates no caller, and its audit names the agent. Limit the rate of requests and finishes of one
  client with the admission of the host ([Admit rsauthnz work](admission.md)). A finish that waits is one keyed read
  and writes nothing.
- A user code proves nothing. Anyone can send a human the code of a request of their own agent. So the page shows the
  name and the fingerprint, and asks the human to approve only an agent on their own screen. The loopback flow binds no
  key of a remote agent.
- The redirect code is in the address of the loopback redirect, as an OAuth authorization code is in RFC 8252. It is
  one-use, it goes only to the loopback interface, and it admits nothing without the device code.

## Support

The enrollment runs in the tests on this Mac (macOS aarch64), on the memory binding, with the test authenticator of the
passkey tests. They cover the journey with the JSON bodies and answers, the substituted owner, a session that ended, two
approvals, the attempt bound, an ended request, the loopback flow, the loopback address rule, a recovery of the owner
between the approval and the finish, and a restore. No browser
or example host runs the approval page yet.
