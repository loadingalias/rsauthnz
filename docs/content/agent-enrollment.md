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

A hosted agent can give the identity of its workload in its request, in place of a pasted secret: a SPIFFE JWT-SVID,
a cloud identity token, or a workload credential of rsauthnz. The request keeps the verified workload, and the approval
page shows it. The workload names no owner: the human still approves, and the owner comes only from the approval.

After the enrollment, the agent rotates its key with signatures by its current key and by its new key. Only its
owner revokes it. No operation changes the owner of an identity: the owner revokes it, and a new enrollment gives a
new agent identifier.

An agent identity is not an authority anchor. A restore ends each pending request, and a restore from a snapshot
before an enrollment loses the identity. The agent then enrolls again. The restore journal keeps each rotation and each
revocation, so no restore gives a revoked identity or an earlier key again.

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
   `agent::Enrollment::parse(body)`. It calls `agents.enroll(&enrollment.key, &enrollment.name, None, None, now, random)`,
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
     answer with `rsauthnz_http::json(identity.json())`: `{"agent":"acme:…","owner":"acme:alice","generation":1}`.
     The agent keeps the generation of its key for its next rotation.

`agents.identity(store, &agent)` gives the current `Identity`: `agent`, `owner`, `key`, `name`, `workload`, `created`,
the `generation` of the key, and the `version` of its record. Each check of a request of the agent reads it, so a key that no enrollment bound refuses.

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

## Bootstrap a hosted agent from its workload

A hosted agent, such as a job in a cluster, proves the identity of its workload in its request. The human approves as
in [Enroll with the user code](#enroll-with-the-user-code), and sees the verified workload on the approval page.

### Configure a platform

A `Platform` is an outside issuer of workload identity tokens that the host trusts: its fetched key set, and the
binding of its tokens to the agent key.

1. Build the profile of the issuer with `jose::Profile::new(algorithm, kind, issuer, audience, limits)`:
   - For a SPIFFE trust domain, `kind` is `jose::Kind::Svid`, and `issuer` is the SPIFFE ID of the trust domain, such
     as `spiffe://prod.example`. `algorithm` is the algorithm of the keys of its JWT bundle, such as `Algorithm::Es256`.
   - For a cloud identity token, `kind` is `jose::Kind::Jwt`, and `issuer` is the `iss` of its tokens.
   - `audience` names the enrollment of this authority, such as `https://app.example/agent`.
2. Build `trust::KeySet::new(profile, freshness)`, and refresh it with the key set of the issuer
   ([Refresh the key set of an outside issuer](trust-snapshots.md#refresh-the-key-set-of-an-outside-issuer)).
3. Select the binding:
   - `Binding::Key`: the audience of a token is the audience of the platform, `#`, and the base64url of the SHA-256
     digest of the agent key. A stolen token then labels only the key that it names. Use it when the platform gives a
     token for an audience that the caller names, as SPIRE, the metadata server of Google Cloud, and GitHub Actions do.
   - `Binding::Bearer`: the audience of a token is the audience of the platform. A stolen token labels each key until
     the token ends. Use it only for a platform that fixes the audience, such as a managed identity of Azure or a
     projected service account token of Kubernetes.
4. Make the platform: `Platform { keys, binding }`. A host with more than one platform selects the platform of a
   request itself, for example by the route of the request.

### Request with a token

1. The agent stores its key in custody. It asks its platform for a token with the audience
   `binding.audience(audience, &key)`, then sends the token in the enrollment body:

   ```json
   {"name":"builder","key":"<base64url of the 1,984-byte public key>","token":"<the compact JWT>"}
   ```

2. `Enrollment::parse(body)` gives `enrollment.bootstrap` as `Some(Bootstrap::Token(token))`. The route calls
   `platform.verify(&token, &enrollment.key, now)`, which gives the `Workload`. Then it calls
   `agents.enroll(&enrollment.key, &enrollment.name, None, Some(&workload), now, random)`, and continues with step 2
   of [Enroll with the user code](#enroll-with-the-user-code).
3. The approval page shows `request.workload` with the name and the fingerprint: `workload.issuer()` and
   `workload.subject()`, as text.

`platform.verify` checks the token with the fresh key set, for the audience of the binding. The workload is the issuer
of the profile and the `sub` of the token. For a JWT-SVID, `sub` is a SPIFFE ID with a path in the trust domain, and
`iss` is not read. Each other claim gives nothing, also a claim that names a person, such as `email` or `owner`.

### Request with a workload credential

A workload with a workload credential of rsauthnz ([Issue and manage workload credentials](workload.md)) gives the credential and
a proof by its registered key.

1. The credential has the audience of this authority. The workload signs a proof with its registered key:
   `credential::ProofDraft::new(&registered, credential, &audience, &Workload::challenge(&key), now)`. The challenge
   binds the SHA-256 digest of the agent key, so the proof starts the enrollment of that key only.
2. The agent sends the base64url of both:

   ```json
   {"name":"builder","key":"<base64url>","credential":"<base64url>","proof":"<base64url>"}
   ```

3. `enrollment.bootstrap` is `Some(Bootstrap::Credential { credential, proof })`. The route takes the fresh `View` of
   a trust snapshot ([Verify with a snapshot](trust-snapshots.md#verify-with-a-snapshot)) and the profile
   `view.issuer(&issuer)` with `issuer.profile(&audience, limits)`. It calls
   `Workload::credential(&view, &profile, &credential, &proof, &enrollment.key, now)` for the `Workload`, and enrolls
   as in [Request with a token](#request-with-a-token).

`Workload::credential` refuses a credential that a rotation, a recovery, or a revocation in the snapshot ended. The
workload is the authority of the credential and its workload identifier.

## Rotate the key of an agent

A rotation replaces the key of an agent identity. The owner, the name, the workload, and the time of creation stay.
It needs a signature by the current key and by the new key, so a party with only one of the keys cannot rotate.

1. The agent stores the new key in custody. It makes the statement
   `Rotation::statement(&agent, &current_key, &new_key, generation)` with the generation of its current key: 1 after
   the enrollment, and the value of the last rotation answer after a rotation.
2. The agent signs the statement with the current key and with the new key, and sends the rotation body:

   ```json
   {"agent":"acme:<22 base64url characters>","key":"<base64url of the new public key>",
    "old_signature":"<base64url>","new_signature":"<base64url>"}
   ```

3. The route reads it with `machine_json` and `agent::Rotation::parse(body)`, and calls
   `agents.rotate(store, &rotation, now, operation)`. Commit the proposal with its plan. The plan names the identity
   as replaced, so the restore journal ends its earlier version.
4. After the commit, the route reads the identity with `agents.identity(store, &agent)`, and answers with
   `identity.json()`: `{"agent":"acme:…","owner":"acme:alice","generation":2}`.

The statement is the canonical CBOR form `["rsauthnz.agent.rotation.1", agent, old, new, generation]`, with the
SHA-256 digest of each key. Each rotation raises the generation, so a statement of an earlier generation never matches
again, also after a rotation back to an earlier key. After the commit, the old key cannot rotate, and
`agents.identity` gives the new key, so a check that reads the identity refuses the old key.

## Revoke an agent

The owner revokes an agent from a signed-in session. A revocation only removes authority, so it needs no fresh user
verification.

1. Check the session of the owner, and call `agents.revoke(store, &access, &agent, now, random)` with its `Access`.
2. Commit the proposal and its plan. The commit ends the identity at the version that the proposal read.

After the commit, `agents.identity`, a rotation, and a second revocation refuse with `Error::NotEnrolled`. The
proposal reads the session, so a revocation from a session that ended refuses at the commit. A revocation by another
human also refuses with `Error::NotEnrolled`, so the answer tells no other human that the agent exists.

## Change the owner of an agent

No operation changes the owner of an identity in place. The owner revokes the agent, and the agent enrolls again: the
new owner approves the new request. The new identity has a new agent identifier, and it can have the same key. The
audit records of the earlier commits keep the earlier owner, and the audit records of the new enrollment name the new
owner.

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
- **A lost response of a rotation.** The agent sends the same body again. `Error::Rotated` shows that the rotation
  committed: the new key is current, and the generation is one more.
- **A lost response of a revocation.** The server looks up the operation. A new revocation refuses with
  `Error::NotEnrolled` when the earlier one committed.
- **A restore.** A restore ends each pending request: a finish refuses with `Error::Request`. A restore from a snapshot
  before a finish loses the identity: `agents.identity` refuses with `Error::NotEnrolled`, and the agent enrolls
  again. A restore from a snapshot before a rotation or a revocation gives no identity: the journal ends the version
  of the snapshot, so neither the earlier key nor the revoked identity serves again. The agent enrolls again.

## Operations

| Operation | Side | Result |
| --- | --- | --- |
| `Agents::new(authority, limits)` | Server | The enrollment of agents under one authority |
| `agents.enroll(&key, name, loopback, workload, now, random)` | Server | `(Proposal, Plan, Started)`. `started.code` and `started.agent` at once. The receipt gives the 32 bytes of the `DeviceCode` |
| `agents.request(store, &access, &code, now, random)` | Server | `(Proposal, Plan, Checked<Request>)`. The `Request` has `name`, `fingerprint`, `loopback`, `workload`, `created`, `ends`, and `approved` |
| `agents.approve(store, &fresh, &code, now, random)` | Server | `(Proposal, Plan, Checked<Option<Loopback>>)`. For a loopback request, the receipt gives the 32 bytes of the `RedirectCode` |
| `checked.release(&outcome)` | Server | The answer of a right code from the accepted commit of its check, also after a lookup. `None` for a wrong code and each other outcome |
| `agents.finish(store, &code, &device, redirect, now, operation)` | Server | `Status::Waiting`, or `Status::Approved(proposal, plan)` |
| `agents.identity(store, &agent)` | Server | The current `Identity` of the agent |
| `Rotation::statement(&agent, &old, &new, generation)` | Agent | The statement that the current key and the new key sign |
| `Rotation::parse(json)`, `agents.rotate(store, &rotation, now, operation)` | Server | The rotation body, and `(Proposal, Plan)` of the rotation |
| `agents.revoke(store, &access, &agent, now, random)` | Server | `(Proposal, Plan)` of the revocation by the owner |
| `Enrollment::parse(json)`, `Finish::parse(json)` | Server | The bodies of the agent. `enrollment.bootstrap` holds the workload identity of a hosted agent. `Debug` shows no token |
| `Platform { keys, binding }`, `platform.verify(&token, &key, now)` | Server | The `Workload` of a token of a configured platform |
| `Workload::credential(&view, &profile, &credential, &proof, &key, now)` | Server | The `Workload` of a workload credential of rsauthnz |
| `binding.audience(audience, &key)`, `Workload::challenge(&key)` | Agent | The audience of a token, and the challenge of a proof, for the agent key |
| `workload.issuer()`, `workload.subject()` | Server | The verified workload, for the approval page |
| `started.json(&device, verification)`, `identity.json()` | Server | The JSON answers to the agent |
| `UserCode::parse(text)`, `code.text()` | Both | The user code, and its text |
| `DeviceCode::from_bytes(bytes)`, `RedirectCode::from_bytes(bytes)`, `as_bytes()` | Both | The codes, and their bytes. `Debug` shows no code |
| `Loopback::parse(text)`, `loopback.redirect(&code)` | Both | The loopback address, and the address of the redirect |
| `rsauthnz_http::machine_json(&request, bytes_max)`, `rsauthnz_http::waiting()` | Server | The check of a request of an agent, and the answer to a finish that waits |

A request, a check, an approval, and a finish each read the request with one keyed lookup. A rotation and a
revocation each read the identity with one keyed lookup and commit. A rotation also checks two composite signatures. A check and an approval
also commit. A finish of an approved
request also reads the account revision of the approval, so a recovery of the account between the approval and the
finish stops the finish. An identity read is one keyed lookup.

## Errors

Each `agent::Error` implements `transition::Recover`, so `?` gives a `rsauthnz_http::Problem`.

| Error | Cause | Recovery |
| --- | --- | --- |
| `Error::Malformed` | A body is not of its form, or is longer than `BODY_BYTES_MAX` (32,768 bytes). A body with a token and a credential, or with a credential and no proof, is not of its form | Refuse |
| `Error::Name` | The name is empty, longer than 64 bytes, or holds a control character | Give another name |
| `Error::Loopback` | The text is not a loopback address | Give a loopback address |
| `Error::Request` | No open request has the codes: it ended, a finish consumed it, a restore ended it, or a recovery of the account of the approval ended the approval | Make a new request |
| `Error::Expired` | The end of the request passed | Make a new request |
| `Error::Locked` | The request had `ATTEMPTS_MAX` (5) wrong checks of its user code | Make a new request |
| `Error::Approved` | An account approved the request already | Show the approval |
| `Error::Redirect` | A loopback request has no redirect code or another one, or a request with no loopback address has one | Refuse |
| `Error::NotEnrolled` | The store holds no identity of the agent: no enrollment bound it, its owner revoked it, or a restore lost it. Also a revocation by another human | Enroll again |
| `Error::Rotated` | The new key of a rotation is the current key: a rotation to it committed | Take the rotation as done |
| `Error::Signature` | A signature of a rotation does not verify with its key over the statement of the current generation | Sign the statement of the current generation with both keys |
| `Error::Record` | A record has no valid form | Restore the store from a snapshot |
| `Error::Time` | The time reading has no bound, or a time overflows | Use a reading with a bound |
| `Error::Transition` | The proposal refuses | Follow its recovery |
| `Error::Trust` | The key set of the platform is missing or stale, or the time reading refuses | Refresh the key set |
| `Error::Token` | The token refuses: `jose::Error::Issuer` for another issuer or trust domain, `Audience` for another agent key, `Expired` past its end, or another `jose::Error` | The agent gets a new token |
| `Error::Credential` | The workload credential or its proof refuses | Refuse |
| `Error::Admission` | The trust snapshot does not admit the credential: it has no registration of the workload, or a rotation, a recovery, or a revocation ended the credential | The workload gets a new credential |
| `Error::Workload` | The issuer or the subject is longer than `WORKLOAD_BYTES_MAX` (2,048 bytes), or holds a control character | Refuse |

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
- A workload token is a bearer secret until it ends. Do not log the enrollment body. With `Binding::Bearer`, a stolen
  token labels each key, so the approval page can show a true workload with the key of another party. The human still
  compares the fingerprint.
- The host fetches each key set from the address that it configures for the issuer, never from an address in a token.

## Support

The enrollment runs in the tests on this Mac (macOS aarch64), on the memory binding, with the test authenticator of the
passkey tests. They cover the journey with the JSON bodies and answers, the substituted owner, a session that ended, two
approvals, the attempt bound, an ended request, the loopback flow, the loopback address rule, a recovery of the owner
between the approval and the finish, and a restore. No browser
or example host runs the approval page yet.

The hosted bootstrap runs in the same tests with an ES256 trust domain that the tests sign for, in the form of a SPIFFE
bundle and of JWT-SVIDs. They cover a token of the configured trust domain, a claim that names an owner, another
trust domain, another key of the agent, an ended token, a bearer platform, and a missing or stale key set. A workload
credential with its proof runs with a trust snapshot, also after a revocation. No token of a SPIRE server or of a
cloud platform ran.

The rotation and the revocation run in the same tests. They cover a rotation with one key, with another key, and with
a statement of another generation, a repeated rotation, the old key after a rotation, and a rotation back to an
earlier key. They also cover a revocation by another human, each operation after a revocation, a restore before a
revocation and before a rotation, and a new owner with the audit of both owners.
