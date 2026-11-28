# Sign the requests of an agent

An agent signs each HTTP request with its own key, as [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) defines. The
request carries the agent credential and the signature, so no bearer secret exists: a captured request gives no key.
The server checks the request with no state of its own. Then its replay store accepts each signature once, and gives
the same evidence as a proof of possession. Then the grant check gives the scope of the request. Module
`rsauthnz::httpsig` gives the profile, and `rsauthnz-http` maps it to `http::Request` values.

Use this profile for an HTTP API that verifies with rsauthnz, also behind a proxy that ends TLS or changes `Host`.
Each request pays for one composite signature and one credential: about 12 KB of fields
([Size of a request](#size-of-a-request)).

## The profile

The signature covers these components, each one time, in any order:

| Component | Value |
| --- | --- |
| `@method` | The method, such as `POST` |
| `@path` | The path of the target, with each percent-encoded byte as the request has it |
| `@query` | `?` and the query of the target, or `?` alone for a target with no query |
| `content-digest` | The SHA-256 digest of the body ([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)), also of an empty body |
| `content-type` | The media type, when the request has one. A changed media type can change how the server reads the same body |
| `agent-credential` | The agent credential: the grant reference. It names the agent, its owner, the grant revision, and the audience |

The signature covers no authority. The audience of the credential is the recipient of the request: a verifier takes
only the credentials of its own audience, such as `acme:api`. The verifier never reads `Host` or `:authority`, so a
proxy can change them. The WIMSE HTTP-signature draft binds its recipient in the same way, with a signed audience.

Each server of one audience takes the requests of the others. For example, if `api.example.com` and
`api-eu.example.com` have one audience, a request for one of them verifies at the other. If the requests of a
service must not verify at another service, give each service its own audience. The grant names each audience of the
agent ([Issue a grant](grants.md#issue-a-grant)).

The signature has exactly four parameters, in any order: `created` and `expires` in whole seconds since the Unix
epoch, `nonce`, and `tag="rsauthnz-agent"` (`httpsig::TAG`). The nonce is the base64url text of 16 to 32 random bytes
of the agent, with no padding. A signature with `alg`, `keyid`, or another parameter refuses. The `cnf` key of the
credential gives the key and its algorithm, so the request never selects an algorithm.

The verifier takes the one signature with the tag of the profile. Thus the signature of a proxy can be in the same
`Signature-Input` and `Signature` fields. Two signatures with the tag refuse.

A signed request has these four fields:

```http
Content-Digest: sha-256=:<base64 of 32 bytes>:
Agent-Credential: :<base64 of the credential>:
Signature-Input: agent=("@method" "@path" "@query" "content-digest" "content-type" "agent-credential");created=1800000040;expires=1800000100;nonce="<base64url of 16 bytes>";tag="rsauthnz-agent"
Signature: agent=:<base64 of the signature>:
```

The `cnf` key of the credential signs the signature base with its algorithm. Each agent key is ML-DSA-65 + Ed25519,
which signs with the empty context ([Signature profiles](profiles.md)). The verifier also checks Ed25519 and ES256
signatures: the signatures of RFC 9421 Appendix B.2.6 and B.3 verify over their signature bases.

## Before you start

- An agent with a grant, and an agent credential for the audience of the server
  ([Get an agent credential](grants.md#get-an-agent-credential)). The agent key is in custody ([Custody](custody.md)).
- At the server: the public key of the issuer of the authority, and the audience of the server, such as `acme:api`.
- The body of the request in memory, which the framework read within its body limit. The content digest needs each
  byte of the body before the operation runs.
- The store of the authority of the server, which is the replay store of its audience ([The replay
  store](#the-replay-store)). Each server of the audience uses the same store.

## Sign a request

The agent signs each request just before it sends it.

1. Build the `http::Request` with its target, such as `https://api.example.com/repos/repo-x/labels?ref=main`, its
   fields, and its body.
2. Make 16 random bytes from the entropy source of the agent: the nonce. Use a new nonce for each request.
3. Call `rsauthnz_http::signature_draft(&agent_key, &credential, &request, &nonce, httpsig::LIFETIME_DEFAULT, now)`.
   `agent_key` is the trusted key of the agent: the `cnf` key of `credential`. The lifetime is in whole seconds, and
   `LIFETIME_DEFAULT` is 60 seconds.
4. Custody signs `draft.to_be_signed()` with the agent key. `draft.finish(&signature, &mut budget)` verifies the
   signature with the agent key, and gives the `Signed` fields.
5. Call `rsauthnz_http::add_signature(request.headers_mut(), &signed)`. It adds the four fields, each in place of each
   field of its name, and marks each one sensitive. Send the request.

Refresh the credential at its `renew_at` ([Get an agent credential](grants.md#get-an-agent-credential)). A request
signed with a credential of the key that a rotation replaced refuses at the grant check.

## Verify a request

1. At startup, build the verifier of the audience of the server:
   `httpsig::Profile::new(grants.profile(issuer_key, &audience)?)`. The longest window is 5 minutes
   (`WINDOW_MAX_DEFAULT`), and the clock skew of an agent is 30 seconds (`SKEW_DEFAULT`). Change them with
   `profile.with_window(window_max, skew)`.
2. For each request, call `rsauthnz_http::verify_signature(&profile, &request, now)`. It reads the method, the path,
   the query, the fields, and the body, and no authority. It gives the `httpsig::Checked` signature, and no evidence
   yet.
3. For a request that commits nothing, such as a read, call `checked.accept(store).await`. The replay store inserts the
   replay record of the signature, and gives the `Evidence` of the agent. Then call `authz::check_agent(&grants, store,
   &evidence, &action, &resource, &policy, now).await`, and use the `Granted` scope ([Check the request of an
   agent](authorization.md#check-the-request-of-an-agent)).
4. For a request that commits a transition, call `checked.check_agent(&grants, store, &action, &resource, &policy,
   now).await`. It reads the replay floor, does the check of `authz::check_agent`, and gives an `httpsig::Pending`
   scope. Then call `pending.propose(operation, request, now)`. It gives the `Granted` scope and the proposal, with the
   replay insert in the proposal. Add the changes of the operation, and commit the proposal. The operation and the
   replay record commit together or not at all.

A host with no `http` values builds an `httpsig::Request`: the method, the path, the query, each field as a name and
a value, and the body. The agent signs it with `httpsig::Draft::new`, and the server verifies it with
`profile.verify(&request, now)`.

`verify` runs each cheap check first. The two signature checks come last: the credential, then the request, each with
its own budget of `Limits::signature_checks`. A request that fails a check inserts no replay record, so a forged
request takes no room in the share of the agent. A handler that returns `Result<Response<Vec<u8>>, Problem>` converts
each refusal with `?` ([Return a problem](http-binding.md#return-a-problem)).

A `Checked` signature gives no evidence and no scope without its replay insert. `accept` inserts before it gives the
evidence, and the proposal of a `Pending` scope holds the insert. Select the path by the effects of the request:

- A request that commits nothing calls `accept`.
- A request whose effects are all in its commit calls `check_agent`. Its commit refuses a repetition.
- A request with an effect outside the store, such as a call to another service, calls `accept` before that effect.
  The insert is then complete, so its proposal from `authz::check_agent` needs no replay insert.

## The replay store

A captured request stays valid until its `expires`, but the replay store accepts its signature once. The replay
identity is the audience of the server, the `cnf` key of the agent, and the nonce. Thus one agent cannot use the
nonce, or the room, of another agent.

- **One store for each audience.** Each server that verifies the requests of one audience uses one store, with one
  atomic insert. rsauthnz cannot detect two servers of one audience with two stores: a request repeats once at each
  store. If two services need separate stores, give each service its own audience.
- **The insert.** One atomic step, with no audit record and no commit driver, so the requests of many agents insert
  at the same time ([The replay insert](storage.md#the-replay-insert)). It refuses once the clock of the store reaches
  `expires` plus the skew, also for a verifier that waited after its check.
- **Retention.** A replay record ends at `expires` plus the skew and twice the bound of the reading of the verifier.
  Run the expiry pass of the store ([Expiry](storage.md#expiry)), which removes each ended record.
- **Restart and restore.** A store that loses its records, such as the memory binding, sets a replay floor at each
  start, and each restore sets one. A signature created before the floor plus the skew refuses with `Floor`, so a
  captured request cannot repeat after a restart. For that short time, a new signature refuses too: the agent signs
  again.
- **Capacity.** The store declares the most replay records, and the most records of one agent key
  (`Declaration::signatures`). A full store or a full share refuses with `Full`. The store never removes a live record
  to make room.

A refused repetition does not show whether the first request committed. The operation identity of the transition
shows it ([Make a transition](transitions.md)).

## Size of a request

Each request carries one signature and one credential. `add_signature` marks the fields sensitive, so an HTTP/2 or
HTTP/3 encoder that keeps the mark never indexes them, and each request sends them again. Measured on a signed `POST`
with a JSON body, with an agent credential of the tests (the issuer `acme:agents`, the audience `acme:api`, and an
agent identifier of 22 characters):

| Field | Bytes of the value |
| --- | --- |
| `Agent-Credential` | 7,398: the base64 of a credential of 5,547 bytes |
| `Signature` | 4,508: the base64 of a composite signature of 3,373 bytes |
| `Signature-Input` | 175, with `content-type` |
| `Content-Digest` | 54 |
| Total, with the names, `: `, and the line ends of HTTP/1.1 | 12,205 |

Longer identifiers make the credential longer. A credential has at most 8,192 bytes, which gives 10,926 bytes of
field value. In the measured request, each field line has less than 8 KiB, and the four lines leave about 4 KB of a
16 KiB bound for all the fields of a request. Check the bound of one field line and of all the fields at each server
and proxy on the path.

## Proxies

A proxy between the agent and the verifier breaks each signature that it changes. It must keep:

- The method, the path, and the query, byte for byte.
- The body, with no change of its encoding, and `Content-Type`.
- `Content-Digest`, `Agent-Credential`, `Signature-Input`, and `Signature`.

A proxy can add its own signature to `Signature-Input` and `Signature` under its own label. It can add other fields,
change the order of the fields, and change the case of their names. A proxy can also end TLS and change `Host` or
`:authority`, as nginx does by default: the signature covers no scheme and no authority.

## Errors

`checked.accept(store)` returns `httpsig::AcceptError` on failure. When upgrading a caller, match `AcceptError::Refused(error)` for a confirmed refusal.
Match `AcceptError::Unknown(cause)` when the binding failed. The store may have written the replay record. Refuse this request and run no application effect.
A standalone insert has no outcome record to look up. A separate application operation uses its own outcome identity.

`Conflict` and `Full` have recovery `Restart`. A conflict describes only this insert attempt.
The caller can submit the signed request for verification again while its window remains open.
`Grant` gives the recovery of its grant error. Each other signature refusal has recovery `Refuse`.

| Error | Cause |
| --- | --- |
| `Field(field)` | `Signature-Input`, `Signature`, `Content-Digest`, or `Agent-Credential` is missing, longer than `Limits::bytes`, or not valid |
| `Tag` | No signature has the tag of the profile, or two have it |
| `Components` | The covered components are not those of the profile, or a request with `Content-Type` does not cover it |
| `Parameters` | The parameters are not `created`, `expires`, `nonce`, and `tag`, each one time, or a time is negative |
| `Nonce` | The nonce is not the base64url of 16 to 32 bytes |
| `Window` | `expires` is not after `created`, or the window is longer than the longest window. A draft with a lifetime under one second |
| `Early` | `created` is later than the earliest time of the verifier plus the skew. Check the clock of the agent |
| `Expired` | The latest time of the verifier can be at or after `expires`, or the clock of the replay store reached `expires` plus the skew at the insert |
| `Digest` | `Content-Digest` has no `sha-256` member, or it is not the digest of the body |
| `Value` | A covered value has a byte that is not visible ASCII, or a derived value is empty |
| `Credential(error)` | The credential refused ([Errors](credential-format.md#errors)). A credential of another audience refuses with `credential::Error::Cose(cose::Error::Audience)` |
| `Signature` | The `cnf` key of the credential did not sign the request, or a covered component changed |
| `Limit(limit)` | A signature check costs more than its budget |
| `Time(error)` | The reading of the time has no bound |
| `Replayed` | The replay store holds the signature: the request is a repetition |
| `Conflict` | The store confirmed that contention aborted this insert with no write. The binding can accept another request |
| `Floor` | The store has no replay floor of its current start, or the signature was created before the floor. Sign again |
| `Full` | The capacity of the replay store, or the share of the agent key, is full. The recovery is `Restart`: sign again later |
| `Grant(error)` | The grant check of `checked.check_agent` refused ([Errors](grants.md#errors)) |

## Operations

| Operation | Result |
| --- | --- |
| `rsauthnz_http::signature_draft(&key, &credential, &request, &nonce, lifetime, now)` | The `httpsig::Draft` of an `http::Request` |
| `httpsig::Draft::new(&key, &credential, &request, &nonce, lifetime, now)` | The draft of an `httpsig::Request` |
| `draft.to_be_signed()` | The signature base, which custody signs |
| `draft.finish(&signature, &mut budget)` | The `Signed` fields, after the check of the signature |
| `rsauthnz_http::add_signature(headers, &signed)` | Adds the four fields to an `http::HeaderMap` |
| `signed.fields()` | Each field: its name and its value |
| `httpsig::Profile::new(credential_profile)` | The verifier of the audience of the credential profile |
| `profile.with_window(window_max, skew)` | The verifier with another window and skew |
| `rsauthnz_http::verify_signature(&profile, &request, now)` | The `httpsig::Checked` signature of an `http::Request` |
| `profile.verify(&request, now)` | The `httpsig::Checked` signature of an `httpsig::Request` |
| `checked.accept(store).await` | The `Evidence` of the agent, after the replay insert |
| `checked.check_agent(&grants, store, &action, &resource, &policy, now).await` | The `httpsig::Pending` scope of a request that commits |
| `pending.propose(operation, request, now)` | The `Granted` scope, and the proposal with the replay insert |

The cost class of a draft is `Parse`, and of `finish` and a verification is `Verify`
([Admit rsauthnz work](admission.md)). A draft makes one SHA-256 digest of the body. A verification makes one SHA-256
digest of the body and two composite signature checks. `accept` is one replay insert, of the class `Mutate`.
`check_agent` is one keyed read of the replay floor and the check of `authz::check_agent`, of the class `Verify`.
`propose` is of the class `Parse`. A proposal that cannot take the replay insert, for example at
`Limits::dependencies`, refuses with its `transition::Error`.
