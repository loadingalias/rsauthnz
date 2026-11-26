# Sign the requests of an agent

An agent signs each HTTP request with its own key, as [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) defines. The
request carries the agent credential and the signature, so no bearer secret exists: a captured request gives no key.
The server verifies the request with no state of its own, and gets the same evidence as a proof of possession. Then
the grant check gives the scope of the request. Module `rsauthnz::httpsig` gives the profile, and `rsauthnz-http`
maps it to `http::Request` values.

Use this profile for an HTTP API that verifies with rsauthnz, also behind a proxy that ends TLS. Each request pays
for one composite signature and one credential: about 12 KB of fields ([Size of a request](#size-of-a-request)).

## The profile

The signature covers these components, each one time, in any order:

| Component | Value |
| --- | --- |
| `@method` | The method, such as `POST` |
| `@authority` | The host and the port of the target, in lowercase: `Host` in HTTP/1.1, `:authority` in HTTP/2 and HTTP/3 |
| `@path` | The path of the target, with each percent-encoded byte as the request has it |
| `@query` | `?` and the query of the target, or `?` alone for a target with no query |
| `content-digest` | The SHA-256 digest of the body ([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)), also of an empty body |
| `content-type` | The media type, when the request has one. A changed media type can change how the server reads the same body |
| `agent-credential` | The agent credential: the grant reference. It names the agent, its owner, the grant revision, and the audience |

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
Signature-Input: agent=("@method" "@authority" "@path" "@query" "content-digest" "content-type" "agent-credential");created=1800000040;expires=1800000100;nonce="<base64url of 16 bytes>";tag="rsauthnz-agent"
Signature: agent=:<base64 of the signature>:
```

The `cnf` key of the credential signs the signature base with its algorithm. Each agent key is ML-DSA-65 + Ed25519,
which signs with the empty context ([Signature profiles](profiles.md)). The verifier also checks Ed25519 and ES256
signatures: the vectors of RFC 9421 Appendix B.2.6, B.3, and B.4 verify.

## Before you start

- An agent with a grant, and an agent credential for the audience of the server
  ([Get an agent credential](grants.md#get-an-agent-credential)). The agent key is in custody ([Custody](custody.md)).
- At the server: the public key of the issuer of the authority, and the authorities that the agents send, such as
  `api.example.com`.
- The body of the request in memory, which the framework read within its body limit. The content digest needs each
  byte of the body before the operation runs.
- A verifier accepts one signed request again until its `expires`. No replay store refuses a repeated signature yet.
  Keep the lifetime short, and give each operation that commits an operation identity
  ([Make a transition](transitions.md)), so that a repeated request commits nothing new.

## Sign a request

The agent signs each request just before it sends it.

1. Build the `http::Request` with an absolute target, such as `https://api.example.com/repos/repo-x/labels?ref=main`,
   its fields, and its body.
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

1. At startup, build the verifier: `httpsig::Profile::new(grants.profile(issuer_key, &audience)?, &authorities)?`.
   `authorities` are the hosts, with a port when it is not the default, that the agents send. They compare in
   lowercase with no other change, so list each form that the agents send. The longest window is 5 minutes
   (`WINDOW_MAX_DEFAULT`), and the clock skew of an agent is 30 seconds (`SKEW_DEFAULT`). Change them with
   `profile.with_window(window_max, skew)`.
2. For each request, call `rsauthnz_http::verify_signature(&profile, &request, now)`. It takes the authority of the
   target, which HTTP/2 and HTTP/3 give, or else the one `Host` of HTTP/1.1. It gives the `Evidence` of the agent.
3. Call `authz::check_agent(&grants, store, &evidence, &action, &resource, &policy, now).await`, and use the `Granted`
   scope ([Check the request of an agent](authorization.md#check-the-request-of-an-agent)).

A host with no `http` values builds an `httpsig::Request`: the method, the authority, the path, the query, each field
as a name and a value, and the body. The agent signs it with `httpsig::Draft::new`, and the server verifies it with
`profile.verify(&request, now)`.

`verify` runs each cheap check first. The two signature checks come last: the credential, then the request, each with
its own budget of `Limits::signature_checks`. A handler that returns `Result<Response<Vec<u8>>, Problem>` converts
each `httpsig::Error` with `?` into `403 Forbidden` and `{"recovery":"refuse"}`
([Return a problem](http-binding.md#return-a-problem)).

## Size of a request

Each request carries one signature and one credential. `add_signature` marks the fields sensitive, so an HTTP/2 or
HTTP/3 encoder that keeps the mark never indexes them, and each request sends them again. Measured on a signed `POST` with a JSON body, with an agent credential of the tests (the
issuer `acme:agents`, the audience `acme:api`, and an agent identifier of 22 characters):

| Field | Bytes of the value |
| --- | --- |
| `Agent-Credential` | 7,398: the base64 of a credential of 5,547 bytes |
| `Signature` | 4,508: the base64 of a composite signature of 3,373 bytes |
| `Signature-Input` | 188, with `content-type` |
| `Content-Digest` | 54 |
| Total, with the names, `: `, and the line ends of HTTP/1.1 | 12,218 |

Longer identifiers make the credential longer. A credential has at most 8,192 bytes, which gives 10,926 bytes of
field value. In the measured request, each field line has less than 8 KiB, and the four lines leave about 4 KB of a
16 KiB bound for all the fields of a request. Check the bound of one field line and of all the fields at each server
and proxy on the path.

## Proxies

A proxy between the agent and the verifier breaks each signature that it changes. It must keep:

- The method, the authority (`Host` or `:authority`), the path, and the query, byte for byte. For nginx, set
  `proxy_set_header Host $host`: its default sends the name of the upstream.
- The body, with no change of its encoding, and `Content-Type`.
- `Content-Digest`, `Agent-Credential`, `Signature-Input`, and `Signature`.

A proxy can add its own signature to `Signature-Input` and `Signature` under its own label, and it can add other
fields. A proxy can end TLS: the scheme is not covered.

## Errors

Each `httpsig::Error` of a request has the recovery `Refuse`: the same request refuses again, and the agent signs a new
request.

| Error | Cause |
| --- | --- |
| `Authority` | The authority is not an authority of the profile, or the request has no authority, or two `Host` fields |
| `Field(field)` | `Signature-Input`, `Signature`, `Content-Digest`, or `Agent-Credential` is missing, longer than `Limits::bytes`, or not valid |
| `Tag` | No signature has the tag of the profile, or two have it |
| `Components` | The covered components are not those of the profile, or a request with `Content-Type` does not cover it |
| `Parameters` | The parameters are not `created`, `expires`, `nonce`, and `tag`, each one time, or a time is negative |
| `Nonce` | The nonce is not the base64url of 16 to 32 bytes |
| `Window` | `expires` is not after `created`, or the window is longer than the longest window. A draft with a lifetime under one second |
| `Early` | `created` is later than the earliest time of the verifier plus the skew. Check the clock of the agent |
| `Expired` | The latest time of the verifier can be at or after `expires` |
| `Digest` | `Content-Digest` has no `sha-256` member, or it is not the digest of the body |
| `Value` | A covered value has a byte that is not visible ASCII, or a derived value is empty |
| `Credential(error)` | The credential refused ([Errors](credential-format.md#errors)) |
| `Signature` | The `cnf` key of the credential did not sign the request, or a covered component changed |
| `Limit(limit)` | A signature check costs more than its budget |
| `Time(error)` | The reading of the time has no bound |

## Operations

| Operation | Result |
| --- | --- |
| `rsauthnz_http::signature_draft(&key, &credential, &request, &nonce, lifetime, now)` | The `httpsig::Draft` of an `http::Request` |
| `httpsig::Draft::new(&key, &credential, &request, &nonce, lifetime, now)` | The draft of an `httpsig::Request` |
| `draft.to_be_signed()` | The signature base, which custody signs |
| `draft.finish(&signature, &mut budget)` | The `Signed` fields, after the check of the signature |
| `rsauthnz_http::add_signature(headers, &signed)` | Adds the four fields to an `http::HeaderMap` |
| `signed.fields()` | Each field: its name and its value |
| `httpsig::Profile::new(credential_profile, &authorities)` | The verifier of the authorities |
| `profile.with_window(window_max, skew)` | The verifier with another window and skew |
| `rsauthnz_http::verify_signature(&profile, &request, now)` | The `Evidence` of the agent of an `http::Request` |
| `profile.verify(&request, now)` | The `Evidence` of the agent of an `httpsig::Request` |

The cost class of a draft is `Parse`, and of `finish` and a verification is `Verify`
([Admit rsauthnz work](admission.md)). A draft makes one SHA-256 digest of the body. A verification makes one SHA-256
digest of the body and two composite signature checks.
