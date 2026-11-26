# Grant an agent access

A grant gives one enrolled agent access to named resource actions, at named services, until a deadline. Its human
owner issues it, changes it, and revokes it. For example, alice lets her build agent read repository `repo-x` at
`acme:api` until 17:00. A write, another repository, another service, and each use after 17:00 refuse. Module
`rsauthnz::grant` gives the operations.

## The model

- An agent identity has at most one **grant** ([Enroll an agent](agent-enrollment.md)). The grant names the agent, its
  owner, the **audiences** (the services that accept the agent), the **permissions** (an action on a resource, both
  identifiers of the application), a **deadline**, and the policy version of its issue.
- Each issue and each change writes a new **revision**. The counter of the commit driver numbers it, so a restore never
  gives one revision number twice.
- A grant keeps only the requested permissions that the owner holds at the issue. Thus it never exceeds what the owner
  approved or what the owner holds.
- **Effective access** is the grant intersected with the current authority of the owner. Each check of a use resolves
  the application policy again: the grant holds no copy of the authority of its owner. A permission that the owner
  loses after the issue refuses at the next use.
- A grant binds the policy version of its issue. A relevant policy change raises the version, and each grant of the
  earlier version then refuses until its owner approves a new revision.
- A permission can carry an **approval mark** (`Approval::Required`). The check gives the mark, and an operation of
  the permission then also needs a one-use approval of the owner.
- A key rotation of the agent keeps its grant: the grant names the agent identity, not its key. A credential of the
  old key refuses, so the agent presents a credential of its new key. A revocation of the grant, or of the agent,
  ends it.
- The agent presents an **agent credential** at each request. It names the agent, its owner, the current revision,
  and one audience of the grant, with the key of the agent as its proof key. It lives 15 minutes by default, and it
  never ends after the grant deadline, so a refresh never extends the grant.
- The **last use** of a grant is the start of the window in which a host last recorded a use. A host records at most
  one use of each revision in each window (5 minutes by default), and never one commit for each request.

## Before you start

- An enrolled agent ([Enroll an agent](agent-enrollment.md)).
- A passkey site with browser sessions ([Keep a browser session](sessions.md)). An issue and a change need a fresh
  user verification of the owner ([Fresh user verification](accounts.md#fresh-user-verification)).
- The policy of the application, an `authz::Policy` ([Authorize an operation](authorization.md)). The policy record of
  its owner is in the store ([Policy records](storage.md#policy-records)), because each commit reads the policy
  version.
- A commit driver on a storage binding ([Storage contract](storage.md)).
- A `Grants` value: `Grants::new(authority, limits)`, with the authority of the `Agents` of the agents.
- For agent credentials: the issuer key of the authority in custody, as a `custody::Handle` of a composite key
  ([Custody](custody.md)), and its public key at each audience.

## Issue a grant

1. The owner signs in, and chooses the agent, the audiences, the permissions, and the deadline on a page of the
   application. Get a fresh user verification with `Fresh::check(&access, max_age, now)`.
2. Make the `Draft`: its `audiences`, its `permissions`, and its `deadline`. Each `Permission` has a `resource`, an
   `action`, and an `approval`: `Approval::NotRequired` or `Approval::Required`. A draft has 1 to `Limits::audiences` (8) audiences and 1 to `Limits::permissions` (32) permissions, each named
   once. A permission is the same as another one when it has the same resource and action. The deadline is the time
   since the Unix epoch, and the issue rounds it down to a whole second.
3. Call `grants.issue(store, &fresh, &agent, &draft, &policy, now, random, &mut driver)`. It gives
   `(proposal, plan, grant)`. Commit the proposal with its plan.
4. After the accepted commit, show the `Grant`. Its `permissions` are the ones that the grant keeps, and its
   `revision` is the number of the revision.

The commit reads the session of the verification, the agent identity, the policy version, and the current grant or its
absence. So a sign-out, a revocation of the agent, a policy change, or a second change between the issue and its
commit refuses the commit.

## Change a grant

A change is an issue for an agent that has a grant. Call `grants.issue` with the new draft and a new fresh user
verification. The commit writes a new revision and ends the earlier one, also in the restore journal. Extending the
deadline and adding a permission each need this approval: no other operation changes a grant.

## Get an agent credential

A first credential and a refresh are the same request. The agent proves its current key, so it needs no earlier
credential and no challenge from the server.

1. The agent makes 32 random bytes: its nonce. The nonce names the operation of the request.
2. The agent makes a proof of possession of its current key with `credential::ProofDraft::new(&agent_key, &statement,
   &audience, &nonce, now)` ([Prove possession](credential-format.md#prove-possession)). `statement` is
   `grant::statement(&authority, &agent, &audience, lifetime)`. Its custody signs `draft.to_be_signed()`, and
   `draft.finish(&signature, &mut budget)` gives the proof.
3. The agent sends the body. `lifetime` is optional, in whole seconds:

   ```json
   {"agent":"acme:<22 base64url characters>","audience":"acme:api","lifetime":900,
    "nonce":"<base64url of 32 bytes>","proof":"<base64url>"}
   ```

4. The route reads it with `rsauthnz_http::machine_json` and `grant::Body::parse(body)`, and calls
   `grants.credential(store, body.request(), &issuer, &policy, now, &mut driver)`. It gives a `grant::Pending`.
5. Custody signs `pending.to_be_signed()` with the issuer key. `pending.finish(&signature, &mut budget)` gives
   `(proposal, plan, awaiting)`.
6. Submit the proposal with its plan. `awaiting.release(outcome)` gives the credential
   ([Release a credential](credential-format.md#release-a-credential)). Answer with `released.json()`:
   `{"credential":"<base64url>","expires":<seconds>,"renew_at":<seconds>}`.
7. The agent refreshes at `renew_at`, half the lifetime after the issue, with a new nonce.

`grants.credential` refuses before custody signs:

1. A lifetime past `grant::LIFETIME_MAX` (1 hour) or under one second refuses with `Error::Lifetime`. No lifetime is
   `grant::LIFETIME_DEFAULT` (15 minutes).
2. The proof must verify with the current key of the agent over the statement of this request, or it refuses with
   `Error::Credential`. Thus no party issues a credential in the name of an agent, and the key that a rotation
   replaced gets none.
3. The grant must not have ended, must name the audience, and must bind the current policy version.

The credential ends at the earlier of the issue plus the lifetime and the grant deadline. Its purpose is
`rsauthnz:agent` (`grant::purpose()`). The commit reads the identity, the grant, and the policy version, writes the
issuance record of the credential, and ends at the grant deadline. So a revocation, a change, a rotation, or a policy
change before the commit refuses it. Its audit names the agent and its owner.

At the audience, verify the credential with `grants.profile(issuer_key, &audience)`. During a rotation of the issuer
key, add the previous key with `profile.with_previous(previous_key, until)`.

## Check each request

Each request of the agent presents an agent credential that names its owner and the revision of its grant.
`authz::check_agent` checks it against the store and the policy, and gives a `Granted` scope. The operation enforces
the scope at each use, and an operation that commits takes its proposal from the scope. A revocation, a change, a key
rotation, or a policy change stops the work at its next use and refuses a later commit.
[Check the request of an agent](authorization.md#check-the-request-of-an-agent) gives the steps and the refusals.

## Record last use

Each host keeps a `grant::Usage` table: `Usage::default()`, or `Usage::new(granularity, capacity)` with a granularity
of whole seconds. The default granularity is 5 minutes (`GRANULARITY_DEFAULT`), and the default capacity is 4,096
grant revisions in one window (`USES_DEFAULT`).

1. After each check, call `usage.note(&scope, now)`. It gives a `LastUse` for the first use of the grant revision in
   the window of `now`, and `None` for each other use.
2. For a `LastUse`, call `grants.record(store, &last_use, now).await`. It gives `None` when the store holds this use
   or a later one. Else submit its `(proposal, plan)`.
3. Take no action for a conflict or a lost response: the next use in a later window records the use again.

The record holds the revision and the start of the window, and it ends at the grant deadline. Its operation identity
is the SHA-256 digest of the grant, the revision, and the window, so a second host that noted the same use commits
once. The commit reads the grant, so a change or a revocation drops it. Its audit names the agent and its owner, so the
audit also shows each use that a host recorded.

A full table notes no new revision until the next window. A host that restarts starts with an empty table, so it can
record one more use in that window.

## Revoke a grant

The owner revokes a grant from a signed-in session. A revocation only removes authority, so it needs no fresh user
verification.

1. Check the session of the owner, and call `grants.revoke(store, &access, &agent, now, random)`.
2. Commit the proposal and its plan.

The commit ends the grant at the revision that it read, so a change that read the same revision conflicts. A
revocation by another human refuses with `Error::NoGrant`. A revocation of the agent (`agents.revoke`) ends its grant
in the same commit.

## The active-access page

The active-access page of the owner shows the sessions and the grants together:

- The sessions: `sessions.list(store, &access, after, now)` ([Sign out, list, and revoke](sessions.md#sign-out-list-and-revoke)).
- The grants: `grants.list(store, &access, after, now)`. It gives one `Page` of the grants of the owner that did not
  end, each with its agent, audiences, permissions, deadline, revision, and `last_use`. `last_use` is the start of the
  window of the last recorded use of the current revision, or `None`: a change shows no use until the next one. One
  range read gives at most `PAGE_MAX` (64) records, each grant and its last use next to it, so a page has at most 64
  grants. A full page that ends at a grant leaves that grant to the next page, with its last use. `page.next` is the key after which the next page starts, or `None`.

A recovery of the owner account ends the sessions of the account and keeps each grant. After a recovery, the owner
reviews the grants on this page and revokes each one that they did not give.

## Lost responses and restore

- **A lost response of an issue, a change, or a revocation.** The server looks up the operation. Never submit the
  same request as a new operation: a change can have committed.
- **A lost response of a credential request.** The credential is never released (`Release::Unknown`). The agent asks
  again with a new nonce. The same nonce names the same operation: when it committed, its answer has no credential
  (`Release::Committed`). The same nonce with other values refuses (`transition::Error::Reuse`).
- **A restore.** The restore journal ends each revision that a change replaced and each grant that a revocation
  ended. A restore from a snapshot before a change thus gives no grant: the owner issues it again, and the new revision
  number is after each one that the store gave.

## Operations

| Operation | Result |
| --- | --- |
| `Grants::new(authority, limits)` | The grants of the agents of one authority |
| `grants.issue(store, &fresh, &agent, &draft, &policy, now, random, &mut driver)` | `(Proposal, Plan, Grant)`: an issue, or a change with a new revision |
| `grants.revoke(store, &access, &agent, now, random)` | `(Proposal, Plan)` of the revocation by the owner |
| `authz::check_agent(&grants, store, &evidence, &action, &resource, &policy, now)` | The `Granted` scope of one request of the agent |
| `scope.enforce(store, &action, &resource, &policy, now)` | Checks the scope again at one use, such as one chunk of a stream |
| `scope.propose(operation, request, now)` | The proposal of an operation of the agent, whose audit names the agent and its owner |
| `grant::statement(&authority, &agent, &audience, lifetime)` | The bytes that the proof of a credential request binds |
| `grant::Body::parse(json)`, `body.request()` | The JSON body of a credential request, and its `grant::Request` |
| `grants.credential(store, request, &issuer, &policy, now, &mut driver)` | The `grant::Pending` issue of an agent credential |
| `pending.finish(&signature, &mut budget)` | `(Proposal, Plan, credential::Awaiting)` |
| `released.json()` | The answer to the agent |
| `grants.profile(key, &audience)` | The `credential::Profile` that verifies the agent credentials at the audience |
| `usage.note(&scope, now)` | A `LastUse` at most once for each revision in each window |
| `grants.record(store, &last_use, now)` | `Option<(Proposal, Plan)>` of the record of a last use |
| `grants.list(store, &access, after, now)` | One `Page` of the grants of the owner, with their last uses |

The cost class of each operation that reads the store is `Verify` ([Admit rsauthnz work](admission.md)). An issue
makes two keyed lookups and one policy decision for each permission of the draft. A credential request makes two
keyed lookups and checks one composite proof. A check reads two keys in one read, makes one SHA-256 digest, and makes
one policy decision. Each `enforce` reads two keys in one read. `usage.note` is one lookup in memory, and a record of
a last use is one keyed lookup. A revocation makes one keyed lookup, and a listing one range read of at most 64
records. Run the signature of custody in the `External` cost class.

## Errors

Each `grant::Error` implements `transition::Recover`, so `?` gives a `rsauthnz_http::Problem`. The operations that
read the store return `grant::Failure`: `Refused(error)`, or `Store(error)` for a failed read.

| Error | Cause | Recovery |
| --- | --- | --- |
| `Error::Draft` | The draft has no audience or no permission, or names one twice | Correct the draft |
| `Error::Limit(limit)` | The draft has more than `Limits::audiences` audiences or `Limits::permissions` permissions | Correct the draft, or raise the limit |
| `Error::Deadline` | The deadline is not after the time of the reading | Give a later deadline |
| `Error::Authority` | The owner holds none of the requested permissions, or does not hold the permission of a use now | Refuse |
| `Error::NotEnrolled` | The store holds no identity of the agent, or the agent has another owner | Refuse |
| `Error::NoGrant` | The agent has no grant of the owner: none was given, it was revoked, or the agent was revoked | Refuse |
| `Error::Principal` | The evidence of a request is not of an agent credential | Refuse |
| `Error::Issuer` | Another authority issued the credential of the request | Refuse |
| `Error::Owner` | The credential names another owner than the identity of the agent | Refuse |
| `Error::Key` | The key of the proof is not the current key of the agent: a rotation replaced it | The agent proves its current key |
| `Error::Revision` | The credential names another revision than the current grant: a change replaced it | The agent gets a credential of the current revision |
| `Error::Expired` | The deadline of the grant passed, or the deadline of the scope of a request: the end of the permit of the owner or of the credential | The owner can approve a new revision, or the agent gets a new credential |
| `Error::Audience` | The grant does not name the audience | Refuse |
| `Error::Permission` | The grant does not name the action on the resource, or the operation of a scope is another action or resource | Refuse |
| `Error::Policy` | The grant binds another policy version | The owner can approve a new revision |
| `Error::Lifetime` | The lifetime of a credential request is past 1 hour or under one second | Ask for another lifetime, or for the default |
| `Error::Credential(error)` | The proof of a credential request does not verify with the current key of the agent, the signature of custody does not verify, or the issuer key is SLH-DSA | The agent proves its current key over the statement of the request |
| `Error::Malformed` | The JSON body of a credential request is not a request | Correct the body |
| `Error::Granularity` | The granularity of `Usage::new` is not a whole number of seconds, at least one | Correct the granularity |
| `Error::Record` | A record has no valid form | Restore the store from a snapshot |
| `Error::Time` | The time reading has no bound | Use a reading with a bound |
| `Error::Driver` | The commit driver does not serve, or its counter has no next value | Follow its recovery |
| `Error::Transition` | The proposal refuses | Follow its recovery |

## Limits

- Grants go directly from a human to an agent. An agent cannot create a grant: `grants.issue` takes the fresh user
  verification of a passkey session.
- One grant has one deadline. Two deadlines for one agent need two grants, so they need two agents.
- The approval mark is in the grant and in the check. The one-use approval of an operation is not in this release.
- A host records last use at the start of a window. The page can thus show a use up to one granularity before the
  latest one, and a restore from an older snapshot can show an earlier one. Last use gives no authority.

## Support

The tests on this Mac (macOS aarch64) run on the memory binding, with the test authenticator of the passkey tests.
They cover a draft wider than the authority of the owner, a permission that the owner loses after the issue, and a
policy change. They also cover the deadline, the draft bounds, a change by another human, and an extension whose
verification ended before its commit. They also cover a change that races a revocation, a restore before a change, a
key rotation and a revocation of the agent, and the active-access page of two humans. Each check presents an agent
credential that the authority issues from the grant, through the JSON body of the request. The tests cover the end at
the grant deadline, a lifetime past the most, a refresh at the deadline, and a proof by another key or for another
audience. They cover repeated checks in one window, a second host, a full table, a change, and a page that ends at
a grant. The tests cover a credential of another authority, of another owner, of an earlier revision, and of a key
that a rotation replaced. They also cover the audit of an operation of an agent, an agent actor outside a scope, a
revocation during a streamed response with pending work, and a policy change, a rotation, and a change during a
scope.
