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
- A key rotation of the agent keeps its grant: the grant names the agent identity, not its key. A revocation of the
  grant, or of the agent, ends it.

## Before you start

- An enrolled agent ([Enroll an agent](agent-enrollment.md)).
- A passkey site with browser sessions ([Keep a browser session](sessions.md)). An issue and a change need a fresh
  user verification of the owner ([Fresh user verification](accounts.md#fresh-user-verification)).
- The policy of the application, an `authz::Policy` ([Authorize an operation](authorization.md)). The policy record of
  its owner is in the store ([Policy records](storage.md#policy-records)), because each commit reads the policy
  version.
- A commit driver on a storage binding ([Storage contract](storage.md)).
- A `Grants` value: `Grants::new(authority, limits)`, with the authority of the `Agents` of the agents.

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

## Check each use

Each use of the agent checks the grant before the operation acts:

1. Call `grants.admits(store, &agent, Use { audience, resource, action }, &policy, now)`.
2. On success, the `Admitted` value gives `agent()`, `owner()`, `revision()`, `deadline()`, and `approval()`. The
   deadline is the earlier of the grant deadline and the end of the permit of the owner.
3. Add `admitted.gate(&mut proposal)` to the commit of the operation. The commit then reads the agent identity, the
   grant revision, and the policy version of the check, and it ends at the deadline. A revocation, a change, a key
   rotation, or a policy change between the check and the commit refuses the commit.

The check refuses when the agent has no identity, the grant has ended, the grant names neither the audience nor the
permission, the grant binds another policy version, or the policy does not permit the owner the action now.

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
- The grants: `grants.list(store, &access, after, now)`. It gives one `Page` of at most `PAGE_MAX` (64) grants of the
  owner that did not end, each with its agent, audiences, permissions, deadline, and revision. `page.next` is the key
  after which the next page starts, or `None`.

A recovery of the owner account ends the sessions of the account and keeps each grant. After a recovery, the owner
reviews the grants on this page and revokes each one that they did not give.

## Lost responses and restore

- **A lost response of an issue, a change, or a revocation.** The server looks up the operation. Never submit the
  same request as a new operation: a change can have committed.
- **A restore.** The restore journal ends each revision that a change replaced and each grant that a revocation
  ended. A restore from a snapshot before a change thus gives no grant: the owner issues it again, and the new revision
  number is after each one that the store gave.

## Operations

| Operation | Result |
| --- | --- |
| `Grants::new(authority, limits)` | The grants of the agents of one authority |
| `grants.issue(store, &fresh, &agent, &draft, &policy, now, random, &mut driver)` | `(Proposal, Plan, Grant)`: an issue, or a change with a new revision |
| `grants.revoke(store, &access, &agent, now, random)` | `(Proposal, Plan)` of the revocation by the owner |
| `grants.admits(store, &agent, request, &policy, now)` | The `Admitted` access of one use: `request` is a `Use` |
| `admitted.gate(&mut proposal)` | Adds the reads of the check and its deadline to the commit of the operation |
| `grants.list(store, &access, after, now)` | One `Page` of the grants of the owner |

The cost class of each operation that reads the store is `Verify` ([Admit rsauthnz work](admission.md)). An issue
makes two keyed lookups and one policy decision for each permission of the draft. A check makes two keyed lookups and
one policy decision. A revocation makes one keyed lookup, and a listing one range read of at most 64 records.

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
| `Error::Expired` | The deadline of the grant passed | The owner can approve a new revision |
| `Error::Audience` | The grant does not name the audience | Refuse |
| `Error::Permission` | The grant does not name the action on the resource | Refuse |
| `Error::Policy` | The grant binds another policy version | The owner can approve a new revision |
| `Error::Record` | A record has no valid form | Restore the store from a snapshot |
| `Error::Time` | The time reading has no bound | Use a reading with a bound |
| `Error::Driver` | The commit driver does not serve, or its counter has no next value | Follow its recovery |
| `Error::Transition` | The proposal refuses | Follow its recovery |

## Limits

- Grants go directly from a human to an agent. An agent cannot create a grant: `grants.issue` takes the fresh user
  verification of a passkey session.
- One grant has one deadline. Two deadlines for one agent need two grants, so they need two agents.
- The approval mark is in the grant and in the check. The one-use approval of an operation is not in this release.
- An agent presents no grant credential yet, and the active-access page shows no last use yet.

## Support

The tests on this Mac (macOS aarch64) run on the memory binding, with the test authenticator of the passkey tests.
They cover a draft wider than the authority of the owner, a permission that the owner loses after the issue, and a
policy change. They also cover the deadline, the draft bounds, a change by another human, and an extension whose
verification ended before its commit. They also cover a change that races a revocation, a restore before a change, a
key rotation and a revocation of the agent, and the active-access page of two humans.
