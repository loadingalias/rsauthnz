# Authorize an operation

The application owns the meaning of its policy. rsauthnz binds the decision of that policy to the evidence of the
caller and to one exact request. It gives a checked scope, and the operation enforces it where it acts. A valid
signature or an authentication alone gives no permission.

A passkey sign-in ([Register a passkey and sign in](passkeys.md#sign-in)) and a workload proof ([Issue and manage
workload credentials](workload.md)) give `Evidence`. An agent has access only through the grant of its human owner, so
its request has its own check ([Check the request of an agent](#check-the-request-of-an-agent)). The examples on this
page compile, but they do not run a check: they have no verifier input.

## Implement the policy

Implement `rsauthnz::authz::Policy` for the policy of the application:

- `version()` gives the current policy version, an `AuthorityVersion`. A permit of another version is stale.
- `resolve(&Request)` gives the `Permit` of the request, or `None` when the policy does not permit it.

A `Request` has three fields: the `principal` that the evidence proved, the `action`, and the `resource`. Only these
reach the policy. A request flag, a string prefix, a role label, an external group, or a claim of the caller is not
evidence, and a request has no field for one. rsauthnz runs no policy text.

A `Permit` names the decision:

| Field | Rule |
| --- | --- |
| `principal`, `action`, `resource` | The request that the permit resolves. The check refuses a permit for another request |
| `version` | The policy version of the decision. It must be the current version |
| `requires` | `Requirements`: `user_verified`, `phishing_resistant`, and `max_age`, the most time from the authentication to each use |
| `expires` | The end of the permit, as the time since the Unix epoch |

## Check and enforce

This example is also the first example of the `rsauthnz::authz` module documentation. One check gives the scope that
the operation uses.

```rust
use core::time::Duration;

use rsauthnz::authz::{self, Permit, Policy, Request, Requirements};
use rsauthnz::evidence::Evidence;
use rsauthnz::id::{Action, AuthorityVersion, Id, Resource};
use rsauthnz::time::Reading;

/// The policy of the application: each principal can do one action on one resource until its end.
struct OneAction {
    version: AuthorityVersion,
    action: Id<Action>,
    resource: Id<Resource>,
    expires: Duration,
}

impl Policy for OneAction {
    fn version(&self) -> &AuthorityVersion {
        &self.version
    }

    fn resolve(&self, request: &Request<'_>) -> Option<Permit> {
        let permitted = *request.action == self.action && *request.resource == self.resource;
        permitted.then(|| Permit {
            principal: request.principal.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            version: self.version.clone(),
            requires: Requirements {
                user_verified: true,
                phishing_resistant: true,
                max_age: Duration::from_secs(300),
            },
            expires: self.expires,
        })
    }
}

/// A request on a resource server: one check gives the scope that the operation enforces.
fn read_repo(evidence: &Evidence, policy: &OneAction, now: Reading) -> Result<(), Box<dyn core::error::Error>> {
    let action = Id::new("acme.repo", "repo.read")?;
    let resource = Id::new("acme.repo", "repo:x")?;
    let scope = authz::check(evidence, &action, &resource, policy, now)?;
    // Where the operation reads the repository:
    scope.enforce(&action, &resource, policy, now)?;
    Ok(())
}
```

`authz::check(evidence, action, resource, policy, now)` gives a `Checked` scope. It refuses with an
`authz::Refusal`:

| Refusal | Cause |
| --- | --- |
| `Agent` | The evidence is of an agent. Check its request with `authz::check_agent` |
| `Denied` | The policy gives no permit |
| `Scope` | The permit names another principal, action, or resource. A human and a workload with the same raw identifier are different principals |
| `Stale` | The permit is not of the current policy version |
| `Requirements` | The evidence does not meet `requires`. A recovery is never phishing resistant |
| `Expired` | `now` permits a time at or after the deadline |
| `Time(TimeError)` | `now` or the time of the evidence has no known bound |

The deadline is the earliest of `expires`, the end of `max_age`, and the end of the credential of the evidence
(`evidence.expires()`). For a credential of a previous issuer key, that end is also no later than the end of that
key. The age starts at the earliest time that the evidence permits. Thus evidence of a credential gives no authority
after the credential ends, also when `max_age` permits an older authentication.

A transition that a check permits carries the deadline: `proposal.until(checked.deadline())`. The commit driver reads a
fresh clock just before the commit, and it refuses the commit at or after the deadline with
`transition::Error::Expired` ([Make a transition](transitions.md#deadlines)).

Call `Checked::enforce(action, resource, policy, now)` where the operation acts. It refuses another action or
resource with `Scope`. It refuses with `Stale` if the policy version changed after the check, and with `Expired`
after the deadline. `Checked` also gives the evidence, the permit, and the deadline.

`check` and `enforce` are in the `Parse` cost class. Each call of the policy is the cost of the application. See
[Admit rsauthnz work](admission.md).

## Check the request of an agent

The request of an agent presents the evidence of an agent credential: the agent proves the possession of the
credential with its key ([Prove possession](credential-format.md#prove-possession)). The credential names the agent,
its human owner, the revision of its grant, and the audience. The authority issues it from the grant
([Get an agent credential](grants.md#get-an-agent-credential)), so its issuer asserts the owner and the revision. The
agent never asserts its own owner.

1. Verify the credential with the profile of the audience, `grants.profile(issuer_key, &audience)?.verify(&credential,
   now, &mut budget)`, and check the proof of the agent with `verified.possession(&proof, &challenge, now, &mut
   budget)`. It gives the `Evidence`. For an HTTP request that the agent signs,
   `rsauthnz_http::verify_signature(&profile, &request, now)` verifies the credential and the signature, and the replay
   insert of the signature gives the same `Evidence` ([Sign the requests of an agent](http-signatures.md#verify-a-request)).
2. Call `authz::check_agent(&grants, store, &evidence, &action, &resource, &policy, now).await`. It gives a
   `Granted` scope, or a `grant::Failure`.
3. At each use, call `scope.enforce(store, &action, &resource, &policy, now).await`. For a streamed response, call it
   before each chunk. To show the last use on the active-access page, note the scope after the check
   ([Record last use](grants.md#record-last-use)).
4. For an operation that commits, take the proposal from `scope.propose(operation, request, now)`. Add the changes of
   the operation, and commit it ([Make a transition](transitions.md)).

The check reads the identity of the agent and its grant from one store state (`Store::read_pair`). Then it refuses
with a `grant::Error` ([Errors](grants.md#errors)) in this order:

1. `Principal`: the evidence is not of an agent credential of the purpose `rsauthnz:agent` (`grant::purpose()`).
2. `Issuer`: another authority issued the credential. An agent of one authority has no access at another.
3. `NotEnrolled`, `Owner`, `Key`: the store has no identity of the agent, the credential names another owner, or the
   key of the proof is not the current key of the agent. A credential of the key that a rotation replaced refuses.
4. `NoGrant`, `Revision`: the agent has no grant, or the credential names another revision. A change of the grant
   stops each credential of the earlier revision.
5. `Expired`, `Audience`, `Permission`: the deadline of the grant passed, or the grant does not name the audience of
   the credential or the action on the resource.
6. `Policy`, `Authority`: the grant binds another policy version, or the policy does not permit the owner the action
   on the resource now.

Thus effective access is the grant intersected with the current authority of the owner. The requirements of the
permit of the owner (`user_verified`, `phishing_resistant`, `max_age`) do not apply to the agent. They are
requirements on the evidence of the owner, and the issue of the grant took a fresh user verification of the owner.

The scope gives `agent()`, `owner()`, `revision()`, `deadline()`, and `approval()`. The deadline is the earliest of
the grant deadline, the end of the permit of the owner, and the end of the credential. `approval()` is
`Approval::Required` when the permission has an approval mark.

`Granted::enforce` keeps no copy of the state. It refuses another action or resource with `Permission`, another
policy version with `Policy`, and a time at or after the deadline with `Expired`. Then it reads the identity and the
grant again with one `Store::read_pair`. It refuses with `NotEnrolled` after a revocation of the agent, `Key` after a
rotation, `NoGrant` after a revocation of the grant, and `Revision` after a change. Thus pending work and a streamed
response stop at their next use.

`Granted::propose` gives a proposal whose audit names the agent as its actor, its owner as a separate field
([Audit and outcome records](storage.md#audit-and-outcome-records)), and the action of the scope. Its request is
`[resource, request]`. The commit reads the identity, the grant, and the policy version of the check, and it ends at
the deadline. So a revocation, a change, a rotation, or a relevant policy change before the commit refuses it.
`Proposal::new` refuses an agent actor with `transition::Error::Agent`, so no audit of an agent request lacks its
owner.

This example is the second example of the `rsauthnz::authz` module documentation:

```rust
use rsauthnz::authz::{self, Policy};
use rsauthnz::evidence::Evidence;
use rsauthnz::grant::{Failure, Grants};
use rsauthnz::id::{Action, Id, Resource};
use rsauthnz::store::Store;
use rsauthnz::time::Reading;

/// A streamed read by an agent: one check, then one use of the scope before each chunk. A revocation, a change of
/// the grant, or a rotation of the key stops the stream at its next chunk.
async fn stream_repo<S: Store>(
    grants: &Grants,
    store: &mut S,
    evidence: &Evidence,
    (action, resource): (&Id<Action>, &Id<Resource>),
    policy: &impl Policy,
    mut now: impl FnMut() -> Reading,
    chunks: &[&[u8]],
    mut send: impl FnMut(&[u8]),
) -> Result<(), Failure<S::Error>> {
    let scope = authz::check_agent(grants, store, evidence, action, resource, policy, now()).await?;
    for chunk in chunks {
        scope.enforce(store, action, resource, policy, now()).await?;
        send(chunk);
    }
    Ok(())
}
```

`check_agent` and `enforce` are in the `Verify` cost class. A check reads two keys in one read, makes one SHA-256
digest of the key of the agent, and makes one policy decision. Each `enforce` reads two keys in one read.
