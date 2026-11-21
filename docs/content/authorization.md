# Authorize an operation

The application owns the meaning of its policy. rsauthnz binds the decision of that policy to the evidence of the
caller and to one exact request. It gives a checked scope, and the operation enforces it where it acts. A valid
signature or an authentication alone gives no permission.

A passkey sign-in ([Register a passkey and sign in](passkeys.md#sign-in)) and a workload proof ([Issue and manage
workload credentials](workload.md)) give `Evidence`. The example on this page compiles, but it does not run a check:
it has no verifier input.

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

This example is also the example of the `rsauthnz::authz` module documentation. It has the "Agent request" shape:
one check gives the scope that the operation uses.

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

/// An agent request on a resource server: one check gives the scope that the operation enforces.
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
| `Denied` | The policy gives no permit |
| `Scope` | The permit names another principal, action, or resource. A human and an agent with the same raw identifier are different principals |
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
