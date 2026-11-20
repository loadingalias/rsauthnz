//! Authorization: the trusted policy of the application, and the check that binds its decision to one request.
//!
//! The application owns the meaning of its policy. [`Policy::resolve`] resolves the exact action on the exact
//! resource for one principal. It gives a [`Permit`]: the evidence that the operation requires, the end of the
//! permit, and the policy version of the decision. The library runs no policy text. [`check`] binds the permit to
//! the evidence of the caller and to the request, and gives a [`Checked`] scope. The operation calls
//! [`Checked::enforce`] where it acts.
//!
//! Only the principal, the action, and the resource of a [`Request`] reach the policy. A request flag, a string
//! prefix, a role label, an external group, or a claim of the caller is not evidence, and a request has no field
//! for one.
//!
//! ```
//! use core::time::Duration;
//!
//! use rsauthnz::authz::{self, Permit, Policy, Request, Requirements};
//! use rsauthnz::evidence::Evidence;
//! use rsauthnz::id::{Action, AuthorityVersion, Id, Resource};
//! use rsauthnz::time::Reading;
//!
//! /// The policy of the application: each principal can do one action on one resource until its end.
//! struct OneAction {
//!     version: AuthorityVersion,
//!     action: Id<Action>,
//!     resource: Id<Resource>,
//!     expires: Duration,
//! }
//!
//! impl Policy for OneAction {
//!     fn version(&self) -> &AuthorityVersion {
//!         &self.version
//!     }
//!
//!     fn resolve(&self, request: &Request<'_>) -> Option<Permit> {
//!         let permitted = *request.action == self.action && *request.resource == self.resource;
//!         permitted.then(|| Permit {
//!             principal: request.principal.clone(),
//!             action: request.action.clone(),
//!             resource: request.resource.clone(),
//!             version: self.version.clone(),
//!             requires: Requirements {
//!                 user_verified: true,
//!                 phishing_resistant: true,
//!                 max_age: Duration::from_secs(300),
//!             },
//!             expires: self.expires,
//!         })
//!     }
//! }
//!
//! /// An agent request on a resource server: one check gives the scope that the operation enforces.
//! fn read_repo(evidence: &Evidence, policy: &OneAction, now: Reading) -> Result<(), Box<dyn core::error::Error>> {
//!     let action = Id::new("acme.repo", "repo.read")?;
//!     let resource = Id::new("acme.repo", "repo:x")?;
//!     let scope = authz::check(evidence, &action, &resource, policy, now)?;
//!     // Where the operation reads the repository:
//!     scope.enforce(&action, &resource, policy, now)?;
//!     Ok(())
//! }
//! ```

use core::fmt;
use core::time::Duration;

use crate::evidence::Evidence;
use crate::id::{Action, AuthorityVersion, Id, Principal, Resource};
use crate::time::{Reading, TimeError};

/// The exact operation that a principal asks to do.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The principal that the evidence proved.
    pub principal: &'a Principal,
    /// The action.
    pub action: &'a Id<Action>,
    /// The resource.
    pub resource: &'a Id<Resource>,
}

/// The trusted policy of the application.
pub trait Policy {
    /// The current version of the policy. A permit of another version is stale.
    fn version(&self) -> &AuthorityVersion;

    /// The permit of `request`, or `None` when the policy does not permit it. The permit names the principal, the
    /// action, and the resource of `request`.
    fn resolve(&self, request: &Request<'_>) -> Option<Permit>;
}

/// The decision of the policy for one request. The application makes it in [`Policy::resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    /// The principal of the request.
    pub principal: Principal,
    /// The action of the request.
    pub action: Id<Action>,
    /// The resource of the request.
    pub resource: Id<Resource>,
    /// The policy version of the decision.
    pub version: AuthorityVersion,
    /// The evidence that the operation requires.
    pub requires: Requirements,
    /// The end of the permit, as the time since the Unix epoch. The permit is not valid at this time and after it.
    pub expires: Duration,
}

/// The evidence that an operation requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requirements {
    /// The authenticator verified its user.
    pub user_verified: bool,
    /// The proof binds the origin. A recovery never has it.
    pub phishing_resistant: bool,
    /// The most time from the authentication to each use of the scope.
    pub max_age: Duration,
}

/// Checks that `policy` permits `action` on `resource` for the subject of `evidence` at the physical time `now`, and
/// gives the checked scope.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse). The check is a bounded comparison. The call of `policy` is
/// the cost of the application.
///
/// # Errors
///
/// [`Refusal::Denied`] if the policy gives no permit, and [`Refusal::Scope`] if the permit names another principal,
/// action, or resource. [`Refusal::Stale`] if the permit is not of the current policy version, and
/// [`Refusal::Requirements`] if the evidence does not meet its requirements. [`Refusal::Expired`] if `now` permits a
/// time at or after the deadline, and [`Refusal::Time`] if `now` or the time of the evidence has no known bound. The
/// deadline is the earliest of the end of the permit, the end of the maximum age of the evidence, and the end of the
/// credential of the evidence ([`Evidence::expires`]).
pub fn check(
    evidence: &Evidence,
    action: &Id<Action>,
    resource: &Id<Resource>,
    policy: &impl Policy,
    now: Reading,
) -> Result<Checked, Refusal> {
    let request = Request {
        principal: evidence.subject(),
        action,
        resource,
    };
    let permit = policy.resolve(&request).ok_or(Refusal::Denied)?;
    if permit.principal != *evidence.subject() || permit.action != *action || permit.resource != *resource {
        return Err(Refusal::Scope);
    }
    let requires = permit.requires;
    if (requires.user_verified && !evidence.user_verified())
        || (requires.phishing_resistant && !evidence.phishing_resistant())
    {
        return Err(Refusal::Requirements);
    }
    // A sum past the last representable time is no bound, so the end of the permit is the deadline. The evidence of a
    // credential gives no authority after the credential ends.
    let deadline = evidence
        .time()
        .earliest()?
        .checked_add(requires.max_age)
        .map_or(permit.expires, |end| end.min(permit.expires));
    let deadline = evidence.expires().map_or(deadline, |end| end.min(deadline));
    let checked = Checked {
        evidence: evidence.clone(),
        permit,
        deadline,
    };
    checked.current(policy, now)?;
    Ok(checked)
}

/// A scope that [`check`] gave: the evidence, the permit of the policy, and the deadline. The operation enforces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    evidence: Evidence,
    permit: Permit,
    deadline: Duration,
}

impl Checked {
    /// Checks that the operation does `action` on `resource`, that `policy` is still at the version of the permit,
    /// and that `now` is before the deadline.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The call of `policy` is the cost of the application.
    ///
    /// # Errors
    ///
    /// [`Refusal::Scope`] for another action or resource, [`Refusal::Stale`] for another policy version,
    /// [`Refusal::Expired`] if `now` permits a time at or after the deadline, and [`Refusal::Time`] if `now` has no
    /// known bound.
    pub fn enforce(
        &self,
        action: &Id<Action>,
        resource: &Id<Resource>,
        policy: &impl Policy,
        now: Reading,
    ) -> Result<(), Refusal> {
        if *action != self.permit.action || *resource != self.permit.resource {
            return Err(Refusal::Scope);
        }
        self.current(policy, now)
    }

    /// The evidence of the caller.
    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The permit of the policy: the principal, the action, the resource, the policy version, and the requirements.
    #[must_use]
    pub const fn permit(&self) -> &Permit {
        &self.permit
    }

    /// The deadline: the earliest of the end of the permit, the end of the maximum age of the evidence, and the end of
    /// the credential of the evidence. The scope is not valid at this time and after it. A transition that the scope
    /// permits carries it as its deadline ([`Proposal::until`](crate::transition::Proposal::until)), so its commit
    /// refuses after it.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    fn current(&self, policy: &impl Policy, now: Reading) -> Result<(), Refusal> {
        if self.permit.version != *policy.version() {
            return Err(Refusal::Stale);
        }
        if now.latest()? >= self.deadline {
            return Err(Refusal::Expired);
        }
        Ok(())
    }
}

/// The cause of a refused authorization. For each refusal, the recovery is to refuse the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The policy does not permit the request.
    Denied,
    /// The permit or the operation names another principal, action, or resource than the scope.
    Scope,
    /// The permit is not of the current policy version.
    Stale,
    /// The evidence does not meet the requirements of the permit.
    Requirements,
    /// The reading permits a time at or after the deadline.
    Expired,
    /// A reading has no known bound, or a bound passes the representable times.
    Time(TimeError),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied => f.write_str("the policy does not permit the request"),
            Self::Scope => f.write_str("the operation is not in the scope"),
            Self::Stale => f.write_str("the permit is not of the current policy version"),
            Self::Requirements => f.write_str("the evidence does not meet the requirements of the permit"),
            Self::Expired => f.write_str("the scope has expired"),
            Self::Time(error) => write!(f, "the time reading cannot bound the check: {error}"),
        }
    }
}

impl core::error::Error for Refusal {}

impl From<TimeError> for Refusal {
    fn from(error: TimeError) -> Self {
        Self::Time(error)
    }
}

#[cfg(test)]
mod tests;
