use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::assert_matches;
use core::cell::RefCell;
use core::time::Duration;

use super::{
    Audit, Change, Dependency, Effect, Ended, Error, Intent, Key, Operation, OperationId, Outcome, Prepared, Proposal,
    Recovery, State,
};
use crate::authz::{self, Permit, Policy, Request, Requirements};
use crate::cbor::Value;
use crate::evidence::{Evidence, Method};
use crate::id::{Action, Agent, AuthorityVersion, Human, Id, Principal, Resource};
use crate::limits::{Limit, Limits};
use crate::time::{Reading, ReadingSource};

fn human() -> Principal {
    Principal::Human(Id::<Human>::new("acme", "u-17").unwrap())
}

fn reading(seconds: u64) -> Reading {
    Reading::new(
        Duration::from_secs(seconds),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

fn version(owner: &str, n: u64) -> AuthorityVersion {
    AuthorityVersion::new(Id::new("acme", owner).unwrap(), &n.to_be_bytes()).unwrap()
}

fn key(name: &str) -> Key {
    Key::new(name.as_bytes()).unwrap()
}

fn action(value: &str) -> Id<Action> {
    Id::new("acme.auth", value).unwrap()
}

fn audit(actor: Principal, action: &str) -> Audit {
    Audit {
        actor,
        action: self::action(action),
        time: reading(1_000),
    }
}

/// The proposal of `action` by `actor` on the request `[grant]`, under the operation identity `id`.
fn proposal(id: &[u8], actor: Principal, action: &str, grant: &str) -> Proposal {
    let request = Value::Array(vec![Value::Text(grant)]);
    Proposal::new(
        OperationId::new(id).unwrap(),
        audit(actor, action),
        &request,
        Limits::default(),
    )
    .unwrap()
}

/// The outcome records of a store, keyed by operation identity, and the count of its commits. A commit of an
/// identity with no record accepts the proposal. A commit or a lookup of an identity with a record gets the answer
/// of that record.
#[derive(Default)]
struct Outcomes {
    records: Vec<Operation>,
    commits: usize,
}

impl Outcomes {
    fn record(&self, operation: &Operation) -> Option<&Operation> {
        self.records.iter().find(|record| record.id == operation.id)
    }

    fn commit(&mut self, proposal: Proposal) -> Outcome {
        if let Some(record) = self.record(proposal.operation()) {
            return record.answer(proposal.operation());
        }
        self.records.push(proposal.operation().clone());
        self.commits += 1;
        Outcome::Accepted(proposal.accept())
    }

    fn lookup(&self, operation: &Operation) -> Outcome {
        self.record(operation).map_or_else(
            || Outcome::Unknown(operation.clone()),
            |record| record.answer(operation),
        )
    }
}

/// The first attempt commits, and its response is lost. The caller follows the recovery of the unknown outcome: a
/// lookup of the same identity gives the first commit, and a new operation would commit the grant twice. A
/// submission of the same request under the same identity gets the first commit too. Another request, actor, or
/// action under that identity refuses.
#[test]
fn reuse_of_an_operation_identity_with_different_input_refuses() {
    let mut store = Outcomes::default();
    let first = proposal(b"op-1", human(), "grant.issue", "repo:x");
    let operation = first.operation().clone();
    assert_matches!(store.commit(first), Outcome::Accepted(_));
    let lost = Outcome::Unknown(operation.clone());

    let resolved = match lost.recovery() {
        Some(Recovery::Lookup) => store.lookup(&operation),
        Some(Recovery::Restart) => store.commit(proposal(b"op-2", human(), "grant.issue", "repo:x")),
        recovery => panic!("an unknown outcome has the recovery {recovery:?}"),
    };
    assert_matches!(resolved, Outcome::Accepted(receipt) if receipt.operation() == &operation.id);
    assert_eq!(
        store.commits, 1,
        "the recovery of the unknown outcome committed the request again"
    );

    assert_matches!(
        store.commit(proposal(b"op-1", human(), "grant.issue", "repo:x")),
        Outcome::Accepted(receipt) if receipt.operation() == &operation.id
    );
    let agent = Principal::Agent(Id::<Agent>::new("acme", "u-17").unwrap());
    for other in [
        proposal(b"op-1", human(), "grant.issue", "repo:y"),
        proposal(b"op-1", agent, "grant.issue", "repo:x"),
        proposal(b"op-1", human(), "grant.change", "repo:x"),
    ] {
        let refused = store.commit(other);
        assert_eq!(refused.recovery(), Some(Recovery::Refuse));
        assert_matches!(refused, Outcome::Refused(Error::Reuse));
    }
    assert_eq!(store.commits, 1);
}

/// The current state that a decision reads: the version of each record, and the policy. It logs each read.
struct Current {
    records: Vec<(Key, AuthorityVersion)>,
    policy: AuthorityVersion,
    reads: RefCell<Vec<Dependency>>,
}

impl Current {
    fn read(&self, key: &Key) -> Dependency {
        let read = self.records.iter().find(|(record, _)| record == key).map_or_else(
            || Dependency::Absent(key.clone()),
            |(_, version)| Dependency::Version(key.clone(), version.clone()),
        );
        self.reads.borrow_mut().push(read.clone());
        read
    }
}

impl Policy for Current {
    fn version(&self) -> &AuthorityVersion {
        self.reads.borrow_mut().push(Dependency::Policy(self.policy.clone()));
        &self.policy
    }

    fn resolve(&self, request: &Request<'_>) -> Option<Permit> {
        Some(Permit {
            principal: request.principal.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            version: self.policy.clone(),
            requires: Requirements {
                user_verified: true,
                phishing_resistant: true,
                max_age: Duration::from_secs(300),
            },
            expires: Duration::from_secs(2_000),
        })
    }
}

/// A decision that enrolls the credential `c-4` with the invitation `i-9`. It checks the policy, reads the
/// invitation, the account, and the absent credential, and reads the invitation again.
fn enroll(state: &Current, evidence: &Evidence) -> Result<Proposal, Error> {
    let (invitation, account, credential) = (key("invitation/i-9"), key("account/u-17"), key("credential/c-4"));
    let mut proposal = Proposal::new(
        OperationId::new(b"op-1")?,
        audit(evidence.subject().clone(), "credential.enroll"),
        &Value::Text("c-4"),
        Limits::default(),
    )?;
    let resource: Id<Resource> = Id::new("acme.auth", "account:u-17").unwrap();
    let scope = authz::check(evidence, &action("credential.enroll"), &resource, state, reading(1_000)).unwrap();
    proposal.read(Dependency::Policy(scope.permit().version.clone()))?;
    for record in [&invitation, &account, &credential, &invitation] {
        proposal.read(state.read(record))?;
    }
    proposal.change(Change::End(invitation))?;
    proposal.change(Change::Write {
        key: credential,
        version: version("auth", 1),
        end: None,
        data: Box::new(*b"credential"),
    })?;
    Ok(proposal)
}

/// The dependencies of a proposal are the reads of its decision: the policy, each record version, and each absence.
/// When the state changes between two reads of one record, the decision refuses and restarts.
#[test]
fn a_proposal_lists_every_read_dependency_of_its_decision() {
    let state = Current {
        records: vec![
            (key("invitation/i-9"), version("auth", 3)),
            (key("account/u-17"), version("auth", 5)),
        ],
        policy: version("policy", 7),
        reads: RefCell::default(),
    };
    let evidence = Evidence::new(human(), Method::Passkey, reading(1_000), true, true, None, None);
    let proposal = enroll(&state, &evidence).unwrap();

    let mut reads: Vec<Dependency> = Vec::new();
    for read in state.reads.take() {
        if !reads.contains(&read) {
            reads.push(read);
        }
    }
    assert_eq!(proposal.dependencies(), reads.as_slice());
    assert_matches!(reads.as_slice(), [Dependency::Policy(_), _, _, Dependency::Absent(_)]);

    // A concurrent commit changes the account between two reads.
    let mut proposal = enroll(&state, &evidence).unwrap();
    let changed = Dependency::Version(key("account/u-17"), version("auth", 6));
    let error = proposal.read(changed).unwrap_err();
    assert_eq!((error, error.recovery()), (Error::Changed, Recovery::Restart));
    assert_eq!(proposal.dependencies(), reads.as_slice());
}

/// A change needs a read that allows it. Thus two consumptions of one value cannot both commit, a creation cannot
/// replace a record, and a write cannot make an earlier version current again.
#[test]
fn a_change_needs_a_read_that_allows_it() {
    let write = |name: &str, version| Change::Write {
        key: key(name),
        version,
        end: None,
        data: Box::new([]),
    };
    let mut proposal = proposal(b"op-1", human(), "session.renew", "s-1");
    for read in [
        Dependency::Absent(key("new")),
        Dependency::Version(key("session"), version("auth", 7)),
        Dependency::Version(key("ceremony"), version("auth", 3)),
        Dependency::Policy(version("policy", 1)),
    ] {
        proposal.read(read).unwrap();
    }

    for refused in [
        // No read of the record.
        Change::End(key("unread")),
        write("unread", version("auth", 1)),
        // An end of an absent record.
        Change::End(key("new")),
        // A write at the version that the proposal read, at an earlier one, or at one of another owner.
        write("session", version("auth", 7)),
        write("session", version("auth", 6)),
        write("session", version("other", 8)),
    ] {
        assert_eq!(proposal.change(refused), Err(Error::Change));
    }

    for allowed in [
        write("new", version("auth", 1)),
        write("session", version("auth", 8)),
        Change::End(key("ceremony")),
    ] {
        proposal.change(allowed).unwrap();
    }
    // A second change of one record.
    assert_eq!(proposal.change(Change::End(key("session"))), Err(Error::Change));
    assert_eq!(proposal.changes().len(), 3);
}

/// A proposal holds at most `Limits::dependencies` reads and `Limits::intents` intents. A repeated read adds nothing.
#[test]
fn a_proposal_refuses_a_dependency_or_an_intent_past_its_bound() {
    let limits = Limits {
        dependencies: 2,
        intents: 1,
        ..Limits::default()
    };
    let request = Value::Null;
    let mut proposal = Proposal::new(
        OperationId::new(b"op-1").unwrap(),
        audit(human(), "a"),
        &request,
        limits,
    )
    .unwrap();

    proposal.read(Dependency::Absent(key("a"))).unwrap();
    proposal.read(Dependency::Absent(key("b"))).unwrap();
    proposal.read(Dependency::Absent(key("a"))).unwrap();
    assert_eq!(
        proposal.read(Dependency::Absent(key("c"))),
        Err(Error::Limit(Limit::Dependencies))
    );

    proposal
        .intend(Intent::new(Effect::Notification, Box::new([])))
        .unwrap();
    assert_eq!(
        proposal.intend(Intent::new(Effect::Signer, Box::new([]))),
        Err(Error::Limit(Limit::Intents))
    );
}

/// The renderings of `bytes` in `Debug` output: as decimal and hexadecimal byte lists, and as text.
fn renderings(bytes: &[u8]) -> [String; 3] {
    [
        format!("{bytes:?}").trim_end_matches(']').into(),
        format!("{bytes:02x?}").trim_end_matches(']').into(),
        String::from_utf8_lossy(bytes).into(),
    ]
}

/// A proposal holds a secret in the request, a record, an intent, and the prepared artifact. No `Debug` output of
/// the proposal or of its outcomes shows the secret bytes. Only the receipt of the acceptance gives the artifact.
#[test]
fn debug_of_a_proposal_with_a_secret_field_shows_no_secret_bytes() {
    const SECRET: &[u8] = b"s3cr3t-session-token";
    let request = Value::Bytes(SECRET);
    let mut proposal = Proposal::new(
        OperationId::new(b"op-1").unwrap(),
        audit(human(), "session.renew"),
        &request,
        Limits::default(),
    )
    .unwrap();
    proposal.read(Dependency::Absent(key("session"))).unwrap();
    proposal
        .change(Change::Write {
            key: key("session"),
            version: version("auth", 1),
            end: None,
            data: SECRET.into(),
        })
        .unwrap();
    proposal.intend(Intent::new(Effect::Provider, SECRET.into())).unwrap();
    proposal
        .prepare(Prepared::new(SECRET.into(), key("session"), version("auth", 1)))
        .unwrap();

    let operation = proposal.operation().clone();
    let shown = format!("{proposal:?}");
    let receipt = proposal.accept();
    let shown = [
        shown,
        format!("{receipt:?}"),
        format!("{:?}", Outcome::Unknown(operation.clone())),
        format!("{:?}", operation.answer(&operation)),
    ];
    for text in &shown {
        for rendering in renderings(SECRET) {
            assert!(!text.contains(&rendering), "{text} shows the secret as {rendering}");
        }
    }
    // The control: the receipt holds the secret that its `Debug` output does not show.
    assert_eq!(receipt.artifact(), Some(SECRET));
}

/// A prepared artifact names its issuance record. A proposal that does not write that record at that version refuses
/// the artifact, so a credential never commits with an unrelated transition. A second artifact refuses too.
#[test]
fn a_prepared_artifact_refuses_a_proposal_that_does_not_write_its_issuance_record() {
    let issued = || Prepared::new(Box::new(*b"credential 9"), key("credential/9"), version("auth", 9));
    let mut unrelated = proposal(b"op-1", human(), "credential.issue", "repo:x");
    unrelated.read(Dependency::Absent(key("credential/1"))).unwrap();
    unrelated
        .change(Change::Write {
            key: key("credential/1"),
            version: version("auth", 1),
            end: None,
            data: Box::new(*b"serial 1"),
        })
        .unwrap();
    assert_eq!(unrelated.prepare(issued()), Err(Error::Prepared));
    // The control: the proposal that writes the issuance record at its version takes the artifact once.
    unrelated.read(Dependency::Absent(key("credential/9"))).unwrap();
    unrelated
        .change(Change::Write {
            key: key("credential/9"),
            version: version("auth", 9),
            end: None,
            data: Box::new(*b"serial 9"),
        })
        .unwrap();
    assert_eq!(unrelated.prepare(issued()), Ok(()));
    assert_eq!(unrelated.prepare(issued()), Err(Error::Prepared));
}

/// A cancel stops new calls, and the record stays until the application observes that the call completed or that
/// its resource came back. A later cancel does not undo the observation.
#[test]
fn a_cancelled_intent_keeps_its_record_until_its_completion_or_return_is_observed() {
    for ended in [Ended::Completed, Ended::Returned] {
        let mut intent = Intent::new(Effect::Signer, Box::new(*b"sign"));
        intent.cancel();
        assert_eq!(intent.state(), State::Cancelled);
        intent.observe(ended);
        assert_eq!(intent.state(), State::Ended(ended));
        intent.cancel();
        assert_eq!(intent.state(), State::Ended(ended));
    }
}
