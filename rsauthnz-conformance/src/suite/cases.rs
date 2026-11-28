//! The cases of the suite. Each one takes a new binding and gives `Err` with the check that failed.

use core::cmp::Ordering;
use core::num::NonZeroUsize;
use core::time::Duration;

use rsauthnz::limits::Limits;
use rsauthnz::store::journal::{self, Append, Body, End, Floor, History, Mark};
use rsauthnz::store::{
    Commit, CrashLoss, Expiry, Insert, Inserted, Instance, JournalWrite, intent_records, outcome_record, policy_key,
};
use rsauthnz::time::{Reading, ReadingSource};

use super::{
    Answer, Build, Checked, DATA, EFFECTS_MAX, Effect, Fault, Journal, Key, Kind, Lookup, Next, Outcome, PAGE, Plan,
    Proposal, Role, Run, Sequence, Status, Store, Subject, Ticket, account, after_commit, anchor, at_commit,
    audit_record, authority, both, commit_of, crashes, driver, ensure, failed, journaled, key, now, once, op, plan,
    replay_floor, same, sign_in, version,
};

/// The instance number of a start of `binding`.
async fn start<S: Subject>(binding: &mut S) -> Result<Instance, String> {
    binding.start().await.map_err(failed("start"))
}

/// The result of the commit of `proposal`.
async fn committed<S: Subject>(binding: &mut S, proposal: &Proposal, instance: Instance) -> Result<Commit, String> {
    binding.commit(proposal, instance).await.map_err(failed("commit"))
}

/// Whether the store holds the record `key`.
async fn holds<S: Subject>(binding: &mut S, key: &Key) -> Result<bool, String> {
    Ok(Store::read(binding, key).await.map_err(failed("read"))?.is_some())
}

/// Whether the store holds no record of the commit of `proposal`: no outcome record and no audit record.
async fn unrecorded<S: Subject>(binding: &mut S, proposal: &Proposal) -> Result<bool, String> {
    let outcome = binding
        .outcome(&proposal.operation().id)
        .await
        .map_err(failed("read"))?;
    let audit = holds(binding, &audit_record(proposal).0).await?;
    Ok(outcome.is_none() && !audit)
}

pub(super) async fn commit<S: Subject>(mut binding: S) -> Checked {
    let instance = start(&mut binding).await?;
    let ended = key(Kind::Credential, "c-1");
    let written = key(Kind::Credential, "c-2");
    let first = Build::new("w-1").writes(&ended, 1).done();
    ensure(
        committed(&mut binding, &first, instance).await? == Commit::Accepted,
        "a commit whose dependencies hold refused",
    )?;
    let second = Build::new("w-2").ends(&ended, 1).writes(&written, 1).intends().done();
    let mut reader = binding.clone();
    let (pair, commit) = both(
        reader.read_pair([&ended, &written]),
        committed(&mut binding, &second, instance),
    )
    .await;
    let [old, new] = pair.map_err(failed("read_pair"))?;
    ensure(
        old.is_some() != new.is_some(),
        "a paired read saw records from two sides of one commit",
    )?;
    ensure(commit? == Commit::Accepted, "a commit whose dependencies hold refused")?;
    let [record, removed] = binding
        .read_pair([&written, &ended])
        .await
        .map_err(failed("read_pair"))?;
    ensure(
        record.is_some_and(|record| record.version == version(1) && *record.data == *DATA),
        "a commit did not write its record",
    )?;
    ensure(removed.is_none(), "a commit did not end its record")?;
    let outcome = binding.outcome(&second.operation().id).await.map_err(failed("read"))?;
    ensure(
        outcome.as_ref() == Some(second.operation()),
        "a commit has no outcome record",
    )?;
    let (audit_key, audit) = audit_record(&second);
    let copies = binding
        .read_pair([&audit_key, &audit_key])
        .await
        .map_err(failed("read_pair"))?;
    ensure(
        copies.iter().all(|record| same(record.as_ref(), &audit)),
        "a paired read of one audit key did not give the committed audit twice",
    )?;
    for (intent_key, intent) in intent_records(&second).map_err(|error| error.to_string())? {
        let stored = Store::read(&mut binding, &intent_key).await.map_err(failed("read"))?;
        ensure(
            same(stored.as_ref(), &intent),
            "a commit did not write its intent record",
        )?;
    }
    ensure(
        committed(&mut binding, &second, instance).await? == Commit::Recorded(second.operation().clone()),
        "a second submission of a commit did not get its outcome record",
    )
}

pub(super) async fn dependency_conflict<S: Subject>(mut binding: S) -> Checked {
    let instance = start(&mut binding).await?;
    let policy = policy_key(&authority());
    let record = key(Kind::Grant, "g-1");
    let present = key(Kind::Credential, "c-1");
    let target = key(Kind::Credential, "c-2");
    for proposal in [
        Build::new("d-1")
            .writes(&policy, 1)
            .writes(&record, 1)
            .writes(&present, 1)
            .done(),
        Build::new("d-2").replaces(&policy, 1, 2).replaces(&record, 1, 2).done(),
    ] {
        ensure(
            committed(&mut binding, &proposal, instance).await? == Commit::Accepted,
            "a commit whose dependencies hold refused",
        )?;
    }
    let rows = [
        ("policy", Build::new("x-1").policy(1).writes(&target, 1)),
        ("version", Build::new("x-2").reads(&record, 1).writes(&target, 1)),
        ("absence", Build::new("x-3").writes(&present, 1)),
    ];
    for (kind, build) in rows {
        let proposal = build.done();
        ensure(
            committed(&mut binding, &proposal, instance).await? == Commit::Conflict,
            &format!("a commit whose {kind} dependency does not hold did not conflict"),
        )?;
        ensure(
            unrecorded(&mut binding, &proposal).await? && !holds(&mut binding, &target).await?,
            &format!("a commit that conflicted on its {kind} dependency wrote a record"),
        )?;
    }
    let holding = Build::new("x-4").policy(2).reads(&record, 2).writes(&target, 1).done();
    ensure(
        committed(&mut binding, &holding, instance).await? == Commit::Accepted,
        "a commit whose policy and version dependencies hold refused",
    )
}

pub(super) async fn deadline<S: Subject>(mut binding: S) -> Checked {
    let instance = start(&mut binding).await?;
    // The clock of the case reads `now`: 1,000 seconds with a bound of one second, so its latest time is 1,001.
    let latest = Duration::from_secs(1_001);
    let (first, second, third) = (
        key(Kind::Session, "t-1"),
        key(Kind::Session, "t-2"),
        key(Kind::Session, "t-3"),
    );
    let before = Build::new("t-1")
        .writes(&first, 1)
        .until(Duration::new(1_001, 1))
        .done();
    ensure(
        committed(&mut binding, &before, instance).await? == Commit::Accepted,
        "a commit before its deadline refused",
    )?;
    let at = Build::new("t-2").writes(&second, 1).until(latest).done();
    expires(&mut binding, &at, &second, instance, "at its deadline").await?;
    binding.set_clock(Reading::new(Duration::from_secs(1_000), None, ReadingSource::Caller));
    let unbounded = Build::new("t-3")
        .writes(&third, 1)
        .until(Duration::from_secs(3_600))
        .done();
    expires(&mut binding, &unbounded, &third, instance, "at a reading with no bound").await?;
    binding.set_clock(now());
    let again = Build::new("t-1").writes(&first, 1).until(latest).done();
    ensure(
        matches!(committed(&mut binding, &again, instance).await?, Commit::Recorded(_)),
        "a second submission after its deadline did not get its outcome record",
    )
}

/// Checks that the commit of `proposal`, which writes `written`, expires `when` and writes nothing.
async fn expires<S: Subject>(
    binding: &mut S,
    proposal: &Proposal,
    written: &Key,
    instance: Instance,
    when: &str,
) -> Checked {
    ensure(
        committed(binding, proposal, instance).await? == Commit::Expired,
        &format!("a commit {when} did not expire"),
    )?;
    ensure(
        unrecorded(binding, proposal).await? && !holds(binding, written).await?,
        &format!("a commit that expired {when} wrote a record"),
    )
}

/// The result of the replay insert of `insert`.
async fn inserted<S: Subject>(binding: &mut S, insert: &Insert) -> Result<Inserted, String> {
    binding.insert_replay(insert).await.map_err(failed("replay insert"))
}

/// The replay insert of the nonce `nonce` of the share `share`, of a signature created after the replay floor of a
/// start at `now`. Its deadline is 1,200 seconds, after the clock of the case, and its record ends at 1,300 seconds.
fn replay(share: u64, nonce: u64) -> Insert {
    let (mut share_digest, mut nonce_digest) = ([0; 32], [0; 32]);
    share_digest[..8].copy_from_slice(&share.to_be_bytes());
    nonce_digest[..8].copy_from_slice(&nonce.to_be_bytes());
    Insert::new(
        &share_digest,
        &nonce_digest,
        Duration::from_secs(1_300),
        Duration::from_secs(1_200),
        Duration::from_secs(1_100),
    )
}

pub(super) async fn replay_insert<S: Subject>(binding: S) -> Checked {
    // The driver starts at `now` and writes the replay floor of the instance.
    let mut run = Run::seeded(binding).await?;
    let first = replay(0, 0);
    ensure(
        inserted(&mut run.binding, &first).await? == Inserted::Accepted,
        "a replay insert after the floor, before its deadline, and within the capacity refused",
    )?;
    let stored = Store::read(&mut run.binding, first.key())
        .await
        .map_err(failed("read"))?;
    ensure(
        stored.is_some_and(|record| record.end == first.record().end),
        "a replay insert did not write its record with its end",
    )?;
    ensure(
        inserted(&mut run.binding, &first).await? == Inserted::Present,
        "a second replay insert of a key did not find its record",
    )?;
    // The clock passes the end of the record, so expiry removes it, and the deadline of the insert.
    run.binding.set_clock(Reading::new(
        Duration::from_secs(1_400),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    ));
    let removed = run
        .binding
        .expire(
            Kind::Signature,
            Duration::from_secs(1_399),
            NonZeroUsize::MIN,
            run.driver.instance().map_err(failed("serving instance"))?,
        )
        .await
        .map_err(failed("expire"))?;
    ensure(
        removed == Expiry::Removed(1) && !holds(&mut run.binding, first.key()).await?,
        "expiry did not remove an ended replay record",
    )?;
    ensure(
        inserted(&mut run.binding, &first).await? == Inserted::Expired,
        "a replay insert after its deadline did not refuse: a late insert accepts a signature twice",
    )?;
    ensure(
        !holds(&mut run.binding, first.key()).await?,
        "a replay insert after its deadline wrote its record",
    )?;
    run.binding.set_clock(now());
    // A start of the store, before the driver writes the replay floor of the new instance.
    start(&mut run.binding).await?;
    ensure(
        inserted(&mut run.binding, &replay(0, 1)).await? == Inserted::Floor,
        "a replay insert landed before the replay floor of its start",
    )
}

pub(super) async fn replay_capacity<S: Subject>(binding: S) -> Checked {
    let capacity = binding.declaration().signatures;
    let (share_max, records_max) = (
        u64::try_from(capacity.share_max).map_err(|_| "the share of the capacity has no 64-bit count")?,
        u64::try_from(capacity.records_max).map_err(|_| "the capacity has no 64-bit count")?,
    );
    let mut run = Run::seeded(binding).await?;
    // Each share holds `share_max` records, up to the capacity: the last share can hold fewer.
    let mut held = 0;
    let mut share = 0;
    while held < records_max {
        let records = share_max.min(records_max.saturating_sub(held));
        for nonce in 0..records {
            ensure(
                inserted(&mut run.binding, &replay(share, nonce)).await? == Inserted::Accepted,
                "a replay insert within the share and the capacity refused",
            )?;
        }
        if share == 0 {
            ensure(
                inserted(&mut run.binding, &replay(0, share_max)).await? == Inserted::Full,
                "a replay insert past the share of its key did not refuse",
            )?;
        }
        held = held.saturating_add(records);
        share = share.saturating_add(1);
    }
    ensure(
        inserted(&mut run.binding, &replay(share, 0)).await? == Inserted::Full,
        "a replay insert past the capacity did not refuse",
    )
}

pub(super) async fn concurrent_consumption<S: Subject>(mut binding: S) -> Checked {
    let instance = start(&mut binding).await?;
    let value = key(Kind::Invitation, "inv-1");
    let seed = Build::new("c-0").writes(&value, 1).done();
    ensure(
        committed(&mut binding, &seed, instance).await? == Commit::Accepted,
        "a commit whose dependencies hold refused",
    )?;
    // Each consumption reads the value at version 1, ends it, and creates its own credential.
    let proposals = ["c-1", "c-2"].map(|name| {
        Build::new(name)
            .ends(&value, 1)
            .writes(&key(Kind::Credential, name), 1)
            .done()
    });
    let mut other = binding.clone();
    let (first, second) = both(
        binding.commit(&proposals[0], instance),
        other.commit(&proposals[1], instance),
    )
    .await;
    let commits = [first.map_err(failed("commit"))?, second.map_err(failed("commit"))?];
    let accepted = commits.iter().filter(|commit| **commit == Commit::Accepted).count();
    ensure(
        accepted == 1 && commits.contains(&Commit::Conflict),
        "two consumptions of one value did not give one commit and one conflict",
    )?;
    let mut recorded = 0;
    for proposal in &proposals {
        recorded += usize::from(!unrecorded(&mut binding, proposal).await?);
    }
    ensure(recorded == 1, "two consumptions of one value wrote two outcome records")?;
    ensure(!holds(&mut binding, &value).await?, "a consumed value is still valid")
}

pub(super) async fn absence_race<S: Subject>(mut binding: S) -> Checked {
    let instance = start(&mut binding).await?;
    let grant = key(Kind::Grant, "g-1");
    let revoked = key(Kind::Grant, "g-1.revoked");
    let seed = Build::new("a-0").writes(&grant, 1).done();
    ensure(
        committed(&mut binding, &seed, instance).await? == Commit::Accepted,
        "a commit whose dependencies hold refused",
    )?;
    // The revocation writes the revocation record, and the change reads its absence. Their writes differ.
    let revocation = Build::new("a-1").reads(&grant, 1).writes(&revoked, 1).done();
    let change = Build::new("a-2").lacks(&revoked).replaces(&grant, 1, 2).done();
    let mut other = binding.clone();
    let (first, second) = both(binding.commit(&revocation, instance), other.commit(&change, instance)).await;
    let commits = [first.map_err(failed("commit"))?, second.map_err(failed("commit"))?];
    ensure(
        commits.iter().filter(|commit| **commit == Commit::Accepted).count() == 1,
        "a grant change and a revocation that read the absence of each other's write both committed, or neither did",
    )
}

pub(super) async fn expiry<S: Subject>(mut binding: S) -> Checked {
    let previous = start(&mut binding).await?;
    let instance = start(&mut binding).await?;
    let seconds = |s: u64| Some(Duration::from_secs(s));
    let rows = [
        (key(Kind::Session, "s-a"), seconds(10), false),
        (key(Kind::Session, "s-b"), seconds(20), false),
        (key(Kind::Session, "s-c"), seconds(25), true),
        (key(Kind::Session, "s-d"), None, true),
        (key(Kind::Grant, "g-a"), seconds(10), true),
    ];
    let mut build = Build::new("e-0");
    for (key, end, _) in &rows {
        build = build.writes_until(key, 1, *end);
    }
    ensure(
        committed(&mut binding, &build.done(), instance).await? == Commit::Accepted,
        "a commit whose dependencies hold refused",
    )?;
    let mut removed = Vec::new();
    ensure(
        matches!(
            rsauthnz::store::expire(&mut binding, now(), PAGE, previous).await,
            Err(rsauthnz::store::ExpiryError::Superseded)
        ),
        "a delayed expiry passed the new storage instance",
    )?;
    for _ in 0..4 {
        let count = binding
            .expire(Kind::Session, Duration::from_secs(25), NonZeroUsize::MIN, instance)
            .await
            .map_err(failed("expire"))?;
        let Expiry::Removed(count) = count else {
            return Err("expiry refused the current instance".into());
        };
        removed.push(count);
    }
    ensure(
        removed == [1, 1, 0, 0],
        "an expiry with a limit of one did not remove one ended record in each call",
    )?;
    for (key, _, kept) in &rows {
        ensure(
            holds(&mut binding, key).await? == *kept,
            "an expiry removed a record that did not end before its time, or of another kind",
        )?;
    }
    Ok(())
}

/// The keys of the range read of `prefix` after `after`, whose records hold what the suite wrote.
async fn ranged<S: Subject>(
    binding: &mut S,
    prefix: &Key,
    after: Option<&Key>,
    limit: NonZeroUsize,
) -> Result<Vec<Key>, String> {
    let records = binding.range(prefix, after, limit).await.map_err(failed("range"))?;
    ensure(
        records
            .iter()
            .all(|(_, record)| record.version == version(1) && *record.data == *DATA),
        "a range read did not give the records of its keys",
    )?;
    Ok(records.into_iter().map(|(key, _)| key).collect())
}

pub(super) async fn range<S: Subject>(mut binding: S) -> Checked {
    let instance = start(&mut binding).await?;
    // The administrator bindings of one authority, and the keys around its prefix: a shorter key before it, the binding
    // of the next authority, and a record of the next kind.
    let prefix = key(Kind::Administrator, "auth-1/");
    let inside = ["auth-1/a", "auth-1/b", "auth-1/c"].map(|id| key(Kind::Administrator, id));
    let before = key(Kind::Administrator, "auth-1");
    let outside = [
        before.clone(),
        key(Kind::Administrator, "auth-2/a"),
        key(Kind::Agent, "auth-1/a"),
    ];
    let mut build = Build::new("r-0");
    for key in inside.iter().chain(&outside) {
        build = build.writes(key, 1);
    }
    ensure(
        committed(&mut binding, &build.done(), instance).await? == Commit::Accepted,
        "a commit whose dependencies hold refused",
    )?;
    let two = NonZeroUsize::new(2).expect("two is not zero");
    ensure(
        ranged(&mut binding, &prefix, None, two).await? == inside[..2],
        "a range read did not give the first records of its prefix in key order, up to its limit",
    )?;
    ensure(
        ranged(&mut binding, &prefix, Some(&inside[1]), two).await? == inside[2..],
        "a range read gave a record at or before its key, or of another prefix",
    )?;
    ensure(
        ranged(&mut binding, &prefix, Some(&before), NonZeroUsize::MAX).await? == inside,
        "a range read gave a record of another prefix",
    )
}

/// Whether the store refused the old instance and wrote nothing.
async fn fenced<S: Subject>(binding: &mut S, proposal: &Proposal, instance: Instance) -> Result<bool, String> {
    Ok(committed(binding, proposal, instance).await? == Commit::Superseded && unrecorded(binding, proposal).await?)
}

pub(super) async fn fencing<S: Subject>(mut binding: S) -> Checked {
    let proposal = |name: &str| Build::new(name).writes(&key(Kind::Credential, name), 1).done();
    let first = start(&mut binding).await?;
    let mut current = start(&mut binding).await?;
    let mut rows = vec![("a start", first)];
    binding.restart();
    rows.push(("a restart", current));
    current = start(&mut binding).await?;
    if journaled(&binding.declaration()) {
        // The start after the snapshot begins a history that the restore abandons.
        let snapshot = binding.snapshot();
        let abandoned = start(&mut binding).await?;
        binding.restore(&snapshot);
        // The restored store takes commits before the next start, for example a delayed commit of an old process.
        for (index, (event, stale)) in [
            ("at the snapshot", current),
            ("of a start after the snapshot", abandoned),
        ]
        .into_iter()
        .enumerate()
        {
            ensure(
                fenced(&mut binding, &proposal(&format!("f-r{index}")), stale).await?,
                &format!(
                    "between a restore and the next start, a commit with the instance number {event} did not refuse"
                ),
            )?;
        }
        current = start(&mut binding).await?;
        rows.push(("a restore", abandoned));
    }
    for (index, (event, stale)) in rows.into_iter().enumerate() {
        ensure(
            fenced(&mut binding, &proposal(&format!("f-{index}")), stale).await?,
            &format!("after {event}, a commit with the instance number of an earlier start did not refuse"),
        )?;
    }
    ensure(
        committed(&mut binding, &proposal("f-current"), current).await? == Commit::Accepted,
        "a commit with the instance number of the latest start refused",
    )?;

    // A join reads the installed instance and writes none, so a commit of a peer in that instance still lands.
    let joined = binding.instance().await.map_err(failed("instance"))?;
    ensure(joined == current, "a join changed the installed instance")?;
    ensure(
        committed(&mut binding, &proposal("f-joined"), current).await? == Commit::Accepted,
        "after a join, a commit with the instance number of the latest start refused",
    )?;

    let journal = journaled(&binding.declaration());
    let mut old = Run::started(binding).await?;
    let first = proposal("f-first");
    let in_flight = old.submit(first, Plan::default())?;
    old.until_commit("f-first").await?;
    let queued = old.submit(proposal("f-queued"), Plan::default())?;
    let mut peer = Run::started(old.binding.clone()).await?;
    old.settle().await?;
    ensure(
        old.driver.status() == Status::Serving,
        "a peer that joined stopped a driver of the open instance",
    )?;
    for ticket in [in_flight, queued] {
        ensure(
            matches!(old.outcome(ticket).await?, Outcome::Accepted(_)),
            "a driver of the open instance lost a commit when a peer joined",
        )?;
    }
    peer.commit(proposal("f-peer"), Plan::default(), "the peer").await?;

    if journal {
        // An activation fences each driver of the earlier instance at the primary store and at the journal.
        let stale = proposal("f-stale");
        let original = stale.operation().clone();
        let in_flight = old.submit(stale, Plan::default())?;
        old.until_commit("f-stale").await?;
        let end = Build::new("f-end").ends(&key(Kind::Credential, "f-first"), 1).done();
        let ending = old.submit(end, Plan::default())?;
        peer.activate().await?;
        peer.serving()?;
        old.settle().await?;
        ensure(
            old.driver.status() == Status::Refused(driver::Error::Superseded),
            "a stale primary write kept its driver in service",
        )?;
        ensure(
            matches!(old.outcome(in_flight).await?, Outcome::Unknown(op) if op == original),
            "a superseded driver lost the original operation identity",
        )?;
        ensure(
            matches!(old.outcome(ending).await?, Outcome::Unknown(_)),
            "a queued operation crossed an activation",
        )?;

        // The end entry of a driver of the earlier instance, delayed across a later activation, refuses.
        let mut late = Run::started(peer.binding.clone()).await?;
        let end = Build::new("f-late").ends(&key(Kind::Credential, "f-peer"), 1).done();
        late.submit(end, Plan::default())?;
        late.steps(|effect| {
            if matches!(effect, Effect::Append(..)) {
                Next::Stop
            } else {
                Next::Run(None)
            }
        })
        .await?;
        let Some(Effect::Append(append, instance)) = late.driver.effect() else {
            return Err("the change of a fact issued no end entry".into());
        };
        peer.activate().await?;
        let result = peer
            .binding
            .append(append, instance)
            .await
            .map_err(failed("delayed append"))?;
        ensure(
            result == JournalWrite::Conflict,
            "an end entry of an earlier instance landed after an activation",
        )?;
        ensure(
            peer.holds(&key(Kind::Credential, "f-peer")).await?
                && !peer.holds(&key(Kind::Credential, "f-stale")).await?,
            "a stale operation changed the store after an activation",
        )?;
    }

    let before = proposal("f-before-start");
    let original = before.operation().clone();
    let queued = peer.submit(before, Plan::default())?;
    peer.start().await?;
    ensure(
        matches!(peer.outcome(queued).await?, Outcome::Unknown(op) if op == original),
        "a queued operation crossed a requested start",
    )?;
    ensure(
        !peer.holds(&key(Kind::Credential, "f-before-start")).await?,
        "a queued operation wrote a credential after a new start",
    )
}

pub(super) async fn servers<S: Subject>(binding: S) -> Checked {
    let mut first = Run::seeded(binding).await?;
    // A second driver joins the open instance: it installs none.
    let mut second = Run::new(first.binding.clone())?;
    second.driver.start(now());
    ensure(
        matches!(second.driver.effect(), Some(Effect::Instance)),
        "a second driver did not join the open instance",
    )?;
    second.settle().await?;
    second.serving()?;
    ensure(
        second.driver.instance() == first.driver.instance(),
        "two drivers of one store serve in two instances",
    )?;

    // A restart of either driver leaves the other one committing: the restart is a new driver that joins.
    for (index, restarts) in ["the second", "the first"].into_iter().enumerate() {
        let (holder, other) = if index == 0 {
            (&mut first, &mut second)
        } else {
            (&mut second, &mut first)
        };
        let name = format!("w-{index}");
        let ticket = holder.submit(
            Build::new(&name).writes(&key(Kind::Credential, &name), 1).done(),
            Plan::default(),
        )?;
        holder.until_commit(&name).await?;
        *other = Run::started(other.binding.clone()).await?;
        holder.settle().await?;
        ensure(
            matches!(holder.outcome(ticket).await?, Outcome::Accepted(_)),
            &format!("a restart of {restarts} driver stopped a commit of its peer"),
        )?;
    }

    // Two removals of the two sign-in methods of `a1` race on two drivers.
    let (a1p, a1q) = (key(Kind::Credential, "a1p"), key(Kind::Credential, "a1q"));
    let held = [anchor(&a1p, sign_in("a1")), anchor(&a1q, sign_in("a1"))];
    let race = first.submit(Build::new("r-1").ends(&a1p, 1).done(), plan(&held, &[], &[]))?;
    first.until_commit("r-1").await?;
    let lost = second.submit(Build::new("r-2").ends(&a1q, 1).done(), plan(&held, &[], &[]))?;
    second.settle().await?;
    ensure(
        matches!(second.outcome(lost).await?, Outcome::Conflict),
        "a removal entered an owner turn that a peer holds",
    )?;
    first.settle().await?;
    ensure(
        matches!(first.outcome(race).await?, Outcome::Accepted(_)),
        "the removal that holds the owner turn did not commit",
    )?;
    let retry = second.submit(
        Build::new("r-3").ends(&a1q, 1).done(),
        plan(&[anchor(&a1q, sign_in("a1"))], &[], &[]),
    )?;
    second.settle().await?;
    ensure(
        matches!(
            second.outcome(retry).await?,
            Outcome::Refused(rsauthnz::transition::Error::LastAnchor)
        ),
        "a removal ended the last sign-in method of an account",
    )?;
    ensure(
        second.holds(&a1q).await? && !second.holds(&a1p).await?,
        "the race of two removals left no sign-in method",
    )
}

/// The most that a store rounds up the end of an audit or outcome record: a store that keeps whole seconds.
const PRECISION_MAX: Duration = Duration::from_secs(1);

pub(super) async fn retention<S: Subject>(binding: S) -> Checked {
    let mut run = Run::started(binding).await?;
    let instance = run.driver.instance().map_err(failed("serving instance"))?;
    let credential = key(Kind::Credential, "t-1");
    let proposal = Build::new("t-1").writes(&credential, 1).done();
    let operation = proposal.operation().clone();
    ensure(
        matches!(run.lookup(&operation).await?, Lookup::Unknown),
        "a status read reported a decision before the first write",
    )?;
    let end = proposal
        .audit()
        .time
        .estimate()
        .saturating_add(run.binding.declaration().outcome_retention);
    let latest = end.saturating_add(PRECISION_MAX);
    let (audit_key, audit) = audit_record(&proposal);
    let outcome_key = outcome_record(&proposal).0;
    run.commit(proposal, Plan::default(), "the credential after a status read")
        .await?;
    for (key, what) in [(&audit_key, "audit"), (&outcome_key, "outcome")] {
        let stored = Store::read(&mut run.binding, key).await.map_err(failed("read"))?;
        ensure(
            stored.is_some_and(|record| record.end.is_some_and(|stored| end <= stored && stored <= latest)),
            &format!(
                "the {what} record does not end at the estimate of the audit time plus the outcome retention, rounded \
                 up by at most {PRECISION_MAX:?}"
            ),
        )?;
    }
    for kind in [Kind::Audit, Kind::Outcome] {
        run.binding
            .expire(kind, end, PAGE, instance)
            .await
            .map_err(failed("expire"))?;
    }
    let stored = Store::read(&mut run.binding, &audit_key)
        .await
        .map_err(failed("read"))?;
    ensure(
        same(stored.as_ref(), &audit),
        "an expire before the retention end removed the audit record",
    )?;
    ensure(
        matches!(run.lookup(&operation).await?, Lookup::Committed(receipt) if receipt.operation() == &operation.id),
        "a lookup lost the committed receipt at its retention end",
    )?;
    if let Some(after) = latest.checked_add(Duration::from_nanos(1)) {
        run.binding
            .expire(Kind::Outcome, after, PAGE, instance)
            .await
            .map_err(failed("expire"))?;
        ensure(
            !run.holds(&outcome_key).await? && run.holds(&credential).await?,
            "expiry did not remove the receipt and keep the issued credential",
        )?;
        ensure(
            matches!(run.lookup(&operation).await?, Lookup::Unknown),
            "a missing receipt gave a definite answer for a committed credential",
        )?;
    }
    Ok(())
}

pub(super) async fn lost_response<S: Subject>(mut binding: S) -> Checked {
    let instance = start(&mut binding).await?;
    let written = key(Kind::Credential, "l-1");
    let lost = Build::new("l-1").writes(&written, 1).done();
    binding.inject(Fault::LostResponse);
    ensure(
        binding.commit(&lost, instance).await.is_err(),
        "a commit whose response is lost gave a result",
    )?;
    let instance = start(&mut binding).await?;
    let outcome = binding.outcome(&lost.operation().id).await.map_err(failed("read"))?;
    ensure(
        outcome.as_ref() == Some(lost.operation()),
        "after a start, a commit whose response was lost has no outcome record",
    )?;
    let (audit_key, audit) = audit_record(&lost);
    let stored = Store::read(&mut binding, &audit_key).await.map_err(failed("read"))?;
    ensure(
        same(stored.as_ref(), &audit) && holds(&mut binding, &written).await?,
        "after a start, a commit whose response was lost has no audit record or no record",
    )?;
    ensure(
        committed(&mut binding, &lost, instance).await? == Commit::Recorded(lost.operation().clone()),
        "a second submission of a commit whose response was lost did not get its outcome record",
    )?;

    let crashed = Build::new("l-2").writes(&key(Kind::Credential, "l-2"), 1).done();
    binding.inject(Fault::CrashBeforeCommit);
    ensure(
        binding.commit(&crashed, instance).await.is_err(),
        "a commit that crashed before it landed gave a result",
    )?;
    start(&mut binding).await?;
    ensure(
        unrecorded(&mut binding, &crashed).await? && !holds(&mut binding, &key(Kind::Credential, "l-2")).await?,
        "a commit that crashed before it landed wrote a record",
    )
}

fn floor_append(after: Mark, name: &str, value: u64) -> Append {
    let body = Body::Floor(Floor {
        kind: Kind::Session,
        value,
    });
    after
        .next(&op(name), &body, Limits::default())
        .expect("the floor fits the journal form")
}

pub(super) async fn journal_fence<S: Subject>(mut binding: S) -> Checked {
    let old = start(&mut binding).await?;
    let left = floor_append(Mark::EMPTY, "left", 1);
    let right = floor_append(Mark::EMPTY, "right", 2);
    let mut peer = binding.clone();
    let (a, b) = both(binding.append(&left, old), peer.append(&right, old)).await;
    let (first, other) = match (a.map_err(failed("append"))?, b.map_err(failed("append"))?) {
        (JournalWrite::Accepted, JournalWrite::Conflict) => (&left, &right),
        (JournalWrite::Conflict, JournalWrite::Accepted) => (&right, &left),
        _ => return Err("one journal predecessor must have exactly one successor".into()),
    };
    let foreign = floor_append(other.head(), "foreign", 3);
    ensure(
        peer.append(&foreign, old).await.map_err(failed("append"))? == JournalWrite::Conflict,
        "the journal accepted a predecessor with the correct sequence and the wrong link",
    )?;
    ensure(
        binding.sync(old).await.map_err(failed("sync"))? == JournalWrite::Accepted,
        "the first sync refused",
    )?;
    let next = floor_append(first.head(), "next", 4);
    let current = start(&mut binding).await?;
    ensure(
        peer.append(&next, old).await.map_err(failed("append"))? == JournalWrite::Conflict,
        "the journal accepted an old writer at an unchanged head",
    )?;
    ensure(
        binding.append(&next, current).await.map_err(failed("append"))? == JournalWrite::Accepted,
        "the current writer could not extend the durable head",
    )?;
    ensure(
        peer.sync(old).await.map_err(failed("sync"))? == JournalWrite::Conflict,
        "the journal confirmed durability to a replaced writer",
    )?;
    ensure(
        binding.sync(current).await.map_err(failed("sync"))? == JournalWrite::Accepted,
        "the current writer could not sync its append",
    )?;
    let entries = Journal::read(&mut binding, Sequence(0), PAGE)
        .await
        .map_err(failed("journal read"))?;
    ensure(
        entries == [first.entry().clone(), next.entry().clone()],
        "the durable journal differs from the two accepted entries",
    )
}

pub(super) async fn failed_sync<S: Subject>(mut binding: S) -> Checked {
    let instance = start(&mut binding).await?;
    let first = floor_append(Mark::EMPTY, "first", 1);
    let second = floor_append(first.head(), "second", 2);
    ensure(
        binding.append(&first, instance).await.map_err(failed("append"))? == JournalWrite::Accepted,
        "the first append refused",
    )?;
    ensure(
        binding.sync(instance).await.map_err(failed("sync"))? == JournalWrite::Accepted,
        "the first sync refused",
    )?;
    ensure(
        binding.append(&second, instance).await.map_err(failed("append"))? == JournalWrite::Accepted,
        "the second append refused",
    )?;
    binding.inject(Fault::FailedSync);
    ensure(
        binding.sync(instance).await.is_err(),
        "a sync that failed returned success",
    )?;
    ensure(
        binding.sync(instance).await.is_err(),
        "a sync after a failed sync returned success before a start",
    )?;
    let proposal = Build::new("y-1").writes(&key(Kind::Credential, "y-1"), 1).done();
    ensure(
        binding.commit(&proposal, instance).await.is_err(),
        "a commit after a failed sync returned a result before a start",
    )?;
    let current = start(&mut binding).await?;
    let entries = Journal::read(&mut binding, Sequence(0), PAGE)
        .await
        .map_err(failed("read of the journal"))?;
    ensure(
        entries == core::slice::from_ref(first.entry()),
        "after a failed sync, the journal does not hold exactly the entries whose sync returned",
    )?;
    ensure(
        binding
            .append(&floor_append(first.head(), "third", 3), current)
            .await
            .map_err(failed("append"))?
            == JournalWrite::Accepted,
        "the append after a failed sync did not get the sequence after the last durable entry",
    )
}

pub(super) async fn restart<S: Subject>(binding: S) -> Checked {
    let mut run = Run::seeded(binding).await?;
    let (a1p, a1q, reg) = (
        key(Kind::Credential, "a1p"),
        key(Kind::Credential, "a1q"),
        key(Kind::Registration, "reg-1"),
    );
    let unlink = Build::new("u-1").ends(&a1q, 1).done();
    let operation = unlink.operation().clone();
    let held = [anchor(&a1p, sign_in("a1")), anchor(&a1q, sign_in("a1"))];
    run.commit(unlink, plan(&held, &[], &[]), "an unlink").await?;
    run.binding.restart();
    let declaration = run.binding.declaration();
    match declaration.crash_loss {
        CrashLoss::Unsynced => {
            run.start().await?;
            ensure(
                run.holds(&a1p).await? && !run.holds(&a1q).await? && run.holds(&reg).await?,
                "a restart lost a commit that the declaration keeps",
            )?;
            ensure(
                matches!(run.lookup(&operation).await?, Lookup::Committed(_)),
                "after a restart, a lookup does not report a commit that the store keeps",
            )
        }
        CrashLoss::Everything if journaled(&declaration) => {
            run.driver.start(now());
            run.settle().await?;
            ensure(
                run.driver.status() == Status::Refused(driver::Error::Restored),
                "a start after the loss of the store did not refuse: the store kept a state that its declaration loses",
            )?;
            run.activate().await?;
            run.serving()?;
            ensure(
                run.holds(&a1p).await? && !run.holds(&a1q).await?,
                "a restore after the loss of the store did not apply the journal",
            )?;
            ensure(
                !run.holds(&reg).await?,
                "a restart kept a record that the declaration loses",
            )?;
            ensure(
                matches!(run.lookup(&operation).await?, Lookup::Unknown),
                "after the loss of the store, a lookup of a lost outcome is not unknown",
            )
        }
        CrashLoss::Everything => {
            run.start().await?;
            ensure(
                !run.holds(&reg).await?,
                "a restart kept a record that the declaration loses",
            )
        }
    }
}

/// The enrollment `name` of `a1s` that consumes `reg-1`.
fn enrollment(name: &str) -> (Proposal, Plan) {
    let a1s = key(Kind::Credential, "a1s");
    let proposal = Build::new(name)
        .ends(&key(Kind::Registration, "reg-1"), 1)
        .writes(&a1s, 1)
        .done();
    (proposal, plan(&[], &[], &[(&a1s, sign_in("a1"))]))
}

/// Whether `history` holds an entry of `operation` whose body `matches` accepts.
fn has(history: &History, operation: &str, matches: impl Fn(&Body) -> bool) -> bool {
    let operation = op(operation);
    history
        .entries()
        .iter()
        .any(|entry| entry.operation == operation && matches(&entry.body))
}

/// The answer of `ticket` at the first moment that the driver gives it, and whether the creation entry of `created`
/// was durable at that moment.
async fn answered<S: Subject>(run: &mut Run<S>, ticket: Ticket, created: &str) -> Result<(Answer, bool), String> {
    let created = op(created);
    for _ in 0..EFFECTS_MAX {
        if let Some(answer) = run.driver.take(ticket) {
            let history = run.history().await?;
            let state = journal::replay(history.entries()).map_err(|error| error.to_string())?;
            return Ok((answer, state.acknowledges([&created])));
        }
        ensure(
            run.step(&mut |_| Next::Run(None)).await?,
            "the driver waits with no answer",
        )?;
    }
    Err(format!("the driver gave no answer in {EFFECTS_MAX} effects"))
}

pub(super) async fn crash_points<S: Subject>(binding: S) -> Checked {
    let mut run = Run::seeded(binding).await?;
    let (reg, a1s) = (key(Kind::Registration, "reg-1"), key(Kind::Credential, "a1s"));
    let ended = |history: &History| has(history, "e-1", |body| matches!(body, Body::End(_)));

    // cChecked: the sync of the end entry fails, so no entry is durable.
    let (proposal, plan_e) = enrollment("e-1");
    let operation = proposal.operation().clone();
    let ticket = run.submit(proposal, plan_e)?;
    run.drive(once(|effect| matches!(effect, Effect::Sync(_)), Fault::FailedSync))
        .await?;
    ensure(
        run.driver.status() == Status::Down,
        "cChecked: the driver serves after a failed sync",
    )?;
    ensure(
        matches!(run.outcome(ticket).await?, Outcome::Unknown(_)),
        "cChecked: a crash before the commit did not give an unknown outcome",
    )?;
    run.start().await?;
    let history = run.history().await?;
    ensure(!ended(&history), "cChecked: an end entry whose sync failed is durable")?;
    ensure(
        matches!(run.lookup(&operation).await?, Lookup::Unknown),
        "cChecked: a status read with no receipt reported a decision",
    )?;

    // cJournaled: a crash before the commit, after the durable end entry. The start voids the entry.
    let (proposal, plan_e) = enrollment("e-2");
    let operation = proposal.operation().clone();
    run.submit(proposal, plan_e)?;
    run.drive(at_commit("e-2", Fault::CrashBeforeCommit)).await?;
    run.start().await?;
    let history = run.history().await?;
    ensure(
        has(&history, "e-2", |body| matches!(body, Body::Void(_))),
        "cJournaled: the start did not void an end entry whose commit did not land",
    )?;
    ensure(
        matches!(run.lookup(&operation).await?, Lookup::Unknown) && run.holds(&reg).await? && !run.holds(&a1s).await?,
        "cJournaled: a commit that crashed before it landed changed the store",
    )?;

    // cCommitted: the commit lands and its response is lost. The next start writes the creation entry. A peer joins
    // while that append is in flight: it finishes the turn of the owner itself, and a lookup and an anchor change of
    // the owner are answered only after the creation entry.
    let (proposal, plan_e) = enrollment("e-3");
    let operation = proposal.operation().clone();
    run.submit(proposal, plan_e)?;
    run.drive(at_commit("e-3", Fault::LostResponse)).await?;
    run.driver.start(now());
    run.steps(|effect| {
        if matches!(effect, Effect::Append(..)) {
            Next::Stop
        } else {
            Next::Run(None)
        }
    })
    .await?;
    let profile = super::Profile::new(run.binding.declaration()).map_err(failed("profile"))?;
    let peer = super::Driver::new(profile, Limits::default(), &mut super::random()).map_err(failed("driver"))?;
    let mut old = core::mem::replace(&mut run.driver, peer);
    let Some(Effect::Append(append, instance)) = old.effect() else {
        return Err("recovery did not issue its pending creation append".into());
    };
    let mut pending = History::new(append.after());
    pending
        .extend(core::slice::from_ref(append.entry()), Limits::default())
        .map_err(failed("creation entry"))?;
    ensure(
        has(&pending, "e-3", |body| matches!(body, Body::Creation(_))),
        "recovery did not append the committed anchor",
    )?;
    // The peer joins the open instance, so the worker before it keeps its instance.
    run.driver.start(now());
    ensure(
        matches!(run.driver.effect(), Some(Effect::Instance)),
        "the peer did not join the open instance",
    )?;
    run.settle().await?;
    run.serving()?;
    let a1p = key(Kind::Credential, "a1p");
    let held = [
        anchor(&a1p, sign_in("a1")),
        anchor(&key(Kind::Credential, "a1q"), sign_in("a1")),
        anchor(&a1s, sign_in("a1")),
    ];
    let unlink = run.submit(Build::new("u-1").ends(&a1p, 1).done(), plan(&held, &[], &[]))?;
    let (answer, created) = answered(&mut run, unlink, "e-3").await?;
    ensure(
        created && matches!(answer, Answer::Outcome(Outcome::Accepted(_))),
        &format!(
            "cCommitted: an anchor change of the owner was answered before the creation entry of its anchor commit: \
             {answer:?}"
        ),
    )?;
    let lookup = run
        .driver
        .lookup(operation)
        .map_err(|error| format!("the driver refused a lookup: {error}"))?;
    let (answer, created) = answered(&mut run, lookup, "e-3").await?;
    ensure(
        created && matches!(answer, Answer::Lookup(Lookup::Committed(_))),
        "cCommitted: a lookup did not report the commit after its creation entry",
    )?;
    // The delayed append of the earlier worker is at a head that the peer moved, so it refuses, and the worker
    // finds the creation entry of the peer and appends none.
    let result = run
        .binding
        .append(append, instance)
        .await
        .map_err(failed("delayed recovery append"))?;
    ensure(
        result == JournalWrite::Conflict,
        "a delayed creation append landed at a head that a peer moved",
    )?;
    old.give(super::Output::Appended(result))
        .map_err(failed("recovery output"))?;
    while let Some(effect) = old.effect() {
        let output = super::execute(&mut run.binding, effect).await;
        old.give(output).map_err(failed("recovery output"))?;
    }
    ensure(
        old.status() == Status::Serving,
        "a worker stopped at a conflict with the entries of a peer",
    )?;
    let history = run.history().await?;
    let creations = history
        .entries()
        .iter()
        .filter(|entry| entry.operation == op("e-3") && matches!(entry.body, Body::Creation(_)))
        .count();
    ensure(
        creations == 1,
        "the journal holds the creation entry of one commit twice",
    )?;
    run.serving()?;
    ensure(
        run.holds(&a1s).await? && !run.holds(&reg).await?,
        "cCommitted: a commit whose response was lost did not land",
    )?;

    // cCreated: a crash after the creation entry of an anchor commit with no consumption, before the end of its
    // journal intent. The answer stands, and the start ends the intent.
    let a1d = key(Kind::Recovery, "a1d");
    let proposal = Build::new("i-1").writes(&a1d, 1).done();
    let operation = proposal.operation().clone();
    let ticket = run.submit(proposal, plan(&[], &[], &[(&a1d, Role::Recovery(account("a1")))]))?;
    run.drive(after_commit(
        "i-1",
        |effect| matches!(effect, Effect::Commit(..)),
        Fault::CrashBeforeCommit,
    ))
    .await?;
    ensure(
        run.driver.status() == Status::Down,
        "cCreated: the crash did not stop the driver",
    )?;
    run.start().await?;
    ensure(
        matches!(run.outcome(ticket).await?, Outcome::Accepted(_)),
        "cCreated: a commit with a durable creation entry was not accepted",
    )?;
    let prefix = Kind::Intent.key(&[]).expect("a key of one byte is valid");
    let intents = run.binding.range(&prefix, None, PAGE).await.map_err(failed("range"))?;
    ensure(
        intents.is_empty(),
        "cCreated: the start did not end the journal intent of a commit with a durable creation entry",
    )?;
    ensure(
        matches!(run.lookup(&operation).await?, Lookup::Committed(_)),
        "cCreated: a lookup did not report the commit",
    )
}

/// The unlink `name` of the passkey `a1q` of `a1`, which the store holds with `a1p` at version 1.
fn unlink_a1q(name: &str) -> (Proposal, Plan) {
    let (a1p, a1q) = (key(Kind::Credential, "a1p"), key(Kind::Credential, "a1q"));
    let held = [anchor(&a1p, sign_in("a1")), anchor(&a1q, sign_in("a1"))];
    (Build::new(name).ends(&a1q, 1).done(), plan(&held, &[], &[]))
}

pub(super) async fn refusal_void<S: Subject>(binding: S) -> Checked {
    let crash = crashes(&binding.declaration());
    let mut run = Run::seeded(binding).await?;
    let a1q = key(Kind::Credential, "a1q");
    let snapshot = run.binding.snapshot();
    // The passkey changes to version 2 with no journal entry, so an unlink that read version 1 conflicts.
    let mut rows = vec![("u-1", None)];
    if crash {
        rows.push(("u-2", Some(Fault::CrashAfterAppend)));
    }
    for (index, (name, fault)) in rows.into_iter().enumerate() {
        let change = Build::new(&format!("v-{index}")).replaces(&a1q, 1, 2).done();
        run.commit(change, Plan::default(), "a change of a passkey").await?;
        let (proposal, plan_u) = unlink_a1q(name);
        let ticket = run.submit(proposal, plan_u)?;
        match fault {
            None => {
                run.settle().await?;
                ensure(
                    matches!(run.outcome(ticket).await?, Outcome::Conflict),
                    "an unlink whose dependency changed did not conflict",
                )?;
                run.restore(&snapshot).await?;
                ensure(
                    run.holds(&a1q).await?,
                    "a restore applied the end entry of an unlink that returned its refusal",
                )?;
            }
            Some(fault) => {
                // The crash stops the void of the refusal.
                run.drive(after_commit(name, |effect| matches!(effect, Effect::Append(..)), fault))
                    .await?;
                ensure(
                    matches!(run.outcome(ticket).await?, Outcome::Unknown(_)),
                    "a refusal whose void was not durable reached its client",
                )?;
                run.start().await?;
            }
        }
    }
    Ok(())
}

pub(super) async fn restore_journal<S: Subject>(binding: S) -> Checked {
    let mut run = Run::seeded(binding).await?;
    let floor = Store::read(&mut run.binding, &replay_floor())
        .await
        .map_err(failed("read"))?;
    let snapshot = run.binding.snapshot();
    let (a1q, session, grant, invitation) = (
        key(Kind::Credential, "a1q"),
        key(Kind::Session, "s-1"),
        key(Kind::Grant, "g-1"),
        key(Kind::Invitation, "inv-1"),
    );
    let (unlink, plan_u) = unlink_a1q("u-1");
    let operation = unlink.operation().clone();
    run.commit(unlink, plan_u, "an unlink").await?;
    let revocation = Build::new("r-1").ends(&session, 1).done();
    run.commit(revocation, Plan::default(), "a revocation of a session")
        .await?;
    let change = Build::new("g-2").replaces(&grant, 1, 2).done();
    run.commit(change, plan(&[], &[&grant], &[]), "a grant change").await?;
    let revocation = Build::new("r-2").ends(&invitation, 1).done();
    run.commit(revocation, Plan::default(), "a revocation of an invitation")
        .await?;

    run.binding.restore(&snapshot);
    run.driver.restore(now()).map_err(failed("restore"))?;
    let mut cleanup = false;
    let mut closing = false;
    run.steps(|effect| {
        match effect {
            Effect::Expire(..) => cleanup = true,
            Effect::Commit(proposal, _) if cleanup && proposal.audit().action.value() == "store.mark" => closing = true,
            Effect::Sync(_) if closing => return Next::Stop,
            _ => {}
        }
        Next::Run(None)
    })
    .await?;
    ensure(
        matches!(run.driver.effect(), Some(Effect::Sync(_))),
        "restore did not reach its final journal sync",
    )?;
    let signature = replay(1, 2);
    ensure(
        inserted(&mut run.binding, &signature).await? == Inserted::Floor,
        "a signed request committed before the final journal sync of a restore",
    )?;
    run.step(&mut |_| Next::Run(None)).await?;
    let mut replacement = Run::started(run.binding.clone()).await?;
    run.settle().await?;
    ensure(
        run.driver.status() == Status::Refused(driver::Error::Superseded),
        "the old restore opened admission after its replacement started",
    )?;
    let earlier = Insert::new(
        &[1; 32],
        &[2; 32],
        Duration::from_secs(1_300),
        signature.deadline(),
        now().estimate(),
    );
    ensure(
        inserted(&mut replacement.binding, &earlier).await? == Inserted::Floor,
        "the replacement admitted a signature from before recovery",
    )?;
    ensure(
        inserted(&mut replacement.binding, &signature).await? == Inserted::Accepted,
        "the replacement did not open admission after recovery",
    )?;
    let mut run = replacement;
    for (key, what) in [
        (&a1q, "the passkey of an unlink"),
        (&session, "a revoked session"),
        (&grant, "the grant revision that a change replaced"),
        (&invitation, "a revoked invitation"),
    ] {
        ensure(
            !run.holds(key).await?,
            &format!("{what} after the snapshot is valid again after a restore"),
        )?;
    }
    let restored = Store::read(&mut run.binding, &replay_floor())
        .await
        .map_err(failed("read"))?;
    let raised = match (&floor, &restored) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(floor), Some(restored)) => restored.version.compare(&floor.version) == Ok(Ordering::Greater),
    };
    ensure(raised, "a restore did not set the replay floor")?;
    ensure(
        matches!(run.lookup(&operation).await?, Lookup::Unknown),
        "after a restore, a lookup of an outcome that the snapshot lacks is not unknown",
    )
}

/// The commit `name` of a new session with the next value of the session counter, and that value.
async fn release<S: Subject>(run: &mut Run<S>, name: &str) -> Result<u64, String> {
    let value = run
        .driver
        .allocate()
        .map_err(|error| format!("the driver gave no counter value: {error}"))?;
    let proposal = Build::new(name).writes(&key(Kind::Session, name), value).done();
    run.commit(proposal, Plan::default(), "a session").await?;
    Ok(value)
}

pub(super) async fn restore_floors<S: Subject>(binding: S) -> Checked {
    let mut run = Run::seeded(binding).await?;
    let older = run.binding.snapshot();
    let mut released = vec![release(&mut run, "f-1").await?];
    let newer = run.binding.snapshot();
    run.restore(&older).await?;
    released.push(release(&mut run, "f-2").await?);
    run.restore(&newer).await?;
    released.push(release(&mut run, "f-3").await?);
    ensure(
        released.array_windows().all(|[earlier, later]| earlier < later),
        "a restore released a counter value that an earlier commit released",
    )
}

pub(super) async fn restore_refusal<S: Subject>(make: &mut impl FnMut() -> S) -> Checked {
    for (loss, gap) in [("a gap", true), ("the loss of the journal before a later entry", false)] {
        let mut run = Run::seeded(make()).await?;
        let head = run.history().await?.head().sequence;
        let snapshot = run.binding.snapshot();
        let (unlink, plan_u) = unlink_a1q("u-1");
        run.commit(unlink, plan_u, "an unlink").await?;
        let revocation = Build::new("r-1").ends(&key(Kind::Session, "s-1"), 1).done();
        run.commit(revocation, Plan::default(), "a revocation of a session")
            .await?;
        let lost = Sequence(head.0.saturating_add(1));
        if gap {
            run.binding.lose(lost..=lost);
        } else {
            run.binding.lose(..=lost);
        }
        run.binding.restore(&snapshot);
        run.activate().await?;
        ensure(
            matches!(
                run.driver.status(),
                Status::Refused(driver::Error::Journal(journal::Error::Missing(_)))
            ),
            &format!("a restore with {loss} after the mark of its snapshot did not refuse"),
        )?;
    }
    Ok(())
}

pub(super) async fn restore_anchors<S: Subject>(binding: S) -> Checked {
    let crash = crashes(&binding.declaration());
    let mut run = Run::seeded(binding).await?;
    let (a4p, a4s, reg) = (
        key(Kind::Credential, "a4p"),
        key(Kind::Credential, "a4s"),
        key(Kind::Registration, "reg-4"),
    );
    let snapshot = run.binding.snapshot();
    // The account has one passkey. An enrollment and an unlink of the first passkey overlap: the unlink keeps the
    // enrolled passkey.
    let enroll = run.submit(
        Build::new("e-4").ends(&reg, 1).writes(&a4s, 1).done(),
        plan(&[], &[], &[(&a4s, sign_in("a4"))]),
    )?;
    let unlink = run.submit(
        Build::new("u-4").ends(&a4p, 1).done(),
        plan(&[anchor(&a4p, sign_in("a4"))], &[], &[]),
    )?;
    run.settle().await?;
    for ticket in [enroll, unlink] {
        ensure(
            matches!(run.outcome(ticket).await?, Outcome::Accepted(_)),
            "an enrollment, or an unlink that keeps the enrolled passkey, did not commit",
        )?;
    }
    run.restore(&snapshot).await?;
    ensure(
        run.holds(&a4s).await?,
        "a restore lost an anchor that an acknowledged commit saw: the account has no sign-in method",
    )?;
    ensure(
        !run.holds(&a4p).await?,
        "a restore made an unlinked passkey valid again",
    )?;
    if crash {
        // An anchor commit with no consumption crashes before its commit lands.
        let snapshot = run.binding.snapshot();
        let a4d = key(Kind::Recovery, "a4d");
        run.submit(
            Build::new("i-4").writes(&a4d, 1).done(),
            plan(&[], &[], &[(&a4d, Role::Recovery(account("a4")))]),
        )?;
        run.drive(at_commit("i-4", Fault::CrashBeforeCommit)).await?;
        run.restore(&snapshot).await?;
        ensure(
            !run.holds(&a4d).await?,
            "a restore created an anchor whose commit did not land",
        )?;
    }
    Ok(())
}

pub(super) async fn restore_completions<S: Subject>(binding: S) -> Checked {
    let mut run = Run::seeded(binding).await?;
    let rows = [
        (
            "c-boot",
            key(Kind::Bootstrap, "b-1"),
            key(Kind::Administrator, "adm-1"),
            Role::Administrator(authority()),
            None,
        ),
        (
            "c-recover",
            key(Kind::Recovery, "a2c"),
            key(Kind::Credential, "a2n"),
            sign_in("a2"),
            Some(key(Kind::Credential, "a2p")),
        ),
        (
            "c-invite",
            key(Kind::Invitation, "inv-1"),
            key(Kind::Credential, "a3p"),
            sign_in("a3"),
            None,
        ),
        (
            "c-enroll",
            key(Kind::Registration, "reg-1"),
            key(Kind::Credential, "a1s"),
            sign_in("a1"),
            None,
        ),
    ];
    for (name, value, created, role, retired) in rows {
        let snapshot = run.binding.snapshot();
        let mut build = Build::new(name).ends(&value, 1);
        if let Some(retired) = &retired {
            build = build.ends(retired, 1);
        }
        let proposal = build.writes(&created, 1).done();
        let operation = proposal.operation().clone();
        run.submit(proposal, plan(&[], &[], &[(&created, role)]))?;
        // The commit lands, and the crash comes before its creation entry.
        run.drive(at_commit(name, Fault::LostResponse)).await?;
        run.binding.restore(&snapshot);
        run.driver
            .restore(now())
            .map_err(|error| format!("the driver refused the restore: {error}"))?;
        let user = format!("x-{name}");
        run.submit(
            Build::new(&user).writes(&key(Kind::Session, &user), 1).done(),
            Plan::default(),
        )?;
        let (completion, user) = (op(name), op(&user));
        let (mut completed, mut early) = (false, false);
        run.drive(|effect| {
            completed |= commit_of(effect, &completion);
            early |= !completed && commit_of(effect, &user);
            None
        })
        .await?;
        run.serving()?;
        ensure(
            completed && !early,
            &format!("{name}: the restored store served before it completed an in-doubt consumption"),
        )?;
        ensure(
            run.holds(&created).await? && !run.holds(&value).await?,
            &format!("{name}: a restore did not complete an in-doubt consumption"),
        )?;
        if let Some(retired) = &retired {
            ensure(
                !run.holds(retired).await?,
                &format!("{name}: a completion did not retire the displaced passkey"),
            )?;
        }
        ensure(
            matches!(run.lookup(&operation).await?, Lookup::Committed(_)),
            &format!("{name}: a lookup did not report the completed consumption"),
        )?;
        // A second restore of the same snapshot completes nothing again: the creation entry keeps the anchor.
        run.binding.restore(&snapshot);
        run.driver
            .restore(now())
            .map_err(|error| format!("the driver refused the restore: {error}"))?;
        let mut again = false;
        run.drive(|effect| {
            again |= commit_of(effect, &completion);
            None
        })
        .await?;
        run.serving()?;
        ensure(
            !again && run.holds(&created).await?,
            &format!("{name}: a second restore completed a consumption again, or lost its anchor"),
        )?;
    }

    // A crash during the completions: the next start completes the rest before it serves.
    let (a4s, reg) = (key(Kind::Credential, "a4s"), key(Kind::Registration, "reg-4"));
    let snapshot = run.binding.snapshot();
    let proposal = Build::new("c-crash").ends(&reg, 1).writes(&a4s, 1).done();
    let operation = proposal.operation().clone();
    run.submit(proposal, plan(&[], &[], &[(&a4s, sign_in("a4"))]))?;
    run.drive(at_commit("c-crash", Fault::LostResponse)).await?;
    run.binding.restore(&snapshot);
    run.driver
        .restore(now())
        .map_err(|error| format!("the driver refused the restore: {error}"))?;
    run.drive(at_commit("c-crash", Fault::CrashBeforeCommit)).await?;
    ensure(
        run.driver.status() == Status::Down,
        "the crash during a completion did not stop the driver",
    )?;
    run.start().await?;
    ensure(
        run.holds(&a4s).await? && matches!(run.lookup(&operation).await?, Lookup::Committed(_)),
        "after a crash during the completions, the next start did not complete the in-doubt consumption",
    )
}

pub(super) async fn restore_ends<S: Subject>(binding: S) -> Checked {
    let mut run = Run::seeded(binding).await?;
    let (challenge, approval) = (key(Kind::SignIn, "ch-1"), key(Kind::Approval, "ap-1"));
    let (proposal, plan_e) = enrollment("e-1");
    run.commit(proposal, plan_e, "an enrollment").await?;
    let snapshot = run.binding.snapshot();
    let sign_in_commit = Build::new("s-in")
        .ends(&challenge, 1)
        .writes(&key(Kind::Session, "s-2"), 1)
        .done();
    run.commit(sign_in_commit, Plan::default(), "a sign-in").await?;
    let history = run.history().await?;
    ensure(
        !has(&history, "s-in", |_| true),
        "a consumption of a sign-in challenge wrote a journal entry",
    )?;
    ensure(
        has(&history, "e-1", |body| {
            matches!(
                body,
                Body::End(End {
                    consumption: Some(_),
                    ..
                })
            )
        }),
        "an enrollment that consumes its ceremony wrote no consumption entry",
    )?;
    run.binding.restore(&snapshot);
    run.driver.restore(now()).map_err(failed("restore"))?;
    run.steps(|effect| match effect {
        Effect::Expire(Kind::SignIn, ..) => Next::Stop,
        _ => Next::Run(None),
    })
    .await?;
    ensure(
        matches!(run.driver.effect(), Some(Effect::Expire(Kind::SignIn, ..))),
        "restore did not request sign-in cleanup",
    )?;
    let signature = replay(0, 1);
    ensure(
        inserted(&mut run.binding, &signature).await? == Inserted::Floor,
        "a signed request committed while old sign-in challenges still awaited cleanup",
    )?;
    let mut replacement = Run::started(run.binding.clone()).await?;
    ensure(
        inserted(&mut replacement.binding, &signature).await? == Inserted::Accepted,
        "a signed request that waited for recovery could not commit after admission opened",
    )?;
    let fresh = key(Kind::SignIn, "new-challenge");
    let proposal = Build::new("fresh-challenge")
        .writes_until(&fresh, 1, Some(Duration::from_secs(2_000)))
        .done();
    replacement
        .commit(proposal, Plan::default(), "a sign-in challenge after restore")
        .await?;
    run.settle().await?;
    ensure(
        run.driver.status() == Status::Refused(driver::Error::Superseded) && replacement.holds(&fresh).await?,
        "a replaced restore worker continued or removed the new sign-in challenge",
    )?;
    for (index, value) in [challenge, approval].iter().enumerate() {
        let name = format!("p-{index}");
        let proposal = Build::new(&name)
            .ends(value, 1)
            .writes(&key(Kind::Session, &name), 1)
            .done();
        let ticket = replacement.submit(proposal, Plan::default())?;
        replacement.settle().await?;
        ensure(
            matches!(replacement.outcome(ticket).await?, Outcome::Conflict),
            "after a restore, a pending sign-in challenge or approval from the snapshot did not refuse",
        )?;
    }
    replacement.start().await?;
    ensure(
        replacement.holds(&fresh).await?,
        "an ordinary start after recovery removed a fresh sign-in challenge",
    )
}

pub(super) async fn start_after_restore<S: Subject>(binding: S) -> Checked {
    let mut run = Run::seeded(binding).await?;
    let a1q = key(Kind::Credential, "a1q");
    let (unlink, plan_u) = unlink_a1q("u-1");
    let ticket = run.submit(unlink, plan_u)?;
    // The snapshot holds the state after the durable end entry, before the commit.
    run.until_commit("u-1").await?;
    let snapshot = run.binding.snapshot();
    run.settle().await?;
    ensure(
        matches!(run.outcome(ticket).await?, Outcome::Accepted(_)),
        "an unlink did not commit",
    )?;
    run.restore(&snapshot).await?;
    ensure(
        !run.holds(&a1q).await?,
        "a restore did not apply the end entry of an unlink that landed after the snapshot",
    )?;
    run.start().await?;
    let history = run.history().await?;
    ensure(
        !has(&history, "u-1", |body| matches!(body, Body::Void(_))),
        "a start after a restore voided an entry that the restore applied",
    )?;
    run.restore(&snapshot).await?;
    ensure(
        !run.holds(&a1q).await?,
        "a second restore made the passkey of an unlink valid again",
    )
}

pub(super) async fn alpha_upgrade<S: Subject>(make: &mut impl FnMut() -> S) -> Checked {
    use rsauthnz::cbor::{self, Value};
    use rsauthnz::id::{AuthorityVersion, Id};
    use rsauthnz::store::driver::AlphaSource;
    use rsauthnz::transition::Change;

    let mark = key(Kind::Mark, "");
    let passkey = key(Kind::Credential, "alpha-passkey");
    let approval = key(Kind::Approval, "alpha-approval");
    let form = Value::Array(vec![
        Value::Text("rsauthnz.store.mark.1"),
        Value::Unsigned(0),
        Value::Bytes(&[0; 32]),
        Value::Bool(true),
        Value::Unsigned(1),
        Value::Array(vec![]),
        Value::Array(vec![]),
    ]);
    let bytes = cbor::encode(&form, Limits::default()).map_err(failed("alpha mark"))?;
    let owner = Id::new("rsauthnz", "driver").map_err(failed("mark owner"))?;
    let first = AuthorityVersion::new(owner, &1u64.to_be_bytes()).map_err(failed("mark version"))?;
    let seed = Build::new("alpha-seed")
        .lacks(&mark)
        .change(Change::Write {
            key: mark.clone(),
            version: first,
            end: None,
            data: bytes.into_boxed_slice(),
        })
        .writes(&passkey, 1)
        .writes_until(&approval, 1, Some(super::LATER))
        .done();
    let unlink = Build::new("alpha-unlink").ends(&passkey, 1).done();
    let end = journal::entries(&unlink, &[], &[])
        .map_err(failed("unlink entry"))?
        .end
        .ok_or("missing unlink entry")?;
    let append = Mark::EMPTY
        .next(&unlink.operation().id, &Body::End(end), Limits::default())
        .map_err(failed("unlink entry"))?;

    for source in [None, Some(AlphaSource::Intact), Some(AlphaSource::Snapshot)] {
        let mut run = Run::new(make())?;
        let initial = start(&mut run.binding).await?;
        ensure(
            committed(&mut run.binding, &seed, initial).await? == Commit::Accepted,
            "alpha setup refused",
        )?;
        if source.is_some() {
            ensure(
                run.binding.append(&append, initial).await.map_err(failed("append"))? == JournalWrite::Accepted,
                "alpha journal append refused",
            )?;
            ensure(
                run.binding.sync(initial).await.map_err(failed("sync"))? == JournalWrite::Accepted,
                "alpha journal sync refused",
            )?;
        }
        run.driver.start(now());
        run.settle().await?;
        if let Some(source) = source {
            let Status::Refused(driver::Error::AlphaReview {
                instance,
                sequence: Sequence(1),
            }) = run.driver.status()
            else {
                return Err("the upgrade did not identify the disputed unlink".into());
            };
            ensure(
                run.holds(&passkey).await? && run.holds(&approval).await?,
                "review changed the credential or approval",
            )?;
            ensure(
                inserted(&mut run.binding, &replay(1, 0)).await? == Inserted::Floor,
                "review admitted a signed request",
            )?;
            run.driver
                .resolve_alpha(instance, source, now())
                .map_err(failed("alpha review"))?;
            run.settle().await?;
        }
        run.serving()?;
        ensure(
            run.holds(&passkey).await? == (source != Some(AlphaSource::Snapshot)),
            "upgrade applied the wrong credential decision",
        )?;
        ensure(
            run.holds(&approval).await? == (source == Some(AlphaSource::Intact)),
            "upgrade applied the wrong ceremony cleanup",
        )?;
        ensure(
            inserted(&mut run.binding, &replay(1, 0)).await? == Inserted::Accepted,
            "the upgraded store did not reopen replay admission",
        )?;
    }
    Ok(())
}
