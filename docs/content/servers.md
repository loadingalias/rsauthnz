# Run several servers on one store

Several application servers can each run a commit driver on one store. Each server commits directly to the store,
and no application service orders their writes. A server that starts or restarts leaves its peers serving.

This page gives the setup, the behavior that changes when servers share a store, the recovery of a lost reply, the
upgrade from the single-driver contract, and the cost of each shared operation. [Storage contract](storage.md) gives
the primitives, and [The commit driver](restore.md#the-commit-driver) gives each effect of the driver.

## Start a server

Each server makes its own driver on its own handle of the binding, with its own random generator. The generator gives
the driver an identity, so the internal operations of two drivers never share an identity.

1. Make the driver: `Driver::new(profile, limits, &mut random)`.
2. Call `driver.start(now)`, and execute the effects until the driver waits. `driver.status()` gives
   `Status::Serving`.
3. Submit, look up, and recover operations on this driver only. A driver is not shared between servers.

The start reads the installed instance (`Store::instance`) and the replay floor:

| The store | The start |
| --- | --- |
| The floor names the installed instance | Joins it with no write of an instance. Each peer keeps serving |
| No instance yet, or no floor: a new store, or a store that lost its state | Activates a new instance (`Store::start`), reconciles, and publishes the floor |
| The floor names an earlier instance: an activation or a restore did not finish | Activates a new instance, which fences the worker before it, and resumes its recorded recovery |

Two starts during one recovery fence each other. Each one resumes from the durable progress of the other, so the
recovery ends when the starts stop. After a restore of a snapshot, call `driver.restore(now)` on one server. Its new
instance fences the other servers: their next commit gives `Outcome::Unknown`, and the driver stops with
`Error::Superseded`. Call `driver.start(now)` on each of them. Each one joins the restored store.

## What changes when servers share a store

- **A crash of one server.** The next start of that driver settles the work of the operation that the crash cut: it
  finishes or retires its owner turn, writes its creation entry, or closes and voids a change that did not commit. A
  new driver of a server that lost its process knows no earlier operation, so its peers settle that work.
- **Anchor changes of one owner.** An anchor change, such as an enrollment or the removal of a passkey, holds the turn
  of each owner of its anchors (`Kind::Turn`). A second change of the same account on any server gets
  `Outcome::Conflict` while the first one holds the turn. Propose it again. The last-anchor check reads the journal
  under the turn, so two servers cannot remove the last two sign-in methods of one account.
- **A stopped holder.** A turn whose change committed, or whose operation recovery closed, gets help at once. A held
  turn of a change that did not commit gets help after `TURN_PATIENCE` (30 seconds) after the latest audit time of
  the change: the helper retires the turn, so the commit of the change refuses, and voids the change. A slow change
  that a helper retires refuses, which is safe.
- **Counter values.** Each driver gives values only from its own blocks, which the journal reserves before any use.
  `driver.allocate()` gives a value for a new record. `driver.allocate_after(&previous)` gives a value above the
  version `previous` for the next version of a record, because a peer can have written that version from a later
  block. `Error::Exhausted` (recovery `Restart`) means that no reserved value is left: the driver reserves a block in
  the background, so retry the request.
- **A record that a key names again.** A grant, an agent identity, or a removal mark can name a record again after
  its end. A new record of such a key needs a version above the dead version that the journal holds for the key. A
  lower version gives `Outcome::Conflict`, and the next allocation is above it.
- **The mark.** A move of the mark passes no entry of an operation that holds a turn. An end entry of a peer that
  holds the mark at two moves of the mark, at least `TURN_PATIENCE` apart, belongs to a server that stopped: that
  move closes the operation and voids its entry.

## Recover a lost reply

A server that loses the reply of a commit, or a peer that takes the request after it, recovers the original
operation. A status read never closes an operation, so only recovery gives a fresh-attempt answer.

1. Before the submission, take the recovery handle: `let handle = driver.handle(&proposal)?`. Keep it where a peer
   can read it, for example in the state of the client. It holds the operation identity, its request binding, the
   instance, and the audit time, and no secret.
2. After `Outcome::Unknown`, call `driver.recover(handle, now)`, execute the effects, and take
   `Answer::Recovered(result)` with `driver.take(ticket)`.

| `Recovered` | Meaning | The caller |
| --- | --- | --- |
| `Committed(receipt)` | The operation committed. The driver wrote its owed creation entry first. The receipt has no artifact | Answer from the stored state |
| `Fresh` | The operation never committed, and it never commits: recovery wrote a closure at its outcome key, and voided its entries | Start the request again with a fresh identity |
| `Refused(error)` | The identity holds the outcome of another request | Refuse the request |
| `Unknown` | A restore or an activation changed the instance after the handle, or the retention of the outcome record (`outcome_retention`) after the handle time can have ended | Keep the operation in doubt |

A closed operation never commits: each later copy of its commit finds the closure in the atomic commit check and
gives `Outcome::Refused(transition::Error::Closed)`, whose recovery is `Restart`. A lookup of a closed operation gives
`Lookup::Refused(transition::Error::Closed)`.

## Upgrade from the single-driver contract

A store that the single-driver contract wrote needs no migration. Its replay floor names its last instance, so the
first start of the new driver joins it. The counter starts above the highest floor of each kind in the journal.

For a binding:

1. Implement `Store::instance`: the installed number, with no write, or `Instance(0)` before the first start. A
   stopped handle serves again after it ([Write a storage binding](storage-binding.md)).
2. Stop only the handle of an error, unless the handles share one writer. A failed sync stops each handle.
3. Run the conformance suite. The case `Servers` runs two drivers on two clones of the binding.

For an application:

1. Give `Driver::new` a random generator: `Driver::new(profile, limits, &mut random)`.
2. Call `driver.allocate()` with no kind. Give `driver.allocate_after(&previous)` the current version of a record
   that a commit writes again.
3. Expect a start to join: it writes no instance, and it reconciles only an activation.
4. Map `transition::Error::Closed` and `driver::Error::Exhausted` to their recovery, `Restart`.
5. Replace a fresh attempt after a missing receipt with `driver.recover(handle, now)`.

## Cost of each shared operation

| Operation | Primary store | Journal |
| --- | --- | --- |
| A start that joins | One instance read, the reads of the floor and the mark record, and one read of each anchor with no end that the journal created after the mark. Then a move of the mark | The entries after the mark, then one read, one append, and one sync for two blocks of the counter |
| A commit with no journal entry, such as a sign-in | One commit, as with one driver | None |
| A commit with an end entry, such as a revocation or a renewal | One commit, as with one driver | The appends and one sync, as with one driver. After a conflict: a read of the new entries, a sync when the read gives none, and a read of the turn or the outcome record before the next append |
| A new record of a key that can repeat | One commit | One read of the new entries |
| An anchor change | The reservation of the turns, the commit, and one commit that releases the turns and the journal intent | One read of the new entries, then the entries as with one driver |
| A counter block | None, or one write of the mark record for a binding with no journal | One read, one append, and one sync for each 1,024 values of a driver, in the background |
| A lookup | One read of the outcome record, and one range read of the intents of the operation after a receipt | One read of the new entries after a receipt |
| A recovery | At most one read, one range read, and one commit | At most one append and one sync |
| A move of the mark | One range read of the turn records, then the reads and the write as with one driver | The entries after the head |

A replacement of a record that a peer wrote from a later block discards the rest of the block in use. Values are
64-bit, so a discarded value costs no capacity that a store can reach.
