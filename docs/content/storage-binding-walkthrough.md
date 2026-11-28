# Walk through a file binding

This page follows the [storage binding guide](storage-binding.md) step by step, with a complete binding that keeps
its state in files. The binding passes each case of the [conformance suite](conformance.md), with a restore journal
and without one. Read it next to the guide when you write a binding for your own store.

The binding is `storage_binding::Files`, in the workspace member `examples/storage-binding`. It is an example, not a
supported backend. It uses only public items of `rsauthnz` and `rsauthnz-conformance`, and the CRC-32C checksum of
`rscrypto`. Its source has three files:

- `src/lib.rs`: the declaration, the primitives of `Store` and `Journal`, and the start.
- `src/form.rs`: the frame of each write and the form of the records in the files.
- `src/subject.rs`: the test controls of `suite::Subject`.

## Run the example

Run the tests of the example from the root of the repository:

```sh
cargo xtask test -p storage-binding
```

Three tests pass. Two run the suite, with a journal and without one, and the third starts the binding after a torn
write. Each test makes its files in a new directory under the temporary directory of the system, and removes it at
the end.

## Limits of the example

- It needs a Unix file system, because a durable rename needs a sync of its directory.
- The primitives do blocking file I/O, and their futures are ready at their first poll. Run them on a thread that can
  block.
- The store log grows with each commit until the next start. Then the start writes the log again with only the current
  records.
- The journal grows with each entry, and a start reads all of it. The driver moves its mark, but the binding never
  removes old entries.
- One process uses the files at a time. Directory locks exclude a second writer at either the store or the journal.
- A start keeps the frames before the first incomplete frame or wrong checksum, as the SQLite write-ahead log
  does. It cannot tell a torn last write from damage inside a file, so damage inside a file loses the writes
  after it.

## The files

The binding keeps its state in two directories. Put them in different failure domains, for example on different
disks.

| Directory | File | Contents |
| --- | --- | --- |
| Store | `store` | The store log: one frame for each commit or expiry, with the writes of the frame |
| Store and journal | `lock` | A writer holds both directory locks while it serves |
| Journal | `journal` | The restore journal: one frame for each entry, with its sequence |
| Journal | `instance` | The last store instance number. A binding without a journal keeps it in the store directory |

A frame is the length of its payload, the CRC-32C of the payload, and the payload. A start reads the frames of a file
and stops at the first frame that is incomplete or has a wrong checksum. That frame is a torn write that no sync made
durable.

## Each step of the guide

### 1. Declare the guarantees

`Files::new(store, restore, outcome_retention)` makes the `Declaration`:

| Field | Value | Reason |
| --- | --- | --- |
| `isolation` | `Isolation::Serializable` | Each primitive holds one lock for its checks and its writes, so the commits run one at a time |
| `crash_loss` | `CrashLoss::Unsynced` | Each commit syncs its frame before it returns, and a start drops each write after the last sync |
| `outcome_retention` | The argument | The caller selects it |
| `crash_injection` | `CrashInjection::Supported` | The binding implements `Subject::inject` |
| `restore` | The argument | `Restore::Journal` names the journal directory in `location`. `Restore::Unsupported` gives a binding without a journal |
| `key_bytes_max` | `Key::BYTES_MAX` | The binding stores each key as opaque bytes |
| `signatures` | `CAPACITY`: 256 replay records of signatures, 32 of one agent key | Small, so that the conformance suite fills it with few syncs |
| `record_bytes_max` | `RECORD_BYTES_MAX`, 1 MiB | It is above `record_bytes_min` of the default `Limits`, 131,377 bytes |

### 2. Keep the store instance number

`Store::start` writes the next number into the file `instance` before it returns. The write is durable: a new file,
its sync, a rename over `instance`, and a sync of the directory. The file is in the journal directory, so a restore of
the store does not lower the number. A start takes both directory locks and advances the instance before installing a snapshot.
Each commit, append, and journal sync compares its instance while the binding holds the locks.
A returning writer uses its remembered file lengths only if the previous instance was its own.
An empty instance file, or a missing instance file beside existing logs, gives `Error::Instance`.

### 3. Read one record

At a start, the binding reads the store log into a `BTreeMap` from `Key` to `Record`. `Store::read` is a lookup in
this map. The binding stores the records of each kind in the same way, the mark record of the driver included.
`Store::read_pair` holds the same lock for both map lookups. A commit can land before or after the pair.

### 4. Commit a proposal

`Store::commit` holds the lock for each check and for the write:

1. It compares the instance number. A different number gives `Commit::Superseded` and stops the old driver.
2. It looks up the outcome record. A record gives `Commit::Recorded`.
3. It checks each dependency in the map. A dependency that does not hold gives `Commit::Conflict`.
4. For a proposal with a deadline, it reads the system clock, with a bound of one second, while it holds the lock. A
   reading that can be at or after the deadline gives `Commit::Expired`.
5. For each write of a new replay record of a signature, it counts the keys of the kind and of the share in the map,
   which keeps the keys in order. When `CAPACITY.admits(records, share)` does not hold, it gives `Commit::Full`.
6. It appends one frame with each change, the audit record, each intent record, and the outcome record.
7. It syncs the store log, applies the writes to the map, and gives `Commit::Accepted`.

`Store::insert_replay` holds the same lock. It checks the floor of the current instance, the key, the capacity, and
the system clock, in that order, then appends one frame with the record and syncs it.

### 5. Keep audit and outcome records for their retention

The commit sets the end of the audit record and the outcome record to the audit time of the proposal plus the outcome
retention. A sum past the largest `Duration` gives `Duration::MAX`.

### 6. Expire ended records

The binding keeps a `BTreeSet` of end and key for each kind. Under the write lock, expiry first checks the supplied instance.
It reads eligible records in end order, removes them in one frame, and syncs the log.
A delayed restore worker receives `Expiry::Superseded` before it can delete a new ceremony.

### 7. Read one key prefix

The keys of one prefix are one range of the map, from the prefix. `Store::range` reads at most `limit` keys of the range
after `after`, and stops at the first key that does not start with the prefix.

### 8. Keep the restore journal

- `Journal::append` compares the instance and both parts of the head. It writes one frame and installs the successor head under the lock.
- `Journal::sync` checks the instance and syncs the file. It records the durable length and entry count.
- `Journal::read` gives only entries before that length, in one read of the file.
- A start drops each byte after the length of the last sync, and a torn last frame. Then it syncs the file.

### 9. Stop at each error

Each primitive runs on the open files. An error stops the binding: it closes the files and keeps the durable length of
each file. Each primitive except `Store::start` then gives `Error::Stopped`. The binding retries nothing. A start
drops each write after the durable lengths, so a write whose sync failed does not come back after the start.

### 10. Run the commit driver

The binding needs no code for this step. The measurement program `examples/journal_cost.rs` of the example has the
`execute` function and the loop of the guide.

### 11. Implement the test controls

Each fault of the suite takes a real failure path of the binding:

| Fault | What the binding does |
| --- | --- |
| `Fault::CrashBeforeCommit` | The commit writes its frame, and its sync fails. The binding stops, and the next start drops the frame |
| `Fault::LostResponse` | The commit writes and syncs its frame, then gives an error and stops |
| `Fault::CrashAfterAppend` | The append writes its frame and returns `JournalWrite::Accepted`. Then the binding stops. The next start drops the append |
| `Fault::FailedSync` | The sync of the journal fails. The binding stops, and the next start drops each append after the last sync |

- `Subject::restart` stops the binding, as a crash does.
- `Subject::snapshot` gives the store log of the current records.
- `Subject::restore` takes both directory locks and a fresh instance before writing the snapshot.
- `Subject::set_clock` gives each later commit the reading of the suite in place of the system clock.
- `Subject::lose` writes the journal again without the lost entries. Each entry keeps its sequence in its frame, so no
  sequence is used again while later entries remain. A loss of the last entries followed by a start gives their
  sequences again, because the file cannot tell a lost entry from a torn append. The suite never makes this sequence
  of events.

### 12. Run the suite

The test `the_binding_with_a_journal_passes_each_case_of_the_suite` in `tests/binding.rs` runs `suite::run`. Each
call of `make` gives a binding in a new directory. The futures are ready at their first poll, so one poll runs the
suite. The report has no failure and no skipped case.

## Journal cost

The program `examples/journal_cost.rs` measures 500 commits of each transition kind through the commit driver, with
the journal and with `Restore::Unsupported`. It counts the journal entries and bytes of each commit, and it times each
commit from `Driver::submit` to its answer. Run it with an optimized build, and give a directory on the disk under
test:

```sh
cargo run --locked --release -p storage-binding --example journal_cost -- "$HOME"
```

The program interleaves the cells: each round measures each kind in both modes, and the first kind and the order of
the modes change from round to round. A disk can change its latency over time. For example, the EBS volume below
changes between about 1.5 ms and 2.8 ms for each sync, for 0.5 to 2 seconds at a time. Thus each cell sees the same
disk.

The record of 2026-11-19:

- **Risk.** Each invalidation of authority waits for a durable journal append before its commit, so it can double the
  commit latency.
- **Budget.** Two runs of about one minute each on one quiet host.
- **Stop condition.** A run longer than 10 minutes, or a p50 that differs by more than 25 % between the two runs.
- **Host.** An ephemeral `aws-linux-x64-bench` host, c8i.xlarge, Ubuntu 26.04.1, Linux `7.0.0-1017-aws`, x86_64, with
  the files in `$HOME` on ext4 on a 40 GB EBS volume. No other work ran on the host.

Each latency cell gives the range of the two runs, in milliseconds. The entries and bytes are equal in both runs. The
p50 of each cell differs by at most 3 % between the runs.

| Transition | Entries | Bytes | p50, journal | p99, journal | p50, no journal | p99, no journal |
| --- | --- | --- | --- | --- | --- | --- |
| Sign-in | 0 | 0 | 2.9 | 3.6–3.7 | 2.9 | 3.6–3.7 |
| Approval consumption | 0 | 0 | 2.9 | 3.6–3.7 | 2.9 | 3.6 |
| Session revocation | 1 | 93–99 | 6.1 | 7.2–7.3 | 2.9 | 3.6 |
| Session renewal | 1 | 92–98 | 6.0 | 7.2–7.4 | 2.9 | 3.6 |
| Grant revocation | 1 | 93–99 | 6.0 | 7.0–7.2 | 2.9 | 3.5–3.6 |
| Grant change | 1 | 93–99 | 6.0 | 7.1–7.4 | 2.9 | 3.6 |
| Passkey unlink | 1 | 95–101 | 6.0–6.1 | 7.1 | 2.9 | 3.6 |
| Passkey enrollment | 2 | 321–345 | 9.0 | 10.4 | 2.9 | 3.7 |

- A sign-in and an approval consumption write no journal entry, and the journal adds nothing to their latency.
- Each invalidation writes one entry. On this disk, the entry adds one sync of about 3.1 ms before the commit, so an
  invalidation has about two times the latency of the same commit with no journal.
- An enrollment writes its consumption entry and its creation entry, so it adds two syncs.
- The commit driver keeps the state of the journal between commits, so the cost of a commit does not grow with the
  length of the journal.
- The records of the measurement are small: 6 bytes in each record. A larger record makes each commit and each sync
  longer.

## Disk durability

The suite runs in one process, so it does not show that a sync survives a loss of power. The binding syncs with
`File::sync_data` and `File::sync_all` of the Rust standard library. On macOS, the standard library makes them full
syncs with `F_FULLFSYNC`. A production binding records the settings of its store and the evidence that its device
keeps a sync.
