# Refresh trust with snapshots

`rsauthnz::trust` gives a remote verifier the workload trust of an authority as one signed snapshot. The verifier
installs the snapshot and refreshes it on a schedule. It then checks each workload credential locally, with no lookup
for each request. It refuses a credential that a rotation, a recovery, or a revocation before the snapshot ended.

A verifier that reads the store of the authority needs no snapshot: `workload::admits` checks the current
registration ([Verify a credential at the audience](workload.md#verify-a-credential-at-the-audience)).

## The model

- A **snapshot** is a `COSE_Sign1` with the tag 18. Its payload is the CBOR array `["rsauthnz.trust.snapshot.1",
  authority, issued, issuers, workloads]`. `issued` is the time of the issue in nanoseconds since the Unix epoch.
  Each issuer is its record form, with its current and previous key, its audiences, and its ceiling. Each workload is
  `[workload, issuer, thumbprint, generation, revoked]`. The thumbprint is the COSE Key Thumbprint of its registered
  key. The generation and the revoked credentials are those of its registration.
- The **trust root** signs each snapshot. It is a `custody::Handle`: an SLH-DSA-SHA2-128s root, or a composite key.
  The protected bucket holds the `alg` of the root, or no `alg` for SLH-DSA, which has no COSE identifier. The header
  only matches the algorithm of the trusted root: it never selects one. The signed bytes are the `Sig_structure`
  `["Signature1", ...]`. Thus they never parse as the DER `TBSCertificate` that the same root can sign.
- The **freshness** of a snapshot comes from its signed time of issue, never from the time of its fetch. A snapshot
  ends at its issue plus the maximum age.
- Each **install** is monotonic. A snapshot older than the installed one refuses. Another snapshot with the same time
  of issue and other bytes refuses too. The same bytes again change nothing.

## Choose the times

`Freshness` holds four times that the host declares. `Profile::new` refuses them with `Error::Freshness` when they
cannot keep their promises.

| Field | Meaning | Rule |
| --- | --- | --- |
| `max_age` | The time after its issue at which a snapshot ends. A refresh is due after half of it | Not zero |
| `uncertainty` | The largest uncertainty bound of a time reading. A reading with a larger bound, or with no bound, refuses | — |
| `propagation` | The revocation propagation objective: the longest time from the issue of a snapshot to the end of its reuse | At least `max_age` plus `uncertainty` |
| `retry` | The least time from the start of a fetch to the start of the next one, after a failure or with no answer | Not zero, and at most half of `max_age` |

`profile.residual()` is the residual window of offline use: `max_age` plus `uncertainty`. A verifier that gets no new
snapshot accepts a credential that a revocation ended for at most this time after the issue of its snapshot. The
authority publishes snapshots more often than half of `max_age`, so that a refresh finds a newer one.

## Publish a snapshot

1. Read the draft from the store of the authority: `Draft::read(&mut store, &authority, &root, now, limits)`. It
   reads each issuer record and each registration record in pages of range reads. The time of the issue is the
   earliest time of `now`.
2. Sign `draft.to_be_signed()` with the root in custody ([Hold keys in custody](custody.md)).
3. Call `draft.finish(&signature, &mut budget)`. It verifies the signature with the root, and gives the snapshot.
4. Serve the snapshot at a URL that each verifier fetches. The snapshot carries its own signature, so the transport
   adds no trust to it.

The limits of the draft bound the store: at most `Limits::keys` (64) issuer keys and at most `Limits::items`
registrations, and the payload within `Limits::bytes`. A larger store refuses with `Error::Limit`: raise the limits
of the authority and of each verifier together.

## Verify with a snapshot

1. At startup, build `Trust::new(Profile::new(authority, root, freshness, limits)?)`. It has no snapshot, so each
   view refuses with `Error::Missing` until the first install. `Trust` is `Sync`: share it in an `RwLock`. Each check
   takes `view` under a read lock, and only `refresh`, `install`, and `fail` take the write lock.
2. Before each check, or on a timer, call `trust.refresh(now)`. On `Refresh::Fetch(ticket)`, fetch the snapshot with
   the I/O of the host. Give the bytes to `trust.install(ticket, &bytes, now)`, or the failure to
   `trust.fail(ticket)`. On `Refresh::Pending` or `Refresh::Fresh`, fetch nothing.
3. Call `trust.view(now)`. It gives a `View` while the installed snapshot is fresh.
4. Get the issuer with `view.issuer(&issuer_authority)`, verify the credential with
   `issuer.profile(&audience, limits)?.verify(credential, now, &mut budget)`, and check it with
   `view.admits(&verified)`.
5. End the reuse of the check at `view.end()`, or at the end of the credential when that is earlier.

One fetch is in flight at a time, so concurrent requests make one fetch. The fetch ends at its install, at its
failure, or at the retry time after its start. A failed fetch, or a snapshot that refuses, holds the next fetch until
the retry time after its start. The core starts no task and does no I/O.

The install verifies the signature of the root before it reads the payload. Then it checks the authority, the order,
and the time of the issue, before it makes a trusted key. A refusal keeps the installed snapshot.

## Time readings

Each operation takes a time reading with a known bound, at most the declared `uncertainty`. The trust keeps the latest
time that it saw: the earliest time of each reading, and the issue of each installed snapshot. A check uses the latest
time of its reading, or that kept time when it is later. Thus a wall-clock rollback of the injected time does not make
an ended snapshot serve again. A snapshot with a time of issue after the check refuses with `Error::Future`.

## Errors

Each `trust::Error` is a small `Copy` value with no secret.

| `Error` | Cause | Response |
| --- | --- | --- |
| `Freshness` | The declared times cannot keep their promises | Correct the configuration |
| `Time(error)` | The reading has no bound, or a time overflows | Give a reading with a known bound |
| `Uncertain` | The bound of the reading is larger than `uncertainty` | Give a more certain reading |
| `Missing` | No snapshot is installed | Refresh |
| `Stale` | The snapshot is at or after its end | Refresh. Refuse each check until a fresh snapshot installs |
| `Rollback` | The snapshot is older than the installed one | Keep the installed one. Look for a stale cache |
| `Inconsistent` | Another snapshot with the time of issue of the installed one, two members with one name, or a registration of an issuer that the snapshot does not hold | Keep the installed one. Report it to the authority |
| `Future` | The time of issue is after the check | Check the clock of the authority |
| `Authority` | The snapshot is of another authority | Fetch from the right authority |
| `Signature` | The root did not sign the snapshot, or its `alg` is not the algorithm of the root | Refuse the snapshot |
| `Cose(error)` | The snapshot is not a `COSE_Sign1` within the limits | Refuse the snapshot |
| `Form` | The payload or a record is not its form | Refuse the snapshot |
| `Limit(limit)` | The snapshot or the store is larger than a bound of the limits | Raise the limits on both sides |
| `Ticket` | The ticket is not the fetch in flight | Drop the answer of the earlier fetch |

`view.admits` gives the errors of `workload::admits`: `Unregistered`, `Possession`, and `Revoked`.
`Draft::read` returns `trust::Failure`: `Refused(error)`, or `Store(error)` for a failed read.

The cost class of `Trust::install` and `Draft::read` is `Verify` ([Admit rsauthnz work](admission.md)). Each makes one
signature check of the root, and one trusted key for each issuer key. The cost class of `refresh`, `fail`, `view`,
`view.admits`, and `Profile::new` is `Parse`.

## Support

The tests on this Mac (macOS aarch64) cover a composite root and an SLH-DSA-SHA2-128s root on the memory binding. They
cover an older snapshot after a newer one, another snapshot of the same issue, and the maximum age. They also cover a
rollback of the time, a replayed old snapshot, a changed signature or payload, and a reading with no bound. Ten
concurrent refresh requests make one fetch, and a remote verifier sees a revocation after its refresh.
