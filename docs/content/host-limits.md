# Check a host at its limits

A host of rsauthnz admits its work at declared limits ([Admit rsauthnz work](admission.md)). Six commands check the
web example at [its limits](web-example.md#limits): floods, a store that does not answer, retained records, and
shutdown. Run them again after a change of the host, of a passkey operation, or of the store.

## Run the checks

Two checks make no measurement. They run with the other tests of the example, on each host:

```sh
cargo xtask test -p web -E 'test(the_request_after_the_last_waiting_place_gets_503_and_a_page_still_serves)'
cargo xtask test -p web -E 'test(a_shutdown_returns_the_response_of_a_request_in_flight_and_then_joins_the_application_thread)'
```

Four runs measure. Run each one alone, in a release build, on a quiet host:

```sh
cargo xtask test --release -p web --run-ignored only --no-capture -E 'test(a_flood_of_malformed_input_gets_its_refusals_and_keeps_no_state)'
cargo xtask test --release -p web --run-ignored only --no-capture -E 'test(a_flood_of_sign_in_verifications_stays_in_its_share_and_keeps_no_state)'
cargo xtask test --release -p web --run-ignored only --no-capture -E 'test(a_legitimate_sign_in_keeps_its_latency_during_a_flood_of_verifications)'
cargo xtask test --release -p web --run-ignored only --no-capture -E 'test(the_records_with_an_end_stay_within_their_limit_at_the_commit_budget)'
```

A run first prints its risk, its budget, its bounds, and its stop condition. Then it prints one `result:` line for
each value that it measured. The run fails if a bound does not hold. The longest run takes about 30 seconds.

## What each check does

| Check | Load | Bounds |
| --- | --- | --- |
| Malformed input | Four kinds of input, 2,000 requests of each kind in each second, for 3 seconds: a body over 16 KiB, a request of another site, a sign-in that is no assertion, and a sign-up that is no JSON | Each request gets its refusal: `413`, `403`, `403`, and `403` or `503`. The 99th percentile of each kind is at most 50 ms. The store has no new record |
| Flood of sign-in verifications | 40,000 sign-ins in each second for 3 seconds, with one registered credential and a wrong signature | Each response is `403` after the signature check, or `503` over the share of the credential. The 99th percentile of a `503` is at most 50 ms. The store has no new record. The credential signs in after the flood |
| A store that does not answer | One request waits for the store, and 64 requests wait in the queue | The next request gets `503` at once. The page and the sign-in options still serve. Each waiting request completes when the store answers |
| A legitimate sign-in during a flood | The flood above for 12 seconds. Another account makes 10 complete sign-ins in each second for 10 seconds | Each legitimate sign-in gets its session. The 99th percentile, from the planned start to the session, is at most 50 ms |
| Retained records | 20 sign-ins in each second of the host clock for 5,400 seconds, then 2 hours with no sign-in | At each time, the store has at most 186,540 records with an end. After the 2 hours, it has none |
| Shutdown with a request in flight | One request waits for the store when the shutdown starts | The shutdown does not return before the response. The request gets `200`. The application thread joins, and the server takes no new connection |

The limit of the retained records comes from the limits of the host. One sign-in keeps a replay record for 302
seconds, a session for 30 minutes, and an audit record and an outcome record for 1 hour. At 20 sign-ins in each
second, these are 186,040 records. A pass removes a record at most 5 seconds after its end, and the start and the
burst of the budget add at most 100.

## The load

The load is open loop: each request starts at its planned time, also when an earlier response is late. The planned
times have steps of one millisecond. A latency counts from the planned start to the end of the response, so it has
each wait of the client too, and up to one millisecond of the step.

Each load uses one HTTP/2 connection, and the flood has its own thread. The server is `web::serve` on its own
thread, with the system clock, as the binaries run it. The retention run drives the routes in the process of the
test, with a clock that the test moves, so 5,400 seconds of the host clock take about 30 seconds.

The legitimate sign-in and the flood use ES256 passkeys of the test authenticator. No run uses a browser or a real
authenticator.

## Observed results

Each bound held in each run of the table. The host was not quiet, so the times are no performance claim.

| Host | Check | Result |
| --- | --- | --- |
| macOS 27.2.1, Apple M1 Pro (aarch64), release build, 2026-11-25, load average about 5 | Malformed input | 24,000 refusals. For each kind, the median was 1.1 ms to 1.2 ms, and the 99th percentile was 5.9 ms to 7.0 ms. 11 records before and after |
| | Flood of sign-in verifications | 120,000 sign-ins: 22,702 got `403` after the signature check (99th percentile 3.3 ms), and 97,298 got `503` (99th percentile 4.5 ms). 22 records before and after |
| | A store that does not answer | Pass |
| | A legitimate sign-in during a flood | 100 of 100 sign-ins got a session during a flood of 480,000 sign-ins. The median was 1.4 ms, the 99th percentile 2.5 ms, and the longest 2.9 ms |
| | Retained records | At most 186,160 records with an end, constant from 3,900 seconds. None after 300 passes of the 2 hours |
| | Shutdown with a request in flight | Pass |
| Linux x86_64 | Each check | Not run yet |
| Windows x86_64 | Each check | Not run yet |
