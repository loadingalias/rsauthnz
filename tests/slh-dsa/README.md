# SLH-DSA vectors

`vectors.json` holds three NIST ACVP cases of SLH-DSA-SHA2-128s (FIPS 205) with the pure external
interface and the empty context. COSE and RFC 9909 use only that form.

| `tcId` | Source | `testPassed` |
| --- | --- | --- |
| 162 | `SLH-DSA-sigGen-FIPS205`, deterministic | `true` |
| 474 | `SLH-DSA-sigGen-FIPS205`, hedged | `true` |
| 255 | `SLH-DSA-sigVer-FIPS205` | `false` |

- Source: `gen-val/json-files` of
  [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files),
  at commit `975de31eb83d87039ec88934fdc47d8c312b892d`, retrieved 2026-11-20. Each upstream file
  had the SHA-256 that rscrypto records in `testdata/slhdsa/acvp/README.md`:

  | Upstream file | SHA-256 |
  | --- | --- |
  | `SLH-DSA-sigGen-FIPS205/prompt.json` | `afa673eacdf0aec53512a159159b7632684adfcd0d88f8640a7f6f5796aacdc8` |
  | `SLH-DSA-sigGen-FIPS205/expectedResults.json` | `71e8e0f7e4b0cfd1747314299204d9d4d50968d200a4ae873921eaa7aabeaad1` |
  | `SLH-DSA-sigVer-FIPS205/prompt.json` | `4e7beb1233e47baa0acdd36417c66c45811aa40a4e32ffdb1a35d93b13b289fb` |
  | `SLH-DSA-sigVer-FIPS205/expectedResults.json` | `259f5e2a0665de0adc0fefa45b5db3a2a6ed13c3c44d14bdaf64a80aee12c687` |

- Change (2026-11-20): the extraction kept only these three cases and wrote each byte field in
  base64. `pk` of a sigGen case is the last 32 bytes of its `sk`: `PK.seed || PK.root` (FIPS 205,
  section 9.1). `signature` of a sigGen case comes from `expectedResults.json`. `testPassed` of the
  sigVer case comes from `expectedResults.json`. No other value changed. `vectors.json` has the
  SHA-256 `bc414fcde6d9e46dbe9b4d2ae6caea1b0f5fd273c242d01427301c9d0f800dd2`.
- NIST supplies these vectors. `NIST-NOTICE.txt` keeps the notice of the upstream `README.md`.
  The files hold test data only.

The other SHA2-128s cases have a context, the pre-hash interface, or the internal interface.
rscrypto runs all 1,248 cases of the 12 sets. `src/crypto/tests.rs` verifies each case here through
the facade, with the empty context.
