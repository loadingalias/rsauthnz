# Composite signature vectors

`vectors.json` holds the `id-MLDSA65-Ed25519-SHA512` and `id-MLDSA65-ECDSA-P256-SHA512` cases of
Appendix E of
[draft-ietf-lamps-pq-composite-sigs-19](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/19/).

- Source: `testdata/composite_mldsa/draft19/vectors.json` of
  [rscrypto](https://github.com/loadingalias/rscrypto), at commit
  `4b1899d17821da07a2866510036fe57e3a820e89`. The file is not changed. Its SHA-256 is
  `90d23a33ac852a8716f9ccc77da95f97382194ae987130ea9aeb412f405151b0`.
- rscrypto took the two cases from `src/testvectors.json` of
  [lamps-wg/draft-composite-sigs](https://github.com/lamps-wg/draft-composite-sigs), at commit
  `b9e2674c0072df66ea09abeabc1c1be5ef9baf29`. That file has the SHA-256
  `a60f697f9fd94c3cd5e4501a40c4396d9a9ffc7cf0f8a1ddd87dedbb46a7abf0`. The README of the rscrypto
  directory records the selection and the check against the draft text.
- Draft text and test data are subject to the IETF Trust Legal Provisions. The file holds test data
  only.

Each case holds base64 fields. `src/crypto/tests.rs` reads `m`, and the `pk` and `s` of each case:
the public key, and the signature over `m` with the empty context. COSE uses only the empty context
(draft-ietf-jose-pq-composite-sigs-06, section 4.1).
