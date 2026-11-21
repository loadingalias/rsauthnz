# JOSE test data

`vectors.rs` holds the JWS cases and the key sets that `tests/jose.rs` checks.

- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), appendix A.2 (RS256) and appendix A.3 (ES256): the JWS Compact
  Serialization and the JWK of each case.
- [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037), appendix A.4 (Ed25519, `alg` `EdDSA`): the JWS, and the key of
  appendices A.1 and A.2.
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), appendix A.1: the set of two public keys.
- [RFC 7520](https://www.rfc-editor.org/rfc/rfc7520), section 6.3 (PS256): the JWS of figure 228, and the key of
  figure 224.
- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964), appendix A.1 (ML-DSA-65): the `jws` and the `jwk` of figure 4.
- Source: the text form of each RFC at `https://www.rfc-editor.org/rfc/`, read on 2026-11-20 (RFC 7520 and RFC 9964 on
  2026-11-21). Each value is the RFC value with the line breaks of the text removed. A public key is the public members
  of the JWK of its case.

No published JOSE case has a composite key. Thus `tests/jose.rs` signs the composite case with an rscrypto key.
