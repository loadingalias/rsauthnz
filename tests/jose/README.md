# JOSE test data

`vectors.rs` holds the JWS cases and the key sets that `tests/jose.rs` checks.

- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), appendix A.2 (RS256) and appendix A.3 (ES256): the JWS Compact
  Serialization and the JWK of each case.
- [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037), appendix A.4 (Ed25519, `alg` `EdDSA`): the JWS, and the key of
  appendices A.1 and A.2.
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), appendix A.1: the set of two public keys.
- Source: the text form of each RFC at `https://www.rfc-editor.org/rfc/`, read on 2026-11-20. Each value is the RFC
  value with the line breaks of the text removed. A public key is the public members of the JWK of its case.

No RFC has a PS256 JWS. Thus `tests/jose.rs` signs a PS256 case with rscrypto and the RSA key of RFC 7515, appendix
A.2. The ML-DSA-65 and composite cases also come from rscrypto keys.
