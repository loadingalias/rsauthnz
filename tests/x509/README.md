# X.509 fixtures

OpenSSL 3.5.9 (Homebrew `openssl@3`, macOS aarch64) made these certificates on 2026-11-21. `tests/x509.rs` builds
each one again from its fields and its signature, and compares the bytes. The keys were deleted after the run, so the
files hold only public keys and signatures.

| File | Subject key | Issuer | Usage |
| --- | --- | --- | --- |
| `slh-dsa-root.der` | SLH-DSA-SHA2-128s | Itself | Issuer, path length 1 |
| `ml-dsa-65-issuer.der` | ML-DSA-65 | `slh-dsa-root.der` | Issuer, path length 0 |
| `ml-dsa-65-leaf.der` | ML-DSA-65 | `ml-dsa-65-issuer.der` | TLS identity |
| `ed25519-leaf.der` | Ed25519 | Itself | TLS identity |
| `es256-leaf.der` | ECDSA P-256 | Itself | TLS identity |

SHA-256 of each file:

```text
fb69cb148a3caa6938266ac68dffcc5791116a4bdf45716ea75bd4046125dd91  ed25519-leaf.der
4ac53a2369352d4e909361cb0121dbbb3b55af7f043ef9238f4c662f2d646bc0  es256-leaf.der
3b2847be3f12b0b56f80538d40ff1501412be762c33f087b3f2f06a8f9cfe04e  ml-dsa-65-issuer.der
602e38c194e2148358268a9e0224d18c2cc7b517d79fb6d40cbdcaea030f063b  ml-dsa-65-leaf.der
c4fc204a00dd9d950ccc8fc4d612c14769ccb3693418437f9fc4727800b91309  slh-dsa-root.der
```

Each issuer certificate has its `subjectKeyIdentifier`, and each certificate that is not self-signed has the
`authorityKeyIdentifier` of its issuer (RFC 5280, sections 4.2.1.1 and 4.2.1.2). The identifier is the first 160 bits
of the SHA-256 digest of the bits of the `subjectPublicKey` (RFC 7093, method 1). Python `hashlib` computed it from the
key of `openssl pkey -pubout`, and the configuration gives it to OpenSSL as a hexadecimal string.

The configuration `ext.cnf`:

```ini
[req]
distinguished_name = dn
string_mask = utf8only
[dn]
[root]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign
subjectKeyIdentifier = 33ADBE00F49E35A9E523664FBC53BAB55624A7DB
authorityKeyIdentifier = none
[issuer]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign
subjectKeyIdentifier = 72E5A3A3AC1040F51009ABCC0C42191688694A0E
authorityKeyIdentifier = keyid:always
[leaf]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:build.app.example, URI:https://app.example/workload/build
subjectKeyIdentifier = none
authorityKeyIdentifier = keyid:always
[self]
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:build.app.example, URI:https://app.example/workload/build
subjectKeyIdentifier = none
authorityKeyIdentifier = none
```

The keys come from a first run of the same commands with `-newkey <algorithm> -nodes -keyout <file>` in place of
`-key <file>`: `SLH-DSA-SHA2-128s` (`root.key`), `ED25519` (`ed.key`), and `EC` with `-pkeyopt ec_paramgen_curve:P-256
-pkeyopt ec_param_enc:named_curve` (`es.key`). That run made certificates with no key identifiers, and the commands
below replaced them. The requests:

```sh
openssl req -new -newkey ML-DSA-65 -nodes -keyout issuer.key -config ext.cnf \
  -subj "/O=rsauthnz/OU=fixtures/CN=ML-DSA-65 issuer" -out issuer.csr
openssl req -new -newkey ML-DSA-65 -nodes -keyout leaf.key -config ext.cnf -subj "/O=rsauthnz/CN=build" -out leaf.csr
```

The certificates, with `V=(-not_before 20261121000000Z -not_after 20361121000000Z)`:

```sh
openssl req -x509 -new -key root.key -config ext.cnf -extensions root \
  -subj "/O=rsauthnz/OU=fixtures/CN=SLH-DSA root" -set_serial 0x4a1b2c3d4e5f60718293a4b5c6d7e8f9 $V \
  -outform DER -out slh-dsa-root.der
openssl x509 -inform DER -in slh-dsa-root.der -out root.pem
openssl x509 -req -in issuer.csr -CA root.pem -CAkey root.key -set_serial 0x5b2c3d4e5f60718293a4b5c6d7e8f90a $V \
  -extfile ext.cnf -extensions issuer -outform DER -out ml-dsa-65-issuer.der
openssl x509 -inform DER -in ml-dsa-65-issuer.der -out issuer.pem
openssl x509 -req -in leaf.csr -CA issuer.pem -CAkey issuer.key -set_serial 0x6c3d4e5f60718293a4b5c6d7e8f90a1b $V \
  -extfile ext.cnf -extensions leaf -outform DER -out ml-dsa-65-leaf.der
openssl req -x509 -new -key ed.key -config ext.cnf -extensions self -subj "/O=rsauthnz/CN=build" \
  -set_serial 0x7d4e5f60718293a4b5c6d7e8f90a1b2c $V -outform DER -out ed25519-leaf.der
openssl req -x509 -new -key es.key -config ext.cnf -extensions self -subj "/O=rsauthnz/CN=build" \
  -set_serial 0x0e5f60718293a4b5c6d7e8f90a1b2c3d -sha256 $V -outform DER -out es256-leaf.der
```

`openssl verify -check_ss_sig -x509_strict -CAfile root.pem -untrusted issuer.pem leaf.pem` gave `OK` for the chain.

The composite certificates are the `x5c` of `tests/composite-sigs/vectors.json` ([its README](../composite-sigs/README.md)).

## Sigstore fixtures

These files come from the Sigstore public-good instance. Each one is public data, under Apache-2.0 at its source.

| File | What it is | Source |
| --- | --- | --- |
| `sigstore-root.der` | The Sigstore root (`O=sigstore.dev, CN=sigstore`, P-384), the trust anchor | The `certChain` of the CA from 2022-04-13 in `targets/trusted_root.json` of `sigstore/root-signing`, commit `c9bda74ad2221f938f7d2e0295ca3aad2da710a8` |
| `sigstore-intermediate.der` | The Fulcio intermediate (`CN=sigstore-intermediate`, P-384, path length 0, `codeSigning`) | The same `certChain` |
| `ctfe-2022.der` | The `SubjectPublicKeyInfo` of the CT log `https://ctfe.sigstore.dev/2022` (P-256). Its SHA-256 digest is its log ID | The `ctlogs` of the same file |
| `fulcio-leaf.der` | The Fulcio leaf of the GitHub Actions release `trailofbits/rfc8785.py` v0.1.2 (P-256, signed with P-384), valid from 2024-03-19 22:41:15 to 22:51:15 UTC | The first certificate of `test/assets/bundle_v3_github.whl.sigstore` of `sigstore/sigstore-python`, commit `300b502ae99ebfaace124f1f4e422a6a669369cf`. The `integratedTime` of its Rekor entry is 1710888076 |

OpenSSL 3 (`openssl x509 -text`) printed the fields, the claims, and the timestamp (2024-03-19 22:41:15.966 UTC) that
`tests/x509.rs` expects. Python `hashlib` computed the log ID.

```text
3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1  sigstore-root.der
15d795348226b4649f750f5802592c393bee7cc53c3b86982175b7ad087efe47  sigstore-intermediate.der
dd3d306ac6c7113263191e1c99673702a24a5eb8de3cadff878a72802f29ee8e  ctfe-2022.der
3bdbfb9fe7a9377878b538dfb2ec6af283d51e243629fa667e360a06b62f63c2  fulcio-leaf.der
```
