//! The contracts of JOSE under trusted profiles: the published JWS cases verify, a header can only match its profile,
//! and the claims of a JWT hold at the time reading.

#[path = "jose/vectors.rs"]
mod vectors;

use core::time::Duration;

use rsauthnz::crypto::Algorithm;
use rsauthnz::jose::{self, Error, Kind, Profile};
use rsauthnz::limits::Limits;
use rsauthnz::time::{Reading, ReadingSource};
use rscodec::base64::Profile::Url;
use rscodec::json::{self, Slot};
use rscrypto::auth::{CompositeMlDsaError, Ed25519SecretKey, MlDsa65Ed25519};
use rscrypto::{HmacSha256, RsaPublicKey, RsaPublicKeyPolicy};

/// The RSA policy of the profiles of rsauthnz: the RFC key has 2,048 bits, below the default of rscrypto.
const RSA_POLICY: RsaPublicKeyPolicy = RsaPublicKeyPolicy::MODULUS_2048_TO_8192;

/// The issuer and the audience of each profile of the tests.
const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "https://api.example";

/// The reading at `seconds` since the Unix epoch, with an uncertainty of one second.
fn at(seconds: u64) -> Reading {
    Reading::new(
        Duration::from_secs(seconds),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The base64url text of `bytes`.
fn b64(bytes: &[u8]) -> String {
    let mut out = vec![0; Url.encoded_len(bytes.len()).expect("a length")];
    let len = Url.encode(bytes, &mut out).expect("base64url").len();
    out.truncate(len);
    String::from_utf8(out).expect("ASCII")
}

/// The bytes of the base64url member `name` of the JWK `jwk`.
fn member(jwk: &str, name: &str) -> Vec<u8> {
    let limits = json::Limits {
        input_bytes_max: 8192,
        depth_max: 2,
        string_bytes_max: 4096,
        members_max: 16,
        elements_max: 16,
        number_digits_max: 16,
    };
    let mut scratch = [Slot::EMPTY; 40];
    let text = json::read(jwk.as_bytes(), &limits, json::Profile::IJson, &mut scratch, |reader| {
        let mut found = None;
        let mut members = reader.value().members()?;
        while let Some((key, value)) = members.next()? {
            if key == name {
                found = value.str()?.borrowed();
            }
        }
        Ok(found)
    })
    .expect("a JWK")
    .expect("the member");
    let mut out = vec![0; Url.decoded_len(text.as_bytes()).expect("base64url")];
    Url.decode(text.as_bytes(), &mut out).expect("base64url");
    out
}

/// The key set of the JWKs `jwks`.
fn set(jwks: &[&str]) -> String {
    format!(r#"{{"keys":[{}]}}"#, jwks.join(","))
}

/// The profile of `algorithm` for JWTs of `kind`, with the keys of the key set `set`.
fn profile(algorithm: Algorithm, kind: Kind, set: &str) -> Result<Profile, Error> {
    Profile::new(algorithm, kind, ISSUER, AUDIENCE, Limits::default())?.with_key_set(set.as_bytes())
}

/// The Ed25519 key of the claim tests, and its JWK.
fn ed25519() -> (Ed25519SecretKey, String) {
    let key = Ed25519SecretKey::from_bytes([1; 32]);
    let x = b64(&key.public_key().to_bytes());
    (key, format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}"#))
}

/// The Ed25519 JWT of `claims` with the type `typ`.
fn jwt(typ: Option<&str>, claims: &str) -> String {
    let input = jose::signing_input(Algorithm::Ed25519, None, typ, claims.as_bytes()).expect("a signing input");
    jose::compact(&input, &ed25519().0.sign(input.as_bytes()).to_bytes())
}

/// A token with the header `header` and a signature of no key: its checks refuse before the signature.
fn unsigned(header: &str) -> String {
    format!("{}.{}.{}", b64(header.as_bytes()), b64(b"{}"), b64(&[0; 64]))
}

#[test]
fn the_published_jws_cases_verify_under_their_profiles() {
    let cases = [
        ("RS256", Algorithm::Rs256, vectors::RS256_KEY, vectors::RS256_TOKEN),
        ("ES256", Algorithm::Es256, vectors::ES256_KEY, vectors::ES256_TOKEN),
        (
            "EdDSA",
            Algorithm::Ed25519,
            vectors::ED25519_KEY,
            vectors::ED25519_TOKEN,
        ),
        ("PS256", Algorithm::Ps256, vectors::PS256_KEY, vectors::PS256_TOKEN),
        (
            "ML-DSA-65",
            Algorithm::MlDsa65,
            vectors::ML_DSA_65_KEY,
            vectors::ML_DSA_65_TOKEN,
        ),
    ];
    for (name, algorithm, key, token) in cases {
        let profile = profile(algorithm, Kind::Jwt, &set(&[key])).expect("a profile");
        let jws = profile.verify(token).expect(name);
        let (header, rest) = token.split_once('.').expect("a header");
        let (payload, signature) = rest.split_once('.').expect("a payload");
        let mut expected = vec![0; Url.decoded_len(payload.as_bytes()).expect("base64url")];
        Url.decode(payload.as_bytes(), &mut expected).expect("base64url");
        assert_eq!(jws.payload(), expected, "{name}");
        // A change of the payload refuses: the signature covers it.
        let (first, others) = payload.split_at(1);
        let other = if first == "A" { "B" } else { "A" };
        let changed = format!("{header}.{other}{others}.{signature}");
        assert_eq!(profile.verify(&changed).err(), Some(Error::Signature), "{name}");
    }
    // The RSA key of the PS256 case under RS256 refuses the token: its `alg` names another algorithm.
    let rs256 = profile(Algorithm::Rs256, Kind::Jwt, &set(&[vectors::PS256_KEY])).expect("a profile");
    assert_eq!(rs256.verify(vectors::PS256_TOKEN).err(), Some(Error::Algorithm));
    assert_eq!(
        vectors::ED25519_TOKEN
            .split('.')
            .nth(1)
            .map(|payload| member(&format!(r#"{{"p":"{payload}"}}"#), "p")),
        Some(b"Example of Ed25519 signing".to_vec())
    );
}

#[test]
fn a_key_set_gives_the_keys_of_the_algorithm_of_its_profile() {
    // A set with an RSA and a P-256 key: each profile takes one key, so a token with no `kid` selects it.
    let mixed = set(&[vectors::ES256_KEY, vectors::RS256_KEY]);
    profile(Algorithm::Rs256, Kind::Jwt, &mixed)
        .expect("a profile")
        .verify(vectors::RS256_TOKEN)
        .unwrap();
    profile(Algorithm::Es256, Kind::Jwt, &mixed)
        .expect("a profile")
        .verify(vectors::ES256_TOKEN)
        .unwrap();
    // The key set of RFC 7517 reads, and an Ed25519 profile takes none of its keys.
    for algorithm in [Algorithm::Es256, Algorithm::Rs256, Algorithm::Ed25519] {
        assert!(
            profile(algorithm, Kind::Jwt, vectors::RFC7517_KEY_SET).is_ok(),
            "{algorithm:?}"
        );
    }
    let ed = profile(Algorithm::Ed25519, Kind::Jwt, vectors::RFC7517_KEY_SET).expect("a profile");
    assert_eq!(ed.verify(vectors::ED25519_TOKEN).err(), Some(Error::Key));
    // A key set is public: a private member refuses the set.
    assert_eq!(
        profile(Algorithm::Rs256, Kind::Jwt, &set(&[vectors::RS256_PRIVATE])).err(),
        Some(Error::Key)
    );
    // A key whose `alg` or `use` does not fit does not join.
    let other = vectors::RS256_KEY.replacen('{', r#"{"use":"enc","#, 1);
    assert_eq!(
        profile(Algorithm::Rs256, Kind::Jwt, &set(&[&other]))
            .expect("a profile")
            .verify(vectors::RS256_TOKEN)
            .err(),
        Some(Error::Key)
    );
}

#[test]
fn a_key_set_keeps_the_restrictions_of_each_key() {
    let verifies = |jwk: &str| {
        profile(Algorithm::Rs256, Kind::Jwt, &set(&[jwk]))
            .and_then(|profile| profile.verify(vectors::RS256_TOKEN).map(drop))
    };
    let with = |member: &str| vectors::RS256_KEY.replacen('{', &format!("{{{member},"), 1);
    // The control: the key joins with a `key_ops` that permits a signature check.
    assert_eq!(verifies(&with(r#""key_ops":["verify"]"#)), Ok(()));
    // A key whose `key_ops` permits no signature check, or whose restriction the reader cannot read, does not join.
    for member in [
        r#""key_ops":["encrypt"]"#,
        r#""key_ops":[]"#,
        r#""key_ops":["verify","verify"]"#,
        r#""key_ops":"verify""#,
        r#""key_ops":["verify",1]"#,
        r#""use":["sig"]"#,
        r#""alg":256"#,
    ] {
        assert_eq!(verifies(&with(member)), Err(Error::Key), "{member}");
    }
    // A set is public: a private member of a key of another type refuses the set. The Ed25519 key is the private key
    // of RFC 8037, appendix A.1.
    let okp = concat!(
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","#,
        r#""d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#
    );
    let private = set(&[vectors::RS256_KEY, okp]);
    assert_eq!(profile(Algorithm::Rs256, Kind::Jwt, &private).err(), Some(Error::Key));
    // The `oth` primes of a private RSA key are objects deeper than the bound of a set, so the set refuses.
    let oth = set(&[&with(r#""oth":[{"r":"AQ","d":"AQ","t":"AQ"}]"#)]);
    assert_eq!(profile(Algorithm::Rs256, Kind::Jwt, &oth).err(), Some(Error::Malformed));
}

/// No published JOSE case has a composite key yet, so rscrypto signs this one.
#[test]
fn a_composite_token_that_rscrypto_signs_verifies() {
    let payload = br#"{"iss":"joe"}"#;
    let (public, secret) = MlDsa65Ed25519::generate_keypair(|out: &mut [u8]| -> Result<(), CompositeMlDsaError> {
        out.fill(6);
        Ok(())
    })
    .expect("a composite key");
    let input = jose::signing_input(Algorithm::MlDsa65Ed25519, None, None, payload).expect("a signing input");
    assert!(input.starts_with(&b64(br#"{"alg":"ML-DSA-65-Ed25519"}"#)));
    let signature = secret.sign_deterministic(input.as_bytes(), &[]).expect("a signature");
    let jwk = format!(
        r#"{{"kty":"AKP","alg":"{}","pub":"{}"}}"#,
        jose::ML_DSA_65_ED25519,
        b64(&public.to_bytes())
    );
    let token = jose::compact(&input, signature.as_bytes());
    profile(Algorithm::MlDsa65Ed25519, Kind::Jwt, &set(&[&jwk]))
        .expect("a profile")
        .verify(&token)
        .unwrap();
}

#[test]
fn a_signing_input_gives_only_tokens_that_verify() {
    let (key, jwk) = ed25519();
    let token = |kid: Option<&str>, payload: &[u8]| {
        jose::signing_input(Algorithm::Ed25519, kid, None, payload)
            .map(|input| jose::compact(&input, &key.sign(input.as_bytes()).to_bytes()))
    };
    // In base64url the header `{"alg":"Ed25519"}` has 23 characters and a signature of 64 bytes has 86. Of the 16,384
    // bytes of a token, 16,273 then remain for the payload, after the two dots. 12,204 bytes take 16,272 of them.
    let unnamed = profile(Algorithm::Ed25519, Kind::Jwt, &set(&[&jwk])).expect("a profile");
    let longest = token(None, &[7; 12_204]).expect("a token");
    assert_eq!(longest.len(), jose::TOKEN_BYTES_MAX - 1);
    assert_eq!(unnamed.verify(&longest).map(|jws| jws.payload().len()), Ok(12_204));
    assert_eq!(token(None, &[7; 12_205]).err(), Some(Error::Limit));
    // A string of the header has at most 1,024 bytes as written, and an escape counts with each of its bytes.
    let kid = "k".repeat(1024);
    let named = profile(
        Algorithm::Ed25519,
        Kind::Jwt,
        &set(&[&jwk.replacen('{', &format!(r#"{{"kid":"{kid}","#), 1)]),
    )
    .expect("a profile");
    let longest_kid = token(Some(&kid), b"{}").expect("a token");
    assert_eq!(
        named.verify(&longest_kid).map(|jws| jws.kid().map(String::from)),
        Ok(Some(kid))
    );
    assert_eq!(token(Some(&"k".repeat(1025)), b"{}").err(), Some(Error::Limit));
    assert_eq!(token(Some(&"\"".repeat(513)), b"{}").err(), Some(Error::Limit));
}

#[test]
fn a_header_that_does_not_match_its_profile_refuses() {
    let rs256 = profile(Algorithm::Rs256, Kind::Jwt, &set(&[vectors::RS256_KEY])).expect("a profile");
    let cases = [
        (r#"{"alg":"none"}"#, Error::Algorithm),
        (r#"{"alg":"ES256"}"#, Error::Algorithm),
        (r#"{"alg":"rs256"}"#, Error::Algorithm),
        (
            r#"{"alg":"RS256","jku":"https://attacker.example/keys"}"#,
            Error::Header,
        ),
        (
            r#"{"alg":"RS256","x5u":"https://attacker.example/cert"}"#,
            Error::Header,
        ),
        (r#"{"alg":"RS256","jwk":{"kty":"oct","k":"AA"}}"#, Error::Header),
        (r#"{"alg":"RS256","crit":["exp"],"exp":1}"#, Error::Header),
        // RFC 7797 requires `crit` with `b64`, so a `b64` with no `crit` refuses too.
        (r#"{"alg":"RS256","b64":false}"#, Error::Header),
        // The names compare after unescape: `\u006aku` is `jku`.
        (
            r#"{"alg":"RS256","\u006aku":"https://attacker.example/keys"}"#,
            Error::Header,
        ),
        (r#"{"alg":"RS256","kid":"another key"}"#, Error::Key),
        (r#"{"typ":"JWT"}"#, Error::Malformed),
    ];
    for (header, error) in cases {
        assert_eq!(rs256.verify(&unsigned(header)).err(), Some(error), "{header}");
    }
    assert_eq!(rs256.verify("a.b.c.d").err(), Some(Error::Malformed));
    assert_eq!(
        rs256.verify(&"a".repeat(jose::TOKEN_BYTES_MAX + 1)).err(),
        Some(Error::Limit)
    );
}

#[test]
fn an_hmac_token_keyed_with_the_public_key_refuses() {
    // The algorithm-confusion attack: an HS256 token whose HMAC key is the public RSA key of the profile, here its
    // RSAPublicKey DER. A verifier that takes the algorithm from the header accepts it.
    let n = member(vectors::RS256_KEY, "n");
    let public = RsaPublicKey::from_modulus_exponent_with_policy(&n, 65_537, &RSA_POLICY)
        .expect("an RSA key")
        .to_pkcs1_der();
    let header = b64(br#"{"alg":"HS256"}"#);
    let input = format!("{header}.{}", b64(br#"{"iss":"joe"}"#));
    let tag = HmacSha256::mac(&public, input.as_bytes());
    let token = jose::compact(&input, tag.as_bytes());
    let rs256 = profile(Algorithm::Rs256, Kind::Jwt, &set(&[vectors::RS256_KEY])).expect("a profile");
    assert_eq!(rs256.verify(&token).err(), Some(Error::Algorithm));
}

#[test]
fn the_claims_of_a_jwt_hold_at_the_reading() {
    let (_, jwk) = ed25519();
    let jwts = profile(Algorithm::Ed25519, Kind::Jwt, &set(&[&jwk])).expect("a profile");
    let claims = |claims: &str| format!(r#"{{"iss":"{ISSUER}","aud":"{AUDIENCE}",{claims}}}"#);
    let jwt_at = |claims: &str, now: Reading| jwts.verify_jwt(&jwt(None, claims), now).map(|jwt| jwt.claims().exp);
    assert_eq!(jwt_at(&claims(r#""exp":1000"#), at(900)), Ok(Some(1000)));
    // The reading can be one second late: an `exp` within the bound refuses.
    assert_eq!(jwt_at(&claims(r#""exp":1000"#), at(999)), Err(Error::Expired));
    assert_eq!(jwt_at(&claims(r#""exp":1000,"nbf":950"#), at(900)), Err(Error::NotYet));
    assert_eq!(jwt_at(&claims(r#""exp":1000,"nbf":950"#), at(951)), Ok(Some(1000)));
    assert_eq!(jwt_at(&claims(r#""sub":"alice""#), at(900)), Err(Error::Claims));
    assert_eq!(jwt_at(&claims(r#""exp":"1000""#), at(900)), Err(Error::Claims));
    let many = format!(r#"{{"iss":"{ISSUER}","aud":["https://other.example","{AUDIENCE}"],"exp":1000}}"#);
    assert_eq!(jwt_at(&many, at(900)), Ok(Some(1000)));
    let other = format!(r#"{{"iss":"{ISSUER}","aud":"https://other.example","exp":1000}}"#);
    assert_eq!(jwt_at(&other, at(900)), Err(Error::Audience));
    let issuer = format!(r#"{{"iss":"https://attacker.example","aud":"{AUDIENCE}","exp":1000}}"#);
    assert_eq!(jwt_at(&issuer, at(900)), Err(Error::Issuer));
    let unknown = Reading::new(Duration::from_secs(900), None, ReadingSource::Caller);
    assert_eq!(
        jwt_at(&claims(r#""exp":1000"#), unknown)
            .err()
            .map(|error| matches!(error, Error::Time(_))),
        Some(true)
    );
}

#[test]
fn an_access_token_has_its_type_and_the_claims_of_rfc_9068() {
    let (_, jwk) = ed25519();
    let access = profile(Algorithm::Ed25519, Kind::Access, &set(&[&jwk])).expect("a profile");
    let full = format!(
        r#"{{"iss":"{ISSUER}","aud":"{AUDIENCE}","exp":1000,"sub":"agent-1","client_id":"cli","iat":800,"jti":"t-1","scope":"repo.read"}}"#
    );
    for typ in ["at+jwt", "application/at+JWT"] {
        let jwt = access.verify_jwt(&jwt(Some(typ), &full), at(900)).expect(typ);
        assert_eq!(jwt.claims().scope.as_deref(), Some("repo.read"));
    }
    assert_eq!(
        access.verify_jwt(&jwt(Some("JWT"), &full), at(900)).err(),
        Some(Error::Type)
    );
    assert_eq!(access.verify_jwt(&jwt(None, &full), at(900)).err(), Some(Error::Type));
    let partial = full.replace(r#","client_id":"cli""#, "");
    assert_eq!(
        access.verify_jwt(&jwt(Some("at+jwt"), &partial), at(900)).err(),
        Some(Error::Claims)
    );
}
