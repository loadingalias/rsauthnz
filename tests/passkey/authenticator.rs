//! A test authenticator: it makes passkeys with rscrypto, and the registration responses of WebAuthn Level 3
//! (`RegistrationResponseJSON`) with the algorithm, the flags, the counter, the challenge, and the origin that a test
//! chooses. A test of a defect that a browser shows uses it. It is never exit evidence: real browsers and
//! authenticators are.

use rsauthnz::cbor::{self, Value};
use rsauthnz::crypto::Algorithm;
use rsauthnz::limits::Limits;
use rscodec::json::{self, Slot};
use rscrypto::auth::{EcdsaP256SecretKey, Ed25519SecretKey, MlDsa65, MlDsaError};

/// The flags of the authenticator data.
pub(crate) const USER_PRESENT: u8 = 0x01;
pub(crate) const USER_VERIFIED: u8 = 0x04;
pub(crate) const BACKUP_ELIGIBLE: u8 = 0x08;
pub(crate) const BACKUP_STATE: u8 = 0x10;
pub(crate) const ATTESTED: u8 = 0x40;
pub(crate) const EXTENSIONS: u8 = 0x80;

/// The flags of a new passkey of a platform authenticator that synchronizes it.
pub(crate) const SYNCHRONIZED: u8 = USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKUP_STATE | ATTESTED;

/// The CBOR value of the integer `value`.
pub(crate) fn int(value: i64) -> Value<'static> {
    if value >= 0 {
        Value::Unsigned(value.unsigned_abs())
    } else {
        Value::Negative(value.unsigned_abs() - 1)
    }
}

/// A passkey: its credential ID and its `COSE_Key`.
pub(crate) struct Passkey {
    pub id: Vec<u8>,
    pub cose_key: Vec<u8>,
}

impl Passkey {
    /// The passkey of `algorithm` whose key and ID come from `seed`, with `alg` in its `COSE_Key`: authenticators write
    /// EdDSA (-8) for Ed25519, ES256 (-7), and ML-DSA-65 (-49).
    pub(crate) fn new(algorithm: Algorithm, alg: i64, seed: u8) -> Self {
        let cose_key = match algorithm {
            Algorithm::Ed25519 => {
                let x = Ed25519SecretKey::from_bytes([seed; 32]).public_key().to_bytes();
                cose(1, alg, &[(-1, Value::Unsigned(6)), (-2, Value::Bytes(&x))])
            }
            Algorithm::Es256 => {
                let point = EcdsaP256SecretKey::from_bytes([seed; 32])
                    .expect("a P-256 scalar")
                    .public_key()
                    .to_sec1_bytes();
                let (x, y) = point[1..].split_at(32);
                cose(
                    2,
                    alg,
                    &[(-1, Value::Unsigned(1)), (-2, Value::Bytes(x)), (-3, Value::Bytes(y))],
                )
            }
            Algorithm::MlDsa65 => {
                let fill = |out: &mut [u8]| -> Result<(), MlDsaError> {
                    out.fill(seed);
                    Ok(())
                };
                let (public, _) = MlDsa65::generate_keypair(fill).expect("an ML-DSA-65 key");
                cose(7, alg, &[(-1, Value::Bytes(public.as_bytes()))])
            }
            _ => panic!("the test authenticator has no {algorithm:?} key"),
        };
        Self {
            id: vec![seed; 16],
            cose_key,
        }
    }
}

/// The `COSE_Key` of the key type `kty` and the algorithm `alg` with `parameters`.
fn cose(kty: u64, alg: i64, parameters: &[(i64, Value<'_>)]) -> Vec<u8> {
    let mut members: Vec<_> = parameters
        .iter()
        .map(|(label, value)| (int(*label), value.clone()))
        .collect();
    members.extend([(int(1), Value::Unsigned(kty)), (int(3), int(alg))]);
    cbor::encode(&Value::Map(members), Limits::default()).expect("a COSE_Key")
}

/// A registration that a test makes: each part of the response that a test can change.
pub(crate) struct Registration<'a> {
    pub passkey: &'a Passkey,
    pub rp_id: &'a str,
    pub origin: &'a str,
    pub challenge: [u8; 32],
    pub kind: &'a str,
    pub cross_origin: bool,
    pub flags: u8,
    pub sign_count: u32,
    /// The CBOR of the extension outputs of the authenticator data. A test sets [`EXTENSIONS`] with it.
    pub extensions: Option<Vec<u8>>,
    /// The `rk` of the `credProps` extension, or `None` for a browser that gives no `credProps`.
    pub discoverable: Option<bool>,
}

impl<'a> Registration<'a> {
    /// The registration of `passkey` at `rp_id` and `origin` for `challenge`, as a synchronized platform passkey.
    pub(crate) fn new(passkey: &'a Passkey, rp_id: &'a str, origin: &'a str, challenge: [u8; 32]) -> Self {
        Self {
            passkey,
            rp_id,
            origin,
            challenge,
            kind: "webauthn.create",
            cross_origin: false,
            flags: SYNCHRONIZED,
            sign_count: 0,
            extensions: None,
            discoverable: Some(true),
        }
    }

    /// The `clientDataJSON`.
    pub(crate) fn client_data(&self) -> Vec<u8> {
        write(|place| {
            place.object(|data| {
                data.member("type").str(self.kind)?;
                data.member("challenge").base64url(&self.challenge)?;
                data.member("origin").str(self.origin)?;
                data.member("crossOrigin").bool(self.cross_origin)
            })
        })
    }

    /// The authenticator data.
    pub(crate) fn authenticator_data(&self) -> Vec<u8> {
        let mut data = crypto_sha256(self.rp_id.as_bytes()).to_vec();
        data.push(self.flags);
        data.extend_from_slice(&self.sign_count.to_be_bytes());
        data.extend_from_slice(&[0; 16]);
        let length = u16::try_from(self.passkey.id.len()).expect("a credential ID of at most 65,535 bytes");
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(&self.passkey.id);
        data.extend_from_slice(&self.passkey.cose_key);
        if let Some(extensions) = &self.extensions {
            data.extend_from_slice(extensions);
        }
        data
    }

    /// The `RegistrationResponseJSON`, with an attestation object of the format `none`.
    pub(crate) fn json(&self) -> Vec<u8> {
        let data = self.authenticator_data();
        let attestation = Value::Map(vec![
            (Value::Text("fmt"), Value::Text("none")),
            (Value::Text("attStmt"), Value::Map(Vec::new())),
            (Value::Text("authData"), Value::Bytes(&data)),
        ]);
        let attestation = cbor::encode(&attestation, Limits::default()).expect("an attestation object");
        response(&self.passkey.id, &self.client_data(), &attestation, self.discoverable)
    }
}

/// The `RegistrationResponseJSON` of the credential `id` with `client_data` and `attestation`.
pub(crate) fn response(id: &[u8], client_data: &[u8], attestation: &[u8], discoverable: Option<bool>) -> Vec<u8> {
    write(|place| {
        place.object(|response| {
            response.member("id").base64url(id)?;
            response.member("rawId").base64url(id)?;
            response.member("response").object(|inner| {
                inner.member("clientDataJSON").base64url(client_data)?;
                inner.member("attestationObject").base64url(attestation)?;
                inner.member("transports").array(|transports| {
                    transports.item().str("internal")?;
                    transports.item().str("hybrid")
                })
            })?;
            response.member("type").str("public-key")?;
            response.member("authenticatorAttachment").str("platform")?;
            response
                .member("clientExtensionResults")
                .object(|results| match discoverable {
                    Some(rk) => results.member("credProps").object(|props| props.member("rk").bool(rk)),
                    None => Ok(()),
                })
        })
    })
}

/// The JSON text that `value` writes.
fn write(value: impl FnOnce(json::Place<'_>) -> Result<(), json::Error>) -> Vec<u8> {
    let mut out = vec![0; 64 * 1024];
    let len = json::write(&mut out, value).expect("a JSON text of at most 64 KiB");
    out.truncate(len);
    out
}

/// The SHA-256 digest of `bytes`.
fn crypto_sha256(bytes: &[u8]) -> [u8; 32] {
    rscrypto::Sha256::digest(bytes)
}

/// The challenge of the creation options `options`.
pub(crate) fn challenge(options: &[u8]) -> [u8; 32] {
    let limits = json::Limits {
        input_bytes_max: 8192,
        depth_max: 4,
        string_bytes_max: 1024,
        members_max: 16,
        elements_max: 8,
        number_digits_max: 16,
    };
    let mut scratch = [Slot::EMPTY; 80];
    let text = json::read(options, &limits, json::Profile::IJson, &mut scratch, |reader| {
        let mut challenge = None;
        let mut members = reader.value().members()?;
        while let Some((name, value)) = members.next()? {
            if name == "challenge" {
                challenge = value.str()?.borrowed();
            }
        }
        Ok(challenge)
    })
    .expect("options in JSON")
    .expect("a challenge");
    let mut bytes = [0; 32];
    rscodec::base64::Profile::Url
        .decode(text.as_bytes(), &mut bytes)
        .expect("a challenge of 32 bytes");
    bytes
}
