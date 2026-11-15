//! The facade of rscrypto: the only module of the core that calls it. Each signature check of the crate passes
//! through [`Verifier::verify`], and a test build counts each call.

use alloc::boxed::Box;

use rscrypto::auth::{
    EcdsaP256PublicKey, EcdsaP256Signature, Ed25519PublicKey, Ed25519Signature, MlDsa65PublicKey, MlDsa65Signature,
};

/// A public key that verifies the signatures of one algorithm.
#[derive(Clone)]
pub(crate) enum Verifier {
    Ed25519(Ed25519PublicKey),
    Es256(Box<EcdsaP256PublicKey>),
    MlDsa65(Box<MlDsa65PublicKey>),
}

impl Verifier {
    /// The Ed25519 key with the encoded point `x`.
    pub(crate) fn ed25519(x: &[u8; 32]) -> Self {
        Self::Ed25519(Ed25519PublicKey::from_bytes(*x))
    }

    /// The P-256 key with the coordinates `x` and `y`, or `None` if the point is not on the curve.
    pub(crate) fn es256(x: &[u8; 32], y: &[u8; 32]) -> Option<Self> {
        let mut sec1 = [0x04; EcdsaP256PublicKey::SEC1_LENGTH];
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        let key = EcdsaP256PublicKey::from_sec1_bytes(&sec1).ok()?;
        Some(Self::Es256(Box::new(key)))
    }

    /// The ML-DSA-65 key with the encoding `public`.
    pub(crate) fn ml_dsa_65(public: &[u8; 1952]) -> Self {
        Self::MlDsa65(Box::new(MlDsa65PublicKey::from_bytes(*public)))
    }

    /// Whether `signature` is a valid signature over `message`. ML-DSA-65 uses the pure form with the empty context.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        #[cfg(test)]
        CALLS.with(|calls| calls.set(calls.get() + 1));
        match self {
            Self::Ed25519(key) => <[u8; 64]>::try_from(signature)
                .is_ok_and(|signature| key.verify(message, &Ed25519Signature::from_bytes(signature)).is_ok()),
            Self::Es256(key) => <[u8; 64]>::try_from(signature)
                .ok()
                .and_then(|signature| EcdsaP256Signature::from_bytes(signature).ok())
                .is_some_and(|signature| key.verify(message, &signature).is_ok()),
            Self::MlDsa65(key) => MlDsa65Signature::try_from_slice(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
        }
    }
}

/// Two keys are equal when their algorithms and their public keys are equal.
impl PartialEq for Verifier {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ed25519(a), Self::Ed25519(b)) => a.as_bytes() == b.as_bytes(),
            (Self::Es256(a), Self::Es256(b)) => a.to_sec1_bytes() == b.to_sec1_bytes(),
            (Self::MlDsa65(a), Self::MlDsa65(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Verifier {}

#[cfg(test)]
thread_local! {
    /// The signature calls of this thread. Each test runs on its own thread, so a test counts only its own calls.
    static CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The signature calls of this thread so far.
#[cfg(test)]
pub(crate) fn calls() -> usize {
    CALLS.with(core::cell::Cell::get)
}
