//! `COSE_Sign1` (RFC 9052 section 4.2) and its header buckets.

use alloc::vec::Vec;
use core::fmt;

use super::{Error, TrustedKey, alg, label};
use crate::cbor::{self, Value};
use crate::limits::{Limits, SignatureBudget};

/// The tag of a `COSE_Sign1` (RFC 9052 section 2).
const SIGN1_TAG: u64 = 18;

/// The labels of the headers that this crate processes: `alg` (1), `content type` (3), and `kid` (4). A `crit`
/// header can name only these.
const PROCESSED: [i64; 3] = [1, 3, 4];

/// One header bucket: its labels and values, in the order of the decoder. The values are untrusted. Thus a header
/// that this crate does not process stays in the bucket, and it has no effect on verification.
#[derive(Clone, Debug)]
pub struct Header<'a>(Vec<(Value<'a>, Value<'a>)>);

impl<'a> Header<'a> {
    /// The value of the header with the integer label `label`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn get(&self, label: i64) -> Option<&Value<'a>> {
        let label = super::label(label);
        self.0.iter().find(|(key, _)| *key == label).map(|(_, value)| value)
    }

    /// Each label and value of the bucket.
    #[must_use]
    pub fn entries(&self) -> &[(Value<'a>, Value<'a>)] {
        &self.0
    }

    /// Reads a header map. Each label is an integer or a text string, and the decoder already refused equal labels.
    fn from_value(value: Value<'a>) -> Result<Self, Error> {
        let Value::Map(entries) = value else {
            return Err(Error::Malformed);
        };
        for (key, value) in &entries {
            let typed = match key {
                Value::Unsigned(1) => is_label(value),
                Value::Unsigned(2) => {
                    matches!(value, Value::Array(labels) if !labels.is_empty() && labels.iter().all(is_label))
                }
                Value::Unsigned(3) => matches!(value, Value::Unsigned(_) | Value::Text(_)),
                Value::Unsigned(4) => matches!(value, Value::Bytes(_)),
                key => is_label(key),
            };
            if !typed {
                return Err(Error::Malformed);
            }
        }
        Ok(Self(entries))
    }
}

/// Whether `value` is a label: an integer or a text string.
const fn is_label(value: &Value<'_>) -> bool {
    matches!(value, Value::Unsigned(_) | Value::Negative(_) | Value::Text(_))
}

/// A decoded `COSE_Sign1`. Each part is untrusted until [`Self::verify`] succeeds.
#[derive(Clone)]
pub struct Sign1<'a> {
    protected_bytes: &'a [u8],
    protected: Header<'a>,
    unprotected: Header<'a>,
    payload: &'a [u8],
    signature: &'a [u8],
}

impl<'a> Sign1<'a> {
    /// Decodes the `COSE_Sign1` that fills `input`, with its tag (18) or without a tag. The decoder applies `limits`
    /// to `input` and to the protected header in it.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Cbor`] if the CBOR decoder refuses the input, [`Error::Unsupported`] for a detached payload, and
    /// [`Error::UnknownCritical`] if `crit` names a header that this crate does not process. [`Error::Malformed`]
    /// for each other difference from RFC 9052: a label in both buckets, a `crit` header that is not protected, or a
    /// `crit` label that the protected bucket does not have.
    pub fn decode(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        Self::from_value(cbor::decode(input, limits)?, limits)
    }

    /// Reads a `COSE_Sign1` from its decoded CBOR value, which has the tag 18 or no tag.
    pub(super) fn from_value(value: Value<'a>, limits: Limits) -> Result<Self, Error> {
        let value = match value {
            Value::Tag(SIGN1_TAG, item) => *item,
            value => value,
        };
        let Value::Array(items) = value else {
            return Err(Error::Malformed);
        };
        let Ok(
            [
                Value::Bytes(protected_bytes),
                unprotected,
                payload,
                Value::Bytes(signature),
            ],
        ) = <[Value<'a>; 4]>::try_from(items)
        else {
            return Err(Error::Malformed);
        };
        let payload = match payload {
            Value::Bytes(payload) => payload,
            Value::Null => return Err(Error::Unsupported),
            _ => return Err(Error::Malformed),
        };
        let protected = if protected_bytes.is_empty() {
            Header(Vec::new())
        } else {
            Header::from_value(cbor::decode(protected_bytes, limits)?)?
        };
        let unprotected = Header::from_value(unprotected)?;
        if unprotected.get(2).is_some()
            || unprotected
                .0
                .iter()
                .any(|(key, _)| protected.0.iter().any(|(other, _)| key == other))
        {
            return Err(Error::Malformed);
        }
        if let Some(Value::Array(critical)) = protected.get(2) {
            for key in critical {
                if !protected.0.iter().any(|(other, _)| key == other) {
                    return Err(Error::Malformed);
                }
                if !PROCESSED.iter().any(|&processed| *key == label(processed)) {
                    return Err(Error::UnknownCritical);
                }
            }
        }
        Ok(Self {
            protected_bytes,
            protected,
            unprotected,
            payload,
            signature,
        })
    }

    /// The protected bucket. The signature covers it.
    #[must_use]
    pub const fn protected(&self) -> &Header<'a> {
        &self.protected
    }

    /// The unprotected bucket. The signature does not cover it.
    #[must_use]
    pub const fn unprotected(&self) -> &Header<'a> {
        &self.unprotected
    }

    /// The untrusted payload.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Verifies the signature with `key`, and gives the payload. The check charges `budget`, the budget of the
    /// artifact, before its signature work. The externally supplied data of RFC 9052 section 4.3 is empty.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// The `alg` of the protected bucket must be the algorithm of `key`. The header only matches the algorithm, so
    /// it never selects one. After that match, the check encodes the `Sig_structure` of RFC 9052 section 4.4 into
    /// one allocation of its exact size. It holds one copy of the payload, and it is at most 10 bytes longer than the
    /// decoded `COSE_Sign1`.
    ///
    /// # Errors
    ///
    /// [`Error::AlgorithmMismatch`] if the protected bucket has no `alg` or a different `alg`, [`Error::Limit`] if
    /// the check costs more than `budget` has, and [`Error::Signature`] if the signature does not verify.
    pub fn verify(&self, key: &TrustedKey, budget: &mut SignatureBudget) -> Result<&'a [u8], Error> {
        if alg(key.algorithm()).is_none_or(|alg| self.protected.get(1) != Some(&alg)) {
            return Err(Error::AlgorithmMismatch);
        }
        key.verify(
            &to_be_signed(self.protected_bytes, self.payload),
            self.signature,
            budget,
        )?;
        Ok(self.payload)
    }
}

/// The `Sig_structure` `["Signature1", protected, h'', payload]` of the protected bucket `protected` and the payload
/// `payload`, in one allocation of its exact size. The external AAD is the empty byte string.
pub(crate) fn to_be_signed(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let parts: [(u8, &[u8]); 4] = [(3, b"Signature1"), (2, protected), (2, &[]), (2, payload)];
    // The parts are in a decoded input that the limits bounded, or in a draft that `credential::MAX_BYTES` bounded.
    // Thus the sum cannot overflow.
    let len = cbor::head_len(4)
        + parts
            .iter()
            .map(|(_, bytes)| cbor::head_len(bytes.len() as u64) + bytes.len())
            .sum::<usize>();
    let mut out = Vec::with_capacity(len);
    cbor::head(&mut out, 4, 4);
    // The rscrypto functions take one contiguous message, so this copies the payload one time.
    for (major, bytes) in parts {
        cbor::head(&mut out, major, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }
    debug_assert_eq!(out.len(), len, "the Sig_structure fills its allocation");
    out
}

// The payload can hold a credential. Thus the output shows the headers and only the length of each byte string.
impl fmt::Debug for Sign1<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sign1")
            .field("protected", &self.protected)
            .field("unprotected", &self.unprotected)
            .field("payload_len", &self.payload.len())
            .field("signature_len", &self.signature.len())
            .finish()
    }
}
