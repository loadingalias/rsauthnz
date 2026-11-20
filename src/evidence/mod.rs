//! Authentication evidence: the facts that one authentication proved, and no others.
//!
//! [`Evidence`] records the principal, the method, the time, and each property that the
//! authentication established: user verification, phishing resistance, recovery, a device or
//! hardware binding of the key, and the authentication of the signature: hybrid, post-quantum, or
//! classical. It has no strength score, and a recovery never records phishing resistance. Only the
//! verifiers of this crate make evidence, so a caller cannot mark an unverified claim as proved.

use alloc::vec;
use core::fmt;
use core::time::Duration;

use crate::cbor::Value;
use crate::crypto::Authentication;
use crate::id::{IdError, Principal};
use crate::time::{Reading, ReadingSource};

/// The facts that one authentication proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    subject: Principal,
    method: Method,
    time: Reading,
    user_verified: bool,
    phishing_resistant: bool,
    binding: Option<Binding>,
    authentication: Option<Authentication>,
}

/// How the authentication proved the principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// A WebAuthn passkey assertion.
    Passkey,
    /// A sign-in at an external identity provider.
    Provider,
    /// A one-use recovery value. The authentication is a recovery.
    Recovery,
    /// A one-use bootstrap value of an authority.
    Bootstrap,
    /// A signature with an enrolled key that proves its possession, such as the key of a native
    /// CLI, a workload, or an agent.
    KeyPossession,
}

/// Where the key of the authentication lives, when the authentication proved it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Binding {
    /// The key cannot leave one device.
    Device,
    /// The key is in hardware that refuses to export it, such as a TPM, a secure enclave, or a
    /// security key.
    Hardware,
}

impl Evidence {
    /// Makes the evidence of one authentication. `phishing_resistant` is true when the proof binds
    /// the origin, as a passkey assertion does; the evidence of a recovery drops it.
    /// `authentication` is the authentication of the signature that proved the principal.
    pub(crate) fn new(
        subject: Principal,
        method: Method,
        time: Reading,
        user_verified: bool,
        phishing_resistant: bool,
        binding: Option<Binding>,
        authentication: Option<Authentication>,
    ) -> Self {
        Self {
            subject,
            method,
            time,
            user_verified,
            phishing_resistant: phishing_resistant && method != Method::Recovery,
            binding,
            authentication,
        }
    }

    /// The principal that the authentication proved.
    #[must_use]
    pub const fn subject(&self) -> &Principal {
        &self.subject
    }

    /// The method of the authentication.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// The physical time of the authentication.
    #[must_use]
    pub const fn time(&self) -> Reading {
        self.time
    }

    /// Whether the authenticator verified its user, for example with a PIN or a biometric.
    #[must_use]
    pub const fn user_verified(&self) -> bool {
        self.user_verified
    }

    /// Whether the proof binds the origin, so a phishing site could not use it. A recovery is never
    /// phishing resistant.
    #[must_use]
    pub const fn phishing_resistant(&self) -> bool {
        self.phishing_resistant
    }

    /// Whether the authentication is a recovery.
    #[must_use]
    pub fn recovery(&self) -> bool {
        self.method == Method::Recovery
    }

    /// The binding of the key, or `None` when the authentication did not prove one.
    #[must_use]
    pub const fn binding(&self) -> Option<Binding> {
        self.binding
    }

    /// The authentication of the signature that proved the principal, or `None` when this crate
    /// verified no signature of the principal, as for a recovery value. A classical signature gives
    /// no post-quantum authentication. Post-quantum key exchange is a separate guarantee of the
    /// transport.
    #[must_use]
    pub const fn authentication(&self) -> Option<Authentication> {
        self.authentication
    }

    /// The canonical CBOR form: the array `[subject, method, time, user verified, phishing
    /// resistant, binding, authentication]`. The method, the binding, and the authentication are
    /// numbers, with `null` for no binding and for no authentication. The time is `[estimate, bound,
    /// source]`: the estimate of the Unix time as `[seconds, nanoseconds]`, the bound in the same
    /// form or `null` when it is unknown, and the source as a number.
    #[must_use]
    pub fn to_cbor(&self) -> Value<'_> {
        Value::Array(vec![
            self.subject.to_cbor(),
            Value::Unsigned(match self.method {
                Method::Passkey => 1,
                Method::Provider => 2,
                Method::Recovery => 3,
                Method::Bootstrap => 4,
                Method::KeyPossession => 5,
            }),
            reading_to_cbor(self.time),
            Value::Bool(self.user_verified),
            Value::Bool(self.phishing_resistant),
            match self.binding {
                None => Value::Null,
                Some(Binding::Device) => Value::Unsigned(1),
                Some(Binding::Hardware) => Value::Unsigned(2),
            },
            match self.authentication {
                None => Value::Null,
                Some(Authentication::Hybrid) => Value::Unsigned(1),
                Some(Authentication::PostQuantum) => Value::Unsigned(2),
                Some(Authentication::Classical) => Value::Unsigned(3),
            },
        ])
    }

    /// Reads the canonical CBOR form of evidence that this crate wrote, for example from the storage
    /// of a session. A storage binding outside this crate never rebuilds evidence: it stores the
    /// encoded bytes of [`Self::to_cbor`] as opaque bytes and gives them back, and this crate reads
    /// them.
    ///
    /// # Errors
    ///
    /// [`EvidenceError::Subject`] for a subject that is not a principal, and [`EvidenceError::Form`]
    /// for each other difference from the canonical form, also a recovery that records phishing
    /// resistance.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the sessions of A2 read the evidence that they store")
    )]
    pub(crate) fn from_cbor(value: &Value<'_>) -> Result<Self, EvidenceError> {
        let Value::Array(items) = value else {
            return Err(EvidenceError::Form);
        };
        let [
            subject,
            Value::Unsigned(method),
            time,
            Value::Bool(user_verified),
            Value::Bool(phishing_resistant),
            binding,
            authentication,
        ] = items.as_slice()
        else {
            return Err(EvidenceError::Form);
        };
        let method = match method {
            1 => Method::Passkey,
            2 => Method::Provider,
            3 => Method::Recovery,
            4 => Method::Bootstrap,
            5 => Method::KeyPossession,
            _ => return Err(EvidenceError::Form),
        };
        let binding = match binding {
            Value::Null => None,
            Value::Unsigned(1) => Some(Binding::Device),
            Value::Unsigned(2) => Some(Binding::Hardware),
            _ => return Err(EvidenceError::Form),
        };
        let authentication = match authentication {
            Value::Null => None,
            Value::Unsigned(1) => Some(Authentication::Hybrid),
            Value::Unsigned(2) => Some(Authentication::PostQuantum),
            Value::Unsigned(3) => Some(Authentication::Classical),
            _ => return Err(EvidenceError::Form),
        };
        if *phishing_resistant && method == Method::Recovery {
            return Err(EvidenceError::Form);
        }
        Ok(Self {
            subject: Principal::from_cbor(subject).map_err(EvidenceError::Subject)?,
            method,
            time: reading_from_cbor(time).ok_or(EvidenceError::Form)?,
            user_verified: *user_verified,
            phishing_resistant: *phishing_resistant,
            binding,
            authentication,
        })
    }
}

/// The cause of refused evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// The subject is not a valid principal.
    Subject(IdError),
    /// The CBOR form is not the canonical form of evidence.
    Form,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subject(error) => write!(f, "the subject of the evidence is not valid: {error}"),
            Self::Form => f.write_str("the CBOR form is not evidence"),
        }
    }
}

impl core::error::Error for EvidenceError {}

/// The CBOR form of a reading. A source that this crate does not know is `null`, which does not
/// read back; the pinned `rstypes` has no such source.
fn reading_to_cbor(reading: Reading) -> Value<'static> {
    Value::Array(vec![
        duration_to_cbor(reading.estimate()),
        reading.bound().map_or(Value::Null, duration_to_cbor),
        match reading.source() {
            ReadingSource::SystemClock => Value::Unsigned(1),
            ReadingSource::Caller => Value::Unsigned(2),
            _ => Value::Null,
        },
    ])
}

fn reading_from_cbor(value: &Value<'_>) -> Option<Reading> {
    let Value::Array(items) = value else {
        return None;
    };
    let [estimate, bound, Value::Unsigned(source)] = items.as_slice() else {
        return None;
    };
    let source = match source {
        1 => ReadingSource::SystemClock,
        2 => ReadingSource::Caller,
        _ => return None,
    };
    let bound = match bound {
        Value::Null => None,
        bound => Some(duration_from_cbor(bound)?),
    };
    Some(Reading::new(duration_from_cbor(estimate)?, bound, source))
}

/// `[seconds, nanoseconds]`.
fn duration_to_cbor(duration: Duration) -> Value<'static> {
    Value::Array(vec![
        Value::Unsigned(duration.as_secs()),
        Value::Unsigned(u64::from(duration.subsec_nanos())),
    ])
}

fn duration_from_cbor(value: &Value<'_>) -> Option<Duration> {
    let Value::Array(items) = value else {
        return None;
    };
    let [Value::Unsigned(seconds), Value::Unsigned(nanos)] = items.as_slice() else {
        return None;
    };
    let nanos = u32::try_from(*nanos).ok().filter(|&nanos| nanos < 1_000_000_000)?;
    Some(Duration::new(*seconds, nanos))
}

#[cfg(test)]
mod tests;
