//! The release of a credential that a transition issues: only the accepted commit of that transition gives it.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use rscodec::base64::Profile::Url;
use rscodec::json;

use super::Serial;
use crate::crypto;
use crate::transition::{self, Operation, OperationId, Outcome, Prepared, Proposal, Recover, Recovery};

/// An issuance whose proposal waits for its commit. It holds no credential, only the SHA-256 digest of its credential,
/// so it releases only that credential ([`Self::release`]).
#[derive(Debug)]
pub struct Awaiting {
    operation: OperationId,
    digest: [u8; 32],
    serial: Serial,
    issued: Duration,
    expires: Duration,
}

impl Awaiting {
    /// The issuance of `prepared`, the credential of the serial `serial` with the validity interval from `issued` to
    /// `expires`, which `proposal` commits.
    pub(crate) fn new(
        proposal: &Proposal,
        prepared: &Prepared,
        serial: Serial,
        issued: Duration,
        expires: Duration,
    ) -> Self {
        Self {
            operation: proposal.operation().id.clone(),
            digest: crypto::sha256(prepared.bytes()),
            serial,
            issued,
            expires,
        }
    }

    /// The serial of the credential. The commit writes the issuance record of this serial
    /// ([`record_key`](super::record_key)).
    #[must_use]
    pub const fn serial(&self) -> Serial {
        self.serial
    }

    /// The credential that the accepted commit of the proposal of this issuance releases: the credential of this
    /// issuance, with its serial and its validity interval. Each other outcome gives no credential, also the receipt of
    /// another issuance under the same operation.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Release::Unknown`] if the commit can have occurred, [`Release::Conflict`] if a dependency changed first, and
    /// [`Release::Refused`] if the commit refused. [`Release::Committed`] if an earlier submission of the operation
    /// committed, so that this one releases nothing. [`Release::Operation`] for the outcome of another operation, and
    /// for the receipt of another issuance under this operation.
    pub fn release(self, outcome: Outcome) -> Result<Released, Release> {
        match outcome {
            Outcome::Accepted(receipt) if *receipt.operation() == self.operation => {
                let bytes = receipt.artifact().ok_or(Release::Committed)?;
                (crypto::sha256(bytes) == self.digest).ok_or(Release::Operation)?;
                Ok(Released {
                    bytes: bytes.into(),
                    serial: self.serial,
                    issued: self.issued,
                    expires: self.expires,
                })
            }
            Outcome::Accepted(_) => Err(Release::Operation),
            Outcome::Conflict => Err(Release::Conflict),
            Outcome::Refused(error) => Err(Release::Refused(error)),
            Outcome::Unknown(operation) => Err(Release::Unknown(operation)),
        }
    }
}

/// A credential that the accepted commit of its issuance released: its encoded bytes, its serial, and its validity
/// interval. `Debug` shows the length of the bytes, and never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Released {
    bytes: Box<[u8]>,
    serial: Serial,
    issued: Duration,
    expires: Duration,
}

impl Released {
    /// The encoded credential.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The serial.
    #[must_use]
    pub const fn serial(&self) -> Serial {
        self.serial
    }

    /// The end of the credential, as the time since the Unix epoch. The credential is not valid at this time and
    /// after it.
    #[must_use]
    pub const fn expires(&self) -> Duration {
        self.expires
    }

    /// The time to renew the credential: half its lifetime after its issue time, as the time since the Unix epoch.
    #[must_use]
    pub fn renew_at(&self) -> Duration {
        self.issued.saturating_add(self.expires.saturating_sub(self.issued) / 2)
    }

    /// The JSON body of the answer that gives the credential: `{"credential","expires","renew_at"}`, with the
    /// base64url of the credential, and each time in whole seconds since the Unix epoch.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn json(&self) -> Vec<u8> {
        let encoded = Url
            .encoded_len(self.bytes.len())
            .expect("a credential has at most 8,192 bytes");
        // The names and the two times are less than 128 bytes.
        let mut out = vec![0; 128 + encoded];
        let len = json::write(&mut out, |place| {
            place.object(|body| {
                body.member("credential").base64url(&self.bytes)?;
                body.member("expires").u64(self.expires.as_secs())?;
                body.member("renew_at").u64(self.renew_at().as_secs())
            })
        })
        .expect("the body fits its buffer");
        out.truncate(len);
        out
    }
}

impl fmt::Debug for Released {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Released")
            .field("len", &self.bytes.len())
            .field("serial", &self.serial)
            .field("issued", &self.issued)
            .field("expires", &self.expires)
            .finish()
    }
}

/// Why an outcome released no credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Release {
    /// A dependency changed before the commit, so nothing committed. Read the records again, and ask again as a new
    /// operation.
    Conflict,
    /// The commit can have occurred: its response was lost. Look up the operation, and never ask again as a new
    /// operation before the lookup answers. A credential whose response was lost is never released.
    Unknown(Operation),
    /// An earlier submission of the operation committed, so this one releases nothing. Ask for a credential as a new
    /// operation.
    Committed,
    /// The outcome is of another operation, or the receipt is of another issuance under the same operation.
    Operation,
    /// The commit refused. Its error gives the recovery.
    Refused(transition::Error),
}

impl Recover for Release {
    /// [`Recovery::Lookup`] after [`Release::Unknown`], [`Recovery::Restart`] after [`Release::Conflict`] and
    /// [`Release::Committed`], the recovery of the commit after [`Release::Refused`], and [`Recovery::Refuse`] after
    /// [`Release::Operation`].
    fn recovery(&self) -> Recovery {
        match self {
            Self::Unknown(_) => Recovery::Lookup,
            Self::Conflict | Self::Committed => Recovery::Restart,
            Self::Refused(error) => error.recovery(),
            Self::Operation => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => f.write_str("a dependency changed before the commit"),
            Self::Unknown(_) => f.write_str("the outcome of the commit is unknown"),
            Self::Committed => f.write_str("an earlier submission of the operation committed"),
            Self::Operation => f.write_str("the outcome is of another operation or another issuance"),
            Self::Refused(error) => write!(f, "the commit refused: {error}"),
        }
    }
}

impl core::error::Error for Release {}
