//! Authority versions: opaque coordinates of the state of an authority, which each owner orders.

use alloc::boxed::Box;
use alloc::vec;
use core::cmp::Ordering;
use core::fmt;

use super::{Authority, Id, IdError};
use crate::cbor::Value;

/// A version of the state that an authority owns, such as its policy or a grant: the owner and an
/// opaque coordinate.
///
/// The comparison is declared: two versions of one owner compare by their coordinates, byte by
/// byte, and a shorter coordinate that is a prefix of a longer one is earlier. Thus an owner gives
/// each later version a greater coordinate, for example a counter in big-endian bytes of a fixed
/// width. A version is no timestamp, database epoch, or causal clock: a storage binding maps its own
/// coordinates into this form. Versions of two owners do not compare.
///
/// ```
/// use core::cmp::Ordering;
///
/// use rsauthnz::id::{AuthorityVersion, Id, VersionError};
///
/// let owner = Id::new("acme", "policy").map_err(VersionError::Owner)?;
/// let older = AuthorityVersion::new(owner.clone(), &7_u64.to_be_bytes())?;
/// let newer = AuthorityVersion::new(owner, &8_u64.to_be_bytes())?;
/// assert_eq!(older.compare(&newer), Ok(Ordering::Less));
///
/// let other = Id::new("globex", "policy").map_err(VersionError::Owner)?;
/// let foreign = AuthorityVersion::new(other, &8_u64.to_be_bytes())?;
/// assert_eq!(older.compare(&foreign), Err(VersionError::Owners));
/// # Ok::<(), VersionError>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuthorityVersion {
    owner: Id<Authority>,
    coordinate: Box<[u8]>,
}

impl AuthorityVersion {
    /// The most bytes in a coordinate.
    pub const MAX_COORDINATE: usize = 64;

    /// Makes the version `coordinate` of `owner`.
    ///
    /// # Errors
    ///
    /// [`VersionError::Coordinate`] for an empty coordinate or one longer than
    /// [`Self::MAX_COORDINATE`] bytes.
    pub fn new(owner: Id<Authority>, coordinate: &[u8]) -> Result<Self, VersionError> {
        if !(1..=Self::MAX_COORDINATE).contains(&coordinate.len()) {
            return Err(VersionError::Coordinate);
        }
        Ok(Self {
            owner,
            coordinate: coordinate.into(),
        })
    }

    /// The owner.
    #[must_use]
    pub const fn owner(&self) -> &Id<Authority> {
        &self.owner
    }

    /// The opaque coordinate.
    #[must_use]
    pub fn coordinate(&self) -> &[u8] {
        &self.coordinate
    }

    /// Compares two versions of one owner: [`Ordering::Less`] when `self` is earlier than `other`.
    ///
    /// # Errors
    ///
    /// [`VersionError::Owners`] when the owners differ.
    pub fn compare(&self, other: &Self) -> Result<Ordering, VersionError> {
        if self.owner != other.owner {
            return Err(VersionError::Owners);
        }
        Ok(self.coordinate.cmp(&other.coordinate))
    }

    /// The canonical CBOR form: the array `[owner, coordinate]`, with the coordinate as a byte
    /// string.
    #[must_use]
    pub fn to_cbor(&self) -> Value<'_> {
        Value::Array(vec![self.owner.to_cbor(), Value::Bytes(&self.coordinate)])
    }

    /// Reads the canonical CBOR form of a version.
    ///
    /// # Errors
    ///
    /// [`VersionError::Form`] if `value` is not an array of an identifier and a byte string,
    /// [`VersionError::Owner`] for an owner that is not an authority identifier, and
    /// [`VersionError::Coordinate`] as for [`Self::new`].
    pub fn from_cbor(value: &Value<'_>) -> Result<Self, VersionError> {
        let Value::Array(items) = value else {
            return Err(VersionError::Form);
        };
        let [owner, Value::Bytes(coordinate)] = items.as_slice() else {
            return Err(VersionError::Form);
        };
        Self::new(Id::from_cbor(owner).map_err(VersionError::Owner)?, coordinate)
    }
}

impl fmt::Debug for AuthorityVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorityVersion({:?}, {:02x?})", self.owner, self.coordinate)
    }
}

/// The cause of a refused authority version or comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionError {
    /// The coordinate is empty or longer than [`AuthorityVersion::MAX_COORDINATE`] bytes.
    Coordinate,
    /// The versions have different owners, so they do not compare.
    Owners,
    /// The owner is not a valid authority identifier.
    Owner(IdError),
    /// The CBOR form is not an array of an identifier and a byte string.
    Form,
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinate => f.write_str("the coordinate of the version is empty or too long"),
            Self::Owners => f.write_str("versions of two owners do not compare"),
            Self::Owner(error) => write!(f, "the owner of the version is not valid: {error}"),
            Self::Form => f.write_str("the CBOR form is not an authority version"),
        }
    }
}

impl core::error::Error for VersionError {}
