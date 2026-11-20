//! Identifiers: bounded canonical names, each in an explicit namespace that the application
//! chooses.
//!
//! An [`Id`] has a kind, a namespace, and a value. The kind is a type, such as [`Id<Action>`] or
//! [`Id<Human>`], so an identifier of one kind never takes the place of another. The namespace and
//! the value are application text, so the application adds identifiers with no change to this
//! crate. An identifier has one form: two identifiers are equal only when their kinds, namespaces,
//! and values are equal, byte for byte.
//!
//! A [`Principal`] is a human, a workload, or an agent. The three kinds stay distinct also when
//! their raw namespace and value are equal.
//!
//! ```
//! use rsauthnz::id::{Action, Agent, Human, Id, IdError, Principal};
//!
//! let read: Id<Action> = Id::new("acme.repo", "repo.read")?;
//! assert_eq!((read.namespace(), read.value()), ("acme.repo", "repo.read"));
//!
//! // A human and an agent with the same raw identifier are not the same principal.
//! let human = Principal::Human(Id::<Human>::new("acme", "u-17")?);
//! let agent = Principal::Agent(Id::<Agent>::new("acme", "u-17")?);
//! assert_ne!(human, agent);
//! # Ok::<(), IdError>(())
//! ```

mod version;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use core::fmt;
use core::marker::PhantomData;

pub use version::{AuthorityVersion, VersionError};

use crate::cbor::Value;

/// The most bytes in a namespace.
pub const MAX_NAMESPACE: usize = 64;
/// The most bytes in a value.
pub const MAX_VALUE: usize = 2048;

/// The kind of an identifier. Each kind is a type with no value, which this crate defines.
pub trait Kind: sealed::Sealed {
    /// The number of the kind in the CBOR encoding of an identifier.
    const TAG: u64;
    /// The name of the kind, for `Debug` output.
    const NAME: &'static str;
}

mod sealed {
    pub trait Sealed {}
}

macro_rules! kinds {
    ($($(#[$doc:meta])* $kind:ident = $tag:literal, $name:literal;)*) => {$(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $kind {}

        impl sealed::Sealed for $kind {}

        impl Kind for $kind {
            const TAG: u64 = $tag;
            const NAME: &'static str = $name;
        }
    )*};
}

kinds! {
    /// A person.
    Human = 1, "human";
    /// A service or a host that acts for itself.
    Workload = 2, "workload";
    /// An agent that acts for its human owner.
    Agent = 3, "agent";
    /// An authority: the owner of principals, policy, and versions.
    Authority = 4, "authority";
    /// A tenant of an authority.
    Tenant = 5, "tenant";
    /// An action on a resource, such as `repo.read`.
    Action = 6, "action";
    /// A resource, such as a repository.
    Resource = 7, "resource";
    /// The audience of an artifact: the service that accepts it.
    Audience = 8, "audience";
    /// The purpose of an artifact or a key.
    Purpose = 9, "purpose";
}

/// An identifier of kind `K`: a namespace and a value.
///
/// A namespace has 1 to [`MAX_NAMESPACE`] bytes, each a lowercase ASCII letter, a digit, `.`, `-`,
/// or `_`. A value has 1 to [`MAX_VALUE`] bytes, each a visible ASCII character (`!` to `~`), so it
/// has no space, no control character, and no second Unicode form. Encode other text, for example
/// with percent-encoding, before it becomes a value.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id<K: Kind> {
    /// The namespace, then the value.
    text: Box<str>,
    /// The length of the namespace in `text`.
    split: u8,
    kind: PhantomData<K>,
}

impl<K: Kind> Id<K> {
    /// Makes an identifier. It allocates the bytes of the namespace and the value, and no more.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`IdError::Namespace`] or [`IdError::Value`] for a part outside its rule.
    pub fn new(namespace: &str, value: &str) -> Result<Self, IdError> {
        let split = u8::try_from(namespace.len())
            .ok()
            .filter(|_| is_namespace(namespace))
            .ok_or(IdError::Namespace)?;
        if !is_value(value) {
            return Err(IdError::Value);
        }
        let mut text = String::with_capacity(namespace.len() + value.len());
        text.push_str(namespace);
        text.push_str(value);
        Ok(Self {
            text: text.into_boxed_str(),
            split,
            kind: PhantomData,
        })
    }

    /// The namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        self.text.get(..usize::from(self.split)).unwrap_or_default()
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &str {
        self.text.get(usize::from(self.split)..).unwrap_or_default()
    }

    /// The canonical CBOR form: the array `[kind, namespace, value]`, with the kind number of `K`.
    #[must_use]
    pub fn to_cbor(&self) -> Value<'_> {
        Value::Array(vec![
            Value::Unsigned(K::TAG),
            Value::Text(self.namespace()),
            Value::Text(self.value()),
        ])
    }

    /// Reads the canonical CBOR form of an identifier of kind `K`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`IdError::Form`] if `value` is not an array of a kind number and two text strings,
    /// [`IdError::Kind`] for the identifier of another kind, and [`IdError::Namespace`] or
    /// [`IdError::Value`] for a part outside its rule.
    pub fn from_cbor(value: &Value<'_>) -> Result<Self, IdError> {
        let Value::Array(items) = value else {
            return Err(IdError::Form);
        };
        let [Value::Unsigned(tag), Value::Text(namespace), Value::Text(text)] = items.as_slice() else {
            return Err(IdError::Form);
        };
        if *tag != K::TAG {
            return Err(IdError::Kind);
        }
        Self::new(namespace, text)
    }
}

/// The text form `namespace:value`. A namespace has no `:`, so the first `:` ends it, and each identifier of a kind
/// has one text form. The text form does not name the kind.
impl<K: Kind> fmt::Display for Id<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace(), self.value())
    }
}

impl<K: Kind> fmt::Debug for Id<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({}:{})", K::NAME, self.namespace(), self.value())
    }
}

/// A principal: a human, a workload, or an agent. Principals of two kinds are never equal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Principal {
    /// A person.
    Human(Id<Human>),
    /// A service or a host that acts for itself.
    Workload(Id<Workload>),
    /// An agent that acts for its human owner.
    Agent(Id<Agent>),
}

impl Principal {
    /// The canonical CBOR form: the form of the identifier, whose kind number names the kind of
    /// principal.
    #[must_use]
    pub fn to_cbor(&self) -> Value<'_> {
        match self {
            Self::Human(id) => id.to_cbor(),
            Self::Workload(id) => id.to_cbor(),
            Self::Agent(id) => id.to_cbor(),
        }
    }

    /// Reads the canonical CBOR form of a principal.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// As for [`Id::from_cbor`]. [`IdError::Kind`] is for an identifier that is not a principal.
    pub fn from_cbor(value: &Value<'_>) -> Result<Self, IdError> {
        let tag = match value {
            Value::Array(items) => match items.first() {
                Some(Value::Unsigned(tag)) => *tag,
                _ => return Err(IdError::Form),
            },
            _ => return Err(IdError::Form),
        };
        match tag {
            Human::TAG => Id::from_cbor(value).map(Self::Human),
            Workload::TAG => Id::from_cbor(value).map(Self::Workload),
            Agent::TAG => Id::from_cbor(value).map(Self::Agent),
            _ => Err(IdError::Kind),
        }
    }
}

/// The cause of a refused identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdError {
    /// The namespace is empty, longer than [`MAX_NAMESPACE`] bytes, or has another byte than a
    /// lowercase ASCII letter, a digit, `.`, `-`, or `_`.
    Namespace,
    /// The value is empty, longer than [`MAX_VALUE`] bytes, or has another byte than a visible
    /// ASCII character.
    Value,
    /// The CBOR form is not an array of a kind number and two text strings.
    Form,
    /// The CBOR form is the identifier of another kind.
    Kind,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Namespace => "the namespace of the identifier is not valid",
            Self::Value => "the value of the identifier is not valid",
            Self::Form => "the CBOR form is not an identifier",
            Self::Kind => "the identifier is of another kind",
        })
    }
}

impl core::error::Error for IdError {}

fn is_namespace(namespace: &str) -> bool {
    (1..=MAX_NAMESPACE).contains(&namespace.len())
        && namespace
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
}

fn is_value(value: &str) -> bool {
    (1..=MAX_VALUE).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests;
