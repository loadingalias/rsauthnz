//! Declared limits and cost classes: the bounds of untrusted input, and the class of the work of each operation.
//!
//! [`Limits`] is the one limit set of the crate. Each parser, each verifier, and each transition proposal checks its
//! input against it before expensive work, and a refusal names the [`Limit`] that refused the input. A future bound
//! joins [`Limits`] in the change that adds its first consumer: grants, resource scopes, and the keys of a key set.
//! [`SignatureBudget`] bounds the signature checks of one artifact.
//!
//! [`Class`] is the cost class of an operation. Each public function names its class in its documentation, in the
//! form "Cost class: [`Parse`](Class::Parse)." A method that takes only `&self` and returns no `Result` reads a
//! value that is already bounded, so it names no class, unless it does signature, KDF, or storage work. A host admits
//! each class separately, so a flood of one class cannot delay the work of another. The host owns admission.
//!
//! An ordinary operation reads current state only by key: the identifier of one principal, session, credential, or
//! record. It never scans all principals, sessions, audit records, or expiry records. Expiry and retention go
//! forward in bounded batches.

/// The bounds of one decode. Each parser of the crate takes them, and [`Limit`] names the bound that refused an
/// input.
///
/// A decoded value has at most [`Self::items`] items. Its strings borrow the input, but a JSON string with an escape
/// is a copy that is not longer than its text in the input. Thus the decoded size is at most [`Self::items`] times
/// the size of one item, plus the bytes of the input, and the decode does not expand the input past that bound.
///
/// A new bound can join the set, so build a value from [`Limits::default`] and set each field that you change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// The most bytes in the encoded item or the JSON text. The default is 65,536.
    pub bytes: usize,
    /// The most levels of nested arrays, maps, tags, and JSON objects. Each array, map, tag, or object adds one
    /// level. The default is 16. The type keeps the recursion of each decoder at 255 levels or fewer.
    pub depth: u8,
    /// The most data items. Each item counts: the outer item, and each array element, map key, map value, and
    /// tagged item. In JSON, the outer value, each array element, and each member name and member value count. The
    /// default is 1,024.
    pub items: usize,
    /// The most keys in one map, and the most members in one JSON object. The default is 64.
    pub map_keys: usize,
    /// The most bytes in one byte or text string. For a JSON string, the bound applies to its UTF-8 after the
    /// escapes. The default is 16,384.
    pub string_bytes: usize,
    /// The most dependencies of one transition proposal: each policy and record that its decision reads. The changes
    /// of a proposal are at most this many too. The default is 64.
    pub dependencies: usize,
    /// The most effect intents of one transition proposal. The default is 8.
    pub intents: usize,
    /// The most signature checks of one artifact. A composite signature is two checks, one for each component. The
    /// default is 2: one composite signature. [`SignatureBudget`] counts them.
    pub signature_checks: usize,
}

impl Limits {
    /// The bounds of the encode of a fixed form of this crate, such as a record form or an audit form. The form is a
    /// shape of typed values, which bounds it, so the encoder applies no other bound. A value of a caller never
    /// encodes with these bounds: it encodes within the limits of its caller.
    pub(crate) const FORM: Self = Self {
        bytes: usize::MAX,
        depth: u8::MAX,
        items: usize::MAX,
        map_keys: usize::MAX,
        string_bytes: usize::MAX,
        dependencies: usize::MAX,
        intents: usize::MAX,
        signature_checks: usize::MAX,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 65_536,
            depth: 16,
            items: 1_024,
            map_keys: 64,
            string_bytes: 16_384,
            dependencies: 64,
            intents: 8,
            signature_checks: 2,
        }
    }
}

/// A bound of [`Limits`]. A new bound can join it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    /// [`Limits::bytes`].
    Bytes,
    /// [`Limits::depth`].
    Depth,
    /// [`Limits::items`].
    Items,
    /// [`Limits::map_keys`].
    MapKeys,
    /// [`Limits::string_bytes`].
    StringBytes,
    /// [`Limits::dependencies`].
    Dependencies,
    /// [`Limits::intents`].
    Intents,
    /// [`Limits::signature_checks`].
    SignatureChecks,
}

/// The signature checks that one artifact can still make. Make one budget for each artifact, and give it to each
/// signature check of the artifact.
///
/// Each signature check of the crate charges the budget with its cost before its work: one check for each component
/// of the signature. A check that costs more than the budget has refuses with [`Limit::SignatureChecks`]. It charges
/// nothing, and it does no signature work.
#[derive(Debug)]
pub struct SignatureBudget(usize);

impl SignatureBudget {
    /// The budget of one artifact: [`Limits::signature_checks`] checks.
    ///
    /// Cost class: [`Parse`](Class::Parse).
    #[must_use]
    pub const fn new(limits: &Limits) -> Self {
        Self(limits.signature_checks)
    }

    /// The checks that the artifact can still make.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.0
    }

    /// Charges `checks`, or refuses and charges nothing.
    pub(crate) fn charge(&mut self, checks: usize) -> Result<(), Limit> {
        self.0 = self.0.checked_sub(checks).ok_or(Limit::SignatureChecks)?;
        Ok(())
    }
}

/// The cost class of an operation. A host admits each class with its own bound on concurrent work and pending
/// work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// A cheap parse or refusal. The work is linear in input that [`Limits`] bounds, and it does no signature, KDF,
    /// storage, or network work.
    Parse,
    /// Verification: signature or KDF work on input that the parse admitted.
    Verify,
    /// A durable mutation: one atomic commit in the storage binding of the application.
    Mutate,
    /// Slow custody or provider work, such as a hardware key or an external identity provider.
    External,
}

#[cfg(test)]
mod tests;
