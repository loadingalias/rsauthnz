//! Exact conversions between the IEEE 754 binary formats of CBOR floats.

/// A binary format: the widths of its exponent and fraction fields.
#[derive(Clone, Copy)]
pub(super) struct Format {
    exponent: u64,
    fraction: u64,
}

pub(super) const HALF: Format = Format {
    exponent: 5,
    fraction: 10,
};
pub(super) const SINGLE: Format = Format {
    exponent: 8,
    fraction: 23,
};
pub(super) const DOUBLE: Format = Format {
    exponent: 11,
    fraction: 52,
};

impl Format {
    /// The biased exponent of infinity and NaN.
    const fn infinite(self) -> u64 {
        (1 << self.exponent) - 1
    }

    const fn bias(self) -> u64 {
        (1 << (self.exponent - 1)) - 1
    }

    /// The sign, the biased exponent, and the fraction of `bits`.
    const fn split(self, bits: u64) -> (u64, u64, u64) {
        (
            bits >> (self.exponent + self.fraction),
            (bits >> self.fraction) & self.infinite(),
            bits & ((1 << self.fraction) - 1),
        )
    }

    const fn join(self, sign: u64, exponent: u64, fraction: u64) -> u64 {
        sign << (self.exponent + self.fraction) | exponent << self.fraction | fraction
    }
}

/// Gives the bits of the `from` value `bits` in the wider format `to`. The value does not change. A NaN keeps its
/// payload, with zeros added on the right.
pub(super) fn widen(bits: u64, from: Format, to: Format) -> u64 {
    let (sign, exponent, fraction) = from.split(bits);
    let shift = to.fraction - from.fraction;
    if exponent == from.infinite() {
        to.join(sign, to.infinite(), fraction << shift)
    } else if exponent != 0 {
        to.join(sign, exponent + to.bias() - from.bias(), fraction << shift)
    } else if fraction == 0 {
        to.join(sign, 0, 0)
    } else {
        // A subnormal `from` value is a normal `to` value. Its highest set bit becomes the hidden bit.
        let top = u64::from(fraction.ilog2());
        let exponent = top + 1 + to.bias() - from.bias() - from.fraction;
        to.join(
            sign,
            exponent,
            (fraction << (to.fraction - top)) & ((1 << to.fraction) - 1),
        )
    }
}

/// Gives the bits of the `from` value `bits` in the narrower format `to`, if `to` holds the same value. A NaN
/// converts if its payload loses only zeros on the right.
pub(super) fn narrow(bits: u64, from: Format, to: Format) -> Option<u64> {
    let (sign, exponent, fraction) = from.split(bits);
    let shift = from.fraction - to.fraction;
    let exact = fraction & ((1 << shift) - 1) == 0;
    // The biased exponent of a normal `to` value is `exponent - offset`.
    let offset = from.bias() - to.bias();
    if exponent == from.infinite() {
        return exact.then(|| to.join(sign, to.infinite(), fraction >> shift));
    }
    if exponent == 0 {
        // A subnormal `from` value is too small for `to`.
        return (fraction == 0).then(|| to.join(sign, 0, 0));
    }
    if exponent > offset {
        return (exact && exponent - offset < to.infinite())
            .then(|| to.join(sign, exponent - offset, fraction >> shift));
    }
    // A subnormal `to` value: the significand, with its hidden bit, moves right past the fraction of `to`.
    let significand = fraction | 1 << from.fraction;
    let shift = shift + 1 + offset - exponent;
    if shift > from.fraction || significand & ((1 << shift) - 1) != 0 {
        return None;
    }
    Some(to.join(sign, 0, significand >> shift))
}
