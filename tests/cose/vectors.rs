//! The COSE and CWT vectors of RFC 9052 Appendix C and RFC 8392 Appendix A. `tests/cose.rs` and the portable
//! consumer (`xtask/portable`) share them, as hexadecimal text.

/// Key "11" of RFC 9052 C.7.1 as a `COSE_Key`, in deterministic order: kty 2, kid '11', crv 1, x, y.
pub(crate) const KEY_11: &str = concat!(
    "a50102024231312001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
    "22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
);

/// The `COSE_Sign1` of RFC 9052 C.2.1: key "11" signs "This is the content." with ES256.
pub(crate) const SIGN1_C_2_1: &str = concat!(
    "d28443a10126a10442313154546869732069732074686520636f6e74656e742e58408eb33e4ca31d1c465ab05aac34cc6b23",
    "d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36",
);

/// The signed CWT of RFC 8392 A.3.
pub(crate) const CWT_A_3: &str = concat!(
    "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e",
    "636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f006",
    "1a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131",
    "680c429a01f85951ecee743a52b9b63632c57209120e1c9e30",
);

/// The P-256 public key of RFC 8392 A.2.3, which signs A.3: its x and its y coordinate.
pub(crate) const CWT_A_3_X: &str = "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f";
pub(crate) const CWT_A_3_Y: &str = "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9";

/// The claims set of RFC 8392 A.1, the payload of A.3.
pub(crate) const CLAIMS_A_1: &str = concat!(
    "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e657861",
    "6d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71",
);
