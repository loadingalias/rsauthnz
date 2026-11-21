//! X.509: `Certificate::parse` of untrusted DER, and the signature check of a certificate that parses. An input over
//! `CERTIFICATE_BYTES_MAX` refuses before a read, and only a check after a parse does signature work.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::x509::{CERTIFICATE_BYTES_MAX, Certificate, Error};
use rsauthnz_fuzz::untouched;

fuzz_target!(|input: &[u8]| {
    let parsed = Certificate::parse(input);
    if input.len() > CERTIFICATE_BYTES_MAX {
        assert_eq!(
            parsed.as_ref().err(),
            Some(&Error::Bytes),
            "an input over the bound was read"
        );
    }
    if let Ok(certificate) = parsed {
        let limits = Limits::default();
        let mut budget = SignatureBudget::new(&limits);
        let checked = certificate.verify(certificate.key(), &mut budget);
        assert!(untouched(&budget, &limits) || matches!(checked, Ok(()) | Err(Error::Signature)));
    }
});
