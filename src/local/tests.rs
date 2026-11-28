use rscrypto::SecretBytes;

use super::{Bootstrap, Error};

/// A pasted value that is not the exact text of a bootstrap value refuses with a typed error: no panic, and no other
/// value. The text of a value reads back as the same value.
#[test]
fn only_the_exact_text_of_a_value_reads_back() {
    let value = Bootstrap(SecretBytes::new([0xa7; 32]));
    let text = String::from_utf8(value.text().unwrap()).unwrap();
    assert_eq!(text, format!("rsauthnz-bootstrap-1-{}", "a7".repeat(32)));
    assert_eq!(Bootstrap::parse(&text).map(|value| *value.0.as_bytes()), Ok([0xa7; 32]));
    let (hex, short) = ("a7".repeat(32), "a7".repeat(31));
    for text in [
        String::new(),
        hex.clone(),
        format!("rsauthnz-bootstrap-2-{hex}"),
        format!("rsauthnz-bootstrap-1-{}", hex.to_uppercase()),
        format!("rsauthnz-bootstrap-1-{short}a"),
        format!("rsauthnz-bootstrap-1-{hex}a7"),
        format!("rsauthnz-bootstrap-1-{hex} "),
        format!("rsauthnz-bootstrap-1-{short}é"),
        format!("rsauthnz-bootstrap-1-{short}g0"),
    ] {
        assert_eq!(
            Bootstrap::parse(&text).map(|value| *value.0.as_bytes()),
            Err(Error::Form),
            "{text:?}"
        );
    }
}
