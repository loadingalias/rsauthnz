use super::{Call, Challenge};
use crate::cbor::Value;
use crate::crypto;
use crate::limits::Limits;
use crate::transition::OperationId;

/// The request binding is the SHA-256 digest of the canonical CBOR form `["rsauthnz.cli.call.1", challenge,
/// operation, request]`. The CLI and the authority make the binding separately. If two versions have two forms, each
/// call between them refuses.
#[test]
fn a_call_binding_is_the_digest_of_its_documented_form() {
    let challenge = [7; 32];
    let form = [
        // An array of 4 items, then the form name in a text string of 19 bytes.
        &b"\x84\x73rsauthnz.cli.call.1"[..],
        b"\x58\x20",
        &challenge,
        b"\x46call-1",
        b"\x66deploy",
    ]
    .concat();
    let call = Call::new(
        Challenge::from_bytes(challenge),
        OperationId::new(b"call-1").unwrap(),
        &Value::Text("deploy"),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(call.binding(), &crypto::sha256(&form));
}
