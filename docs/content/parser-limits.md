# Parser limits

Each rsauthnz parser bounds its untrusted input before it does work on it. The caller supplies the bounds, and
each bound has a stated default. A refusal names the bound that refused the input. [Admit rsauthnz
work](admission.md) gives the cost class of each operation.

rsauthnz has one CBOR codec: `rsauthnz::cbor`. Use it for each CBOR input, so one set of rules and bounds applies to
all of them.

The X.509 reader has fixed bounds of its own: at most `CERTIFICATE_BYTES_MAX` (16,384) bytes, refused before a read,
and lengths that fit in the input, so it allocates nothing for the DER ([Read and verify a
certificate](certificates.md#read-and-verify-a-certificate)). [Fuzz the parsers](fuzzing.md) gives hostile input to each
parser with these bounds.

## The limit set

Set the bounds of the CBOR decoder in a `rsauthnz::limits::Limits` value: the one limit set of the crate. Build it
from `Limits::default()`, and set each field that you change. A refusal names its bound with
`rsauthnz::limits::Limit`, in `Error::Limit` of the codec.

| `Limits` field | Default | Bound | Refusal |
| --- | --- | --- | --- |
| `bytes` | 65,536 | Bytes in the encoded item. `decode` refuses a longer input before it reads a byte. For `decode_prefix`, the bound applies to the item, not to the bytes after it | `Limit::Bytes` |
| `depth` | 16 | Levels of nested arrays, maps, and tags. Each array, map, or tag adds one level | `Limit::Depth` |
| `items` | 1,024 | Data items. The outer item counts, and so does each array element, map key, map value, and tagged item | `Limit::Items` |
| `map_keys` | 64 | Keys in one map | `Limit::MapKeys` |
| `string_bytes` | 16,384 | Bytes in one byte string or text string | `Limit::StringBytes` |
| `keys` | 64 | Keys in one key set, such as the issuer keys of a [trust snapshot](trust-snapshots.md). The check counts them before it makes a trusted key | `Limit::Keys` |

The fields `dependencies` and `intents` bound a transition proposal, not a codec. [Propose a
transition](transitions.md#limits) gives them. The field `signature_checks` bounds the signature checks of one
artifact. [Bound the signature checks](verification.md#bound-the-signature-checks) gives it.

Each limit refuses before the decoder allocates memory. Each error value is a small `Copy` value that holds no
input text and no allocation.

The type of `depth` is `u8`, so the decoder recurses 255 levels or fewer.

A decoded value has at most `items` items, and its strings borrow the input. Thus the decode does not expand the
input past `items` times the size of one item.

## CBOR

`rsauthnz::cbor` decodes and encodes the CBOR of WebAuthn attestation objects and authenticator data, COSE
structures, and CWT claims. [Verify COSE and CWT artifacts](verification.md) gives the rules of the COSE verifier.

- `decode(input, limits)` decodes one item that fills `input`.
- `decode_prefix(input, limits)` decodes the item at the start of `input` and gives the bytes after it. Use it
  for WebAuthn authenticator data, where the extensions follow the credential public key.
- `encode(value, limits)` writes the deterministic encoding of a value. It sorts map keys, so the order of the map
  entries in the value has no effect on the output.

`encode` applies each bound of `limits` that `decode` applies, and it refuses at the same bound with the same
`Error::Limit`. Thus a value encodes within `limits` if and only if its encoding decodes within them. The encoder
checks each bound before it writes the item, so a deep or long value that you build costs bounded work and stack.
The operations that take a CBOR value of yours, such as `transition::Proposal::new` and `cli::Call::new`, encode it
within the limits that you give them.

The decoder accepts only the deterministic encoding of
[RFC 8949, section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1). Thus each value has one
encoding. The decoder checks the whole item before it builds the value, so a refused input allocates no memory.
Byte and text strings in the value borrow the input.

This example is also the example of the `rsauthnz::cbor` module documentation, and `cargo xtask test` runs it:

```rust
use rsauthnz::cbor::{self, Value};
use rsauthnz::limits::Limits;

// {1: 2, 3: -7}: the key type and the algorithm of a COSE key.
let bytes = [0xa2, 0x01, 0x02, 0x03, 0x26];
let mut limits = Limits::default();
limits.string_bytes = 4096;
let value = cbor::decode(&bytes, limits)?;
assert_eq!(
    value,
    Value::Map(vec![
        (Value::Unsigned(1), Value::Unsigned(2)),
        (Value::Unsigned(3), Value::Negative(6)),
    ])
);
assert_eq!(cbor::encode(&value, limits)?, bytes);
```

The decoder checks the bound of an array, map, or string at its head, before it reads the contents. For each
other input that it refuses, it returns one of these errors:

| Error | Cause |
| --- | --- |
| `Error::Truncated` | The input ends in the item |
| `Error::TrailingBytes` | Bytes follow the item. Only `decode` returns it |
| `Error::Malformed` | The item is not well-formed CBOR, or a text string in it is not UTF-8. A head that is not well-formed has a reserved value, a break code outside an indefinite-length item, or a two-byte simple value less than 32 |
| `Error::IndefiniteLength` | An item has an indefinite length |
| `Error::NonShortest` | A head argument or a float has a longer form than its shortest form |
| `Error::KeyOrder` | The map keys do not increase in bytewise order of their encodings |
| `Error::DuplicateKey` | A map has two equal keys |

`encode` returns `Error::DuplicateKey` for a map with two equal keys. It returns `Error::Malformed` for
`Value::Simple` with 20 to 22, which are `Value::Bool` and `Value::Null`, or with 24 to 31, which have no
encoding.

The debug output of a `Value` shows only the length of each string, because a string can hold a credential, a
challenge, or a key.

