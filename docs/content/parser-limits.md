# Parser limits

Each rsauthnz parser bounds its untrusted input before it does work on it. The caller supplies the bounds, and
each bound has a stated default. A refusal names the bound that refused the input. [Admit rsauthnz
work](admission.md) gives the cost class of each operation.

## CBOR

`rsauthnz::cbor` is the one CBOR codec of the crate. It decodes and encodes the CBOR of WebAuthn attestation
objects and authenticator data, COSE structures, and CWT claims. [Verify COSE and CWT artifacts](verification.md)
gives the rules of the COSE verifier.

- `decode(input, limits)` decodes one item that fills `input`.
- `decode_prefix(input, limits)` decodes the item at the start of `input` and gives the bytes after it. Use it
  for WebAuthn authenticator data, where the extensions follow the credential public key.
- `encode(value)` writes the deterministic encoding of a value. It sorts map keys, so the order of the map
  entries in the value has no effect on the output.

The decoder accepts only the deterministic encoding of
[RFC 8949, section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1). Thus each value has one
encoding. The decoder checks the whole item before it builds the value, so a refused input allocates no memory.
Byte and text strings in the value borrow the input.

Set the bounds in a `rsauthnz::limits::Limits` value: the one limit set of the crate. This example is also the
example of the `rsauthnz::cbor` module documentation, and `cargo xtask test` runs it:

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
assert_eq!(cbor::encode(&value)?, bytes);
```

The decoded value has at most `items` items, and its strings borrow the input. Thus the decode does not expand the
input past `items` times the size of one item. A refusal names its bound with `rsauthnz::limits::Limit`.

| Bound | `Limits` field | Default | Refusal |
| --- | --- | --- | --- |
| Bytes in the encoded item. `decode` refuses a longer input before it reads a byte. For `decode_prefix`, the bound applies to the item, not to the bytes after it | `bytes` | 65,536 | `Error::Limit(Limit::Bytes)` |
| Levels of nested arrays, maps, and tags. Each array, map, or tag adds one level. The maximum is 255 | `depth` | 16 | `Error::Limit(Limit::Depth)` |
| Data items. The outer item counts, and so does each array element, map key, map value, and tagged item | `items` | 1,024 | `Error::Limit(Limit::Items)` |
| Keys in one map | `map_keys` | 64 | `Error::Limit(Limit::MapKeys)` |
| Bytes in one byte string or text string | `string_bytes` | 16,384 | `Error::Limit(Limit::StringBytes)` |

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
