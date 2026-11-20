# Parser limits

Each rsauthnz parser bounds its untrusted input before it does work on it. The caller supplies the bounds, and
each bound has a stated default. A refusal names the bound that refused the input. [Admit rsauthnz
work](admission.md) gives the cost class of each operation.

rsauthnz has one codec for each format: `rsauthnz::cbor` for CBOR and `rsauthnz::json` for JSON. Use them for each
input of these formats, so one set of rules and bounds applies to all of them.

## The limit set

Set the bounds of the CBOR decoder and of the JSON reader in a `rsauthnz::limits::Limits` value: the one limit set
of the crate. Build it from `Limits::default()`, and set each field that you change. A refusal names its bound
with `rsauthnz::limits::Limit`, in `Error::Limit` of the codec.

| `Limits` field | Default | CBOR | JSON | Refusal |
| --- | --- | --- | --- | --- |
| `bytes` | 65,536 | Bytes in the encoded item. `decode` refuses a longer input before it reads a byte. For `decode_prefix`, the bound applies to the item, not to the bytes after it | Bytes in the JSON text, with its whitespace. `decode` refuses a longer input before it reads a byte | `Limit::Bytes` |
| `depth` | 16 | Levels of nested arrays, maps, and tags. Each array, map, or tag adds one level | Levels of nested arrays and objects. Each array or object adds one level | `Limit::Depth` |
| `items` | 1,024 | Data items. The outer item counts, and so does each array element, map key, map value, and tagged item | The outer value, each array element, and each member name and member value | `Limit::Items` |
| `map_keys` | 64 | Keys in one map | Members in one object | `Limit::MapKeys` |
| `string_bytes` | 16,384 | Bytes in one byte string or text string | UTF-8 bytes in one string or member name, after the escapes | `Limit::StringBytes` |

The fields `dependencies` and `intents` bound a transition proposal, not a codec. [Propose a
transition](transitions.md#limits) gives them.

Each limit refuses before the decoder allocates memory. Each error value is a small `Copy` value that holds no
input text and no allocation.

The type of `depth` is `u8`, so each decoder recurses 255 levels or fewer. At 255 levels, the JSON reader runs in
a thread with a 1 MiB stack, which is the default stack of a `wasm32-unknown-unknown` program.

A decoded value has at most `items` items. Its strings borrow the input, but a JSON string with an escape is a
copy that is not longer than its text in the input. Thus the decode does not expand the input past `items` times
the size of one item, plus the bytes of the input.

## CBOR

`rsauthnz::cbor` decodes and encodes the CBOR of WebAuthn attestation objects and authenticator data, COSE
structures, and CWT claims. [Verify COSE and CWT artifacts](verification.md) gives the rules of the COSE verifier.

- `decode(input, limits)` decodes one item that fills `input`.
- `decode_prefix(input, limits)` decodes the item at the start of `input` and gives the bytes after it. Use it
  for WebAuthn authenticator data, where the extensions follow the credential public key.
- `encode(value)` writes the deterministic encoding of a value. It sorts map keys, so the order of the map
  entries in the value has no effect on the output.

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
assert_eq!(cbor::encode(&value)?, bytes);
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

## JSON

`rsauthnz::json` reads WebAuthn `clientDataJSON`, JOSE headers and claims, and OAuth metadata documents.
`decode(input, limits)` decodes the one JSON value that fills `input`. Whitespace can come before and after it.

The reader accepts exactly the grammar of [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259), in UTF-8. It also
applies two rules of I-JSON ([RFC 7493](https://www.rfc-editor.org/rfc/rfc7493)):

- No object has two members with equal names. Names are equal when their characters are equal after the escapes,
  so `"a"` and `"\u0061"` are equal.
- No escape gives a lone surrogate. An escape of a high surrogate needs an escape of a low surrogate after it, and
  the two give one character.

The reader accepts each other code point, also a noncharacter such as U+FFFF: it is valid JSON, and a JOSE issuer
can send it. The reader refuses a byte order mark.

This example is also the example of the `rsauthnz::json` module documentation, and `cargo xtask test` runs it:

```rust
use rsauthnz::json::{self, Value};
use rsauthnz::limits::Limits;

// A JOSE header.
let text = br#"{"typ": "JWT", "alg": "EdDSA"}"#;
let value = json::decode(text, Limits::default())?;
assert_eq!(
    value,
    Value::Object(vec![
        ("alg".into(), Value::String("EdDSA".into())),
        ("typ".into(), Value::String("JWT".into())),
    ])
);
```

A `json::Value` is `Null`, `Bool`, `Number`, `String`, `Array`, or `Object`:

- `Number` holds the text of the number, as in the input. Read it with `str::parse` into the integer or float type
  of your protocol. If the type cannot hold the number, the parse returns an error.
- `String` and each member name are a `Cow<str>`. A string with no escape borrows the input. A string with an
  escape is one copy.
- `Object` gives its members in increasing bytewise order of the UTF-8 of their names. The reader does not keep
  the order of the input, which has no meaning in JSON. To find a member, do a binary search on the names.

The reader works in two passes. The check pass reads the whole text, makes each refusal but one, and allocates no
memory. Then the build pass makes the value. A duplicate member refuses in the build pass, and it can allocate only
within the bounds that the check pass admitted. Each limit still refuses before allocation. The error value holds
no input text and no allocation.

The work is linear in the input. To find two equal names, the build pass sorts the members of each object in
place, with no allocation. The sort adds a factor of at most log2 of `map_keys`: 6 at the default.

| Error | Cause |
| --- | --- |
| `Error::Limit(limit)` | The text is larger than a bound of `Limits` |
| `Error::Truncated` | The input ends in the value |
| `Error::TrailingBytes` | Bytes other than whitespace follow the value |
| `Error::Malformed` | The input is not in the grammar of RFC 8259, or it is not UTF-8 |
| `Error::LoneSurrogate` | An escape gives a lone surrogate |
| `Error::DuplicateMember` | An object has two members with equal names |

The debug output of a `Value` shows the numbers, and only the length of each string and member name.
