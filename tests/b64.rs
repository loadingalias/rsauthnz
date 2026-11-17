//! The contracts of the base64url codec: the RFC 4648 vectors, the exact text of each input of up to three bytes,
//! and the refusal of each text that is not canonical.

use rsauthnz::b64::{Error, decode, decoded_len, encode, encoded_len};

/// The base64url alphabet of RFC 4648, section 5, Table 2: the character of each sextet (6-bit value).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The text of the `len` low bytes of `n`, at most three, from the alphabet table, and its length. Zero bits after
/// the bytes fill the last sextet, and each sextet gives one character.
fn table_text(n: u32, len: usize) -> ([u8; 4], usize) {
    let chars = (8 * len).div_ceil(6);
    let bits = n << (6 * chars - 8 * len);
    let mut text = [0; 4];
    for (at, symbol) in text[..chars].iter_mut().enumerate() {
        *symbol = ALPHABET[(bits >> (6 * (chars - 1 - at)) & 63) as usize];
    }
    (text, chars)
}

/// Encodes `bytes`, and gives the text.
fn encoded(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0; encoded_len(bytes)];
    encode(bytes, &mut out)
        .expect("an output of the encoded length")
        .to_vec()
}

/// Decodes `text`, and gives the bytes or the refusal.
fn decoded(text: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; 64];
    decode(text, &mut out).map(<[u8]>::to_vec)
}

/// The vectors of RFC 4648, section 10, with no padding, and three bytes whose text has the two characters that
/// base64url changes: `-` and `_` in place of `+` and `/`.
#[test]
fn rfc_4648_vectors_encode_and_decode_without_padding() {
    let vectors: [(&[u8], &[u8]); 8] = [
        (b"", b""),
        (b"f", b"Zg"),
        (b"fo", b"Zm8"),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg"),
        (b"fooba", b"Zm9vYmE"),
        (b"foobar", b"Zm9vYmFy"),
        (&[0xfb, 0xff, 0xbf], b"-_-_"),
    ];
    for (bytes, text) in vectors {
        assert_eq!(encoded(bytes), text, "{bytes:02x?}");
        assert_eq!(decoded(text).as_deref(), Ok(bytes), "{text:?}");
    }
}

/// Each input of zero to three bytes encodes to its text in the alphabet table, and the text decodes to the input.
#[test]
fn every_input_of_zero_to_three_bytes_has_its_table_text_and_decodes_to_itself() {
    for len in 0..=3 {
        for n in 0..1_u32 << (8 * len) {
            let bytes = &n.to_be_bytes()[4 - len..];
            let (table, chars) = table_text(n, len);
            let mut text = [0; 4];
            let text = encode(bytes, &mut text).expect("an output of four characters");
            assert_eq!(text, &table[..chars], "{bytes:02x?}");
            let mut out = [0; 3];
            assert_eq!(decode(text, &mut out), Ok(bytes), "{text:?}");
        }
    }
}

/// Of the texts of two and three characters of the alphabet, only the canonical text of each input decodes: its last
/// character has zero bits after the last byte. Each other text refuses with [`Error::TrailingBits`].
#[test]
fn only_the_canonical_text_of_each_input_decodes() {
    for len in [2, 3] {
        // The bits of the last character after the last byte: four after two characters, and two after three.
        let unused = if len == 2 { 0b1111 } else { 0b11 };
        let (mut accepted, mut texts) = (0, 0);
        for n in 0..64_usize.pow(len) {
            let text: Vec<u8> = (0..len)
                .rev()
                .map(|digit| ALPHABET[n / 64_usize.pow(digit) % 64])
                .collect();
            let last = n % 64;
            let result = decoded(&text);
            if last & unused == 0 {
                accepted += 1;
                assert_eq!(encoded(&result.expect("a canonical text")), text);
            } else {
                assert_eq!(result, Err(Error::TrailingBits), "{text:?}");
            }
            texts += 1;
        }
        // One text for each input of one or two bytes.
        assert_eq!((accepted, texts), (1 << (8 * (len - 1)), 64_usize.pow(len)));
    }
}

/// Each byte outside the alphabet refuses in each position of a full block and of a last part. This includes the
/// padding character `=`, and `+` and `/` of the base64 alphabet.
#[test]
fn each_byte_outside_the_alphabet_refuses_in_each_position() {
    for byte in (0..=u8::MAX).filter(|byte| !ALPHABET.contains(byte)) {
        for text in [b"AAAA".as_slice(), b"AAAAAA", b"AAAAAAA"] {
            for at in 0..text.len() {
                let mut text = text.to_vec();
                text[at] = byte;
                assert_eq!(decoded(&text), Err(Error::Malformed), "{text:?}");
            }
        }
    }
    assert_eq!(decoded(b"Zg=="), Err(Error::Malformed));
    assert_eq!(decoded(b"Zm8="), Err(Error::Malformed));
}

/// A text of 4n + 1 characters has no bytes, and an output slice that is too short refuses before the codec writes.
#[test]
fn an_impossible_length_and_a_short_output_refuse() {
    for (len, bytes) in [
        (0, Ok(0)),
        (1, Err(Error::Length)),
        (2, Ok(1)),
        (3, Ok(2)),
        (4, Ok(3)),
        (5, Err(Error::Length)),
    ] {
        assert_eq!(decoded_len(&vec![b'A'; len]), bytes, "{len} characters");
    }
    assert_eq!(decoded(b"Zm9vY"), Err(Error::Length));
    let mut out = [0; 2];
    assert_eq!(decode(b"Zm9v", &mut out), Err(Error::ShortOutput));
    assert_eq!(encode(b"foo", &mut [0; 3]), Err(Error::ShortOutput));
    assert_eq!(out, [0; 2]);
}
