//! The forms of the files: the frame of each write, the payload of a journal entry, and the payload of the store
//! writes.
//!
//! A frame is the length of its payload (`u64`), the CRC-32C of the payload (`u32`), both little-endian, and then the
//! payload. A start reads the frames of a file and stops at the first one that is incomplete or fails its checksum:
//! a torn write that no sync made durable.

use core::time::Duration;

use rsauthnz::id::{AuthorityVersion, Id};
use rsauthnz::store::{Record, Sequence};
use rsauthnz::transition::Key;
use rscrypto::{Checksum as _, Crc32C};

/// The bytes of the length and the checksum before a payload.
const HEADER_BYTES: usize = 12;

/// The nanoseconds in one second.
const NANOS_PER_SEC: u32 = 1_000_000_000;

/// The frame of `payload`.
pub(crate) fn frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_BYTES.saturating_add(payload.len()));
    frame.extend((payload.len() as u64).to_le_bytes());
    frame.extend(Crc32C::checksum(payload).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// The offset and the payload of each complete frame at the start of `bytes`, and the end of the last one.
pub(crate) fn frames(bytes: &[u8]) -> (Vec<(usize, &[u8])>, usize) {
    let mut payloads = Vec::new();
    let mut rest = bytes;
    while let Some((payload, after)) = next(rest) {
        payloads.push((bytes.len() - rest.len(), payload));
        rest = after;
    }
    (payloads, bytes.len() - rest.len())
}

/// The payload of the frame at the start of `bytes` and the bytes after it, or `None` for a torn frame.
fn next(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<8>()?;
    let (checksum, rest) = rest.split_first_chunk::<4>()?;
    let (payload, rest) = rest.split_at_checked(usize::try_from(u64::from_le_bytes(*len)).ok()?)?;
    (Crc32C::checksum(payload) == u32::from_le_bytes(*checksum)).then_some((payload, rest))
}

/// The payload of the journal entry `data` with its sequence.
pub(crate) fn entry(sequence: Sequence, data: &[u8]) -> Vec<u8> {
    [&sequence.0.to_le_bytes()[..], data].concat()
}

/// The sequence and the data of the journal payload `payload`, or `None` for a payload that [`entry`] did not make.
pub(crate) fn read_entry(payload: &[u8]) -> Option<(Sequence, &[u8])> {
    let (sequence, data) = payload.split_first_chunk::<8>()?;
    Some((Sequence(u64::from_le_bytes(*sequence)), data))
}

/// The payload of the store writes `writes`: each key, then its record, or nothing for a removal.
pub(crate) fn writes<'a>(writes: impl IntoIterator<Item = (&'a Key, Option<&'a Record>)>) -> Vec<u8> {
    let mut form = Vec::new();
    for (key, record) in writes {
        put(&mut form, key.as_bytes());
        let Some(record) = record else {
            form.push(0);
            continue;
        };
        form.push(1);
        let owner = record.version.owner();
        put(&mut form, owner.namespace().as_bytes());
        put(&mut form, owner.value().as_bytes());
        put(&mut form, record.version.coordinate());
        match record.end {
            None => form.push(0),
            Some(end) => {
                form.push(1);
                form.extend(end.as_secs().to_le_bytes());
                form.extend(end.subsec_nanos().to_le_bytes());
            }
        }
        put(&mut form, &record.data);
    }
    form
}

/// The store writes of the payload `form`, or `None` for a payload that [`writes`] did not make.
pub(crate) fn read_writes(mut form: &[u8]) -> Option<Vec<(Key, Option<Record>)>> {
    let mut writes = Vec::new();
    while !form.is_empty() {
        let key = Key::new(take(&mut form)?).ok()?;
        let record = match take_chunk(&mut form)? {
            [0] => None,
            [1] => Some(read_record(&mut form)?),
            _ => return None,
        };
        writes.push((key, record));
    }
    Some(writes)
}

/// Reads one record of [`writes`] from the start of `form`.
fn read_record(form: &mut &[u8]) -> Option<Record> {
    let namespace = core::str::from_utf8(take(form)?).ok()?;
    let value = core::str::from_utf8(take(form)?).ok()?;
    let version = AuthorityVersion::new(Id::new(namespace, value).ok()?, take(form)?).ok()?;
    let end = match take_chunk(form)? {
        [0] => None,
        [1] => {
            let secs = u64::from_le_bytes(*take_chunk(form)?);
            let nanos = u32::from_le_bytes(*take_chunk(form)?);
            // Below one second of nanoseconds, `Duration::new` has no carry, so it cannot overflow.
            Some((nanos < NANOS_PER_SEC).then(|| Duration::new(secs, nanos))?)
        }
        _ => return None,
    };
    Some(Record {
        version,
        end,
        data: take(form)?.into(),
    })
}

/// Writes the length of `bytes` (`u64`, little-endian) and then `bytes`.
fn put(form: &mut Vec<u8>, bytes: &[u8]) {
    form.extend((bytes.len() as u64).to_le_bytes());
    form.extend_from_slice(bytes);
}

/// Reads the bytes that [`put`] wrote at the start of `form`.
fn take<'a>(form: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::try_from(u64::from_le_bytes(*take_chunk(form)?)).ok()?;
    let (bytes, rest) = form.split_at_checked(len)?;
    *form = rest;
    Some(bytes)
}

/// Reads `N` bytes at the start of `form`.
fn take_chunk<'a, const N: usize>(form: &mut &'a [u8]) -> Option<&'a [u8; N]> {
    let (chunk, rest) = form.split_first_chunk::<N>()?;
    *form = rest;
    Some(chunk)
}
