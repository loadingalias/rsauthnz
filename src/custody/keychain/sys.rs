//! The system ABI of the Keychain custody: the owned declarations of CoreFoundation and Security, and the owners of
//! their objects.

use core::ffi::c_void;
use core::ptr::{self, NonNull};
use core::slice;
use std::io::ErrorKind;

use crate::custody::Error;

/// A `CFTypeRef`: a reference to a CF object.
type Ref = *const c_void;

/// `kCFStringEncodingUTF8`.
const UTF8: u32 = 0x0800_0100;
/// `errSecDuplicateItem`.
const DUPLICATE_ITEM: i32 = -25_299;
/// `errSecItemNotFound`.
const ITEM_NOT_FOUND: i32 = -25_300;
/// The refusal of a CF call that gives no object: it could not allocate the object.
const OUT_OF_MEMORY: Error = Error::Storage(ErrorKind::OutOfMemory);

#[link(name = "CoreFoundation", kind = "framework")]
#[expect(unsafe_code, reason = "the system ABI of the CF object calls")]
unsafe extern "C" {
    safe static kCFAllocatorNull: Ref;
    safe static kCFBooleanTrue: Ref;
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    fn CFStringCreateWithBytes(allocator: Ref, bytes: *const u8, len: isize, encoding: u32, external: u8) -> Ref;
    fn CFDataCreateWithBytesNoCopy(allocator: Ref, bytes: *const u8, len: isize, deallocator: Ref) -> Ref;
    fn CFDictionaryCreate(
        allocator: Ref,
        keys: *const Ref,
        values: *const Ref,
        count: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> Ref;
    safe fn CFDataGetTypeID() -> usize;
    fn CFGetTypeID(object: Ref) -> usize;
    fn CFDataGetLength(data: Ref) -> isize;
    fn CFDataGetBytePtr(data: Ref) -> *const u8;
    fn CFRelease(object: Ref);
}

#[link(name = "Security", kind = "framework")]
#[expect(unsafe_code, reason = "the system ABI of the keychain item calls")]
unsafe extern "C" {
    safe static kSecClass: Ref;
    safe static kSecClassGenericPassword: Ref;
    safe static kSecAttrService: Ref;
    safe static kSecAttrAccount: Ref;
    safe static kSecValueData: Ref;
    safe static kSecReturnData: Ref;
    fn SecItemAdd(attributes: Ref, result: *mut Ref) -> i32;
    fn SecItemCopyMatching(query: Ref, result: *mut Ref) -> i32;
    fn SecItemDelete(query: Ref) -> i32;
}

/// A reference to a CF object that the custody owns. It releases the object when it drops.
struct Owned(NonNull<c_void>);

impl Owned {
    /// The owner of `object`, a reference that a create or copy call gave. `None` if the call gave no object.
    fn new(object: Ref) -> Option<Self> {
        NonNull::new(object.cast_mut()).map(Self)
    }

    const fn get(&self) -> Ref {
        self.0.as_ptr()
    }
}

impl Drop for Owned {
    #[expect(unsafe_code, reason = "CFRelease of the one reference that the owner holds")]
    fn drop(&mut self) {
        // SAFETY: the owner holds one reference to the object, and nothing uses the object through the owner after
        // this call.
        unsafe { CFRelease(self.get()) }
    }
}

/// The data of an item, in memory of CoreFoundation. It releases the data when it drops.
pub(super) struct Data(Owned);

impl Data {
    /// The bytes of the data.
    #[expect(unsafe_code, reason = "a slice of the bytes that the data object owns")]
    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: the object is a CFData, which `copy` checks. A CFData has a length of zero or more.
        let len = unsafe { CFDataGetLength(self.0.get()) }.cast_unsigned();
        if len == 0 {
            return &[];
        }
        // SAFETY: the object is a CFData of `len` bytes. Nothing changes its bytes, and they live while `self` holds
        // its reference.
        unsafe { slice::from_raw_parts(CFDataGetBytePtr(self.0.get()), len) }
    }
}

/// Adds the item `account` of `service`, with the data `data`.
///
/// # Errors
///
/// [`Error::Exists`] if the item exists. [`Error::Vault`] with the status of another refusal.
#[expect(unsafe_code, reason = "SecItemAdd of a dictionary whose data object borrows `data`")]
pub(super) fn add(service: &str, account: &str, data: &[u8]) -> Result<(), Error> {
    // SAFETY: `data` has `data.len()` bytes, and a slice has at most `isize::MAX` bytes. The object borrows the bytes,
    // and `kCFAllocatorNull` never frees them. Only the dictionary retains the object, and SecItemAdd copies its bytes
    // and keeps no reference. The dictionary and the object drop at the end of this function, while `data` lives.
    let object =
        unsafe { CFDataCreateWithBytesNoCopy(ptr::null(), data.as_ptr(), data.len().cast_signed(), kCFAllocatorNull) };
    let object = Owned::new(object).ok_or(OUT_OF_MEMORY)?;
    let attributes = query(service, account, Some((kSecValueData, object.get())))?;
    // SAFETY: `attributes` is a valid dictionary, and a null result place asks for no result.
    status(unsafe { SecItemAdd(attributes.get(), ptr::null_mut()) })
}

/// The data of the item `account` of `service`.
///
/// # Errors
///
/// [`Error::Unknown`] if the item does not exist. [`Error::Mismatch`] if the result is not data. [`Error::Vault`]
/// with the status of another refusal.
#[expect(
    unsafe_code,
    reason = "SecItemCopyMatching gives a new reference to the data of the item"
)]
pub(super) fn copy(service: &str, account: &str) -> Result<Data, Error> {
    let query = query(service, account, Some((kSecReturnData, kCFBooleanTrue)))?;
    let mut result = ptr::null();
    // SAFETY: `query` is a valid dictionary, and `result` is a valid place for the result.
    status(unsafe { SecItemCopyMatching(query.get(), &raw mut result) })?;
    let result = Owned::new(result).ok_or(Error::Mismatch)?;
    // SAFETY: `result` is a valid CF object.
    (unsafe { CFGetTypeID(result.get()) } == CFDataGetTypeID()).ok_or(Error::Mismatch)?;
    Ok(Data(result))
}

/// Deletes the item `account` of `service`.
///
/// # Errors
///
/// [`Error::Unknown`] if the item does not exist. [`Error::Vault`] with the status of another refusal.
#[expect(unsafe_code, reason = "SecItemDelete of a valid query")]
pub(super) fn delete(service: &str, account: &str) -> Result<(), Error> {
    let query = query(service, account, None)?;
    // SAFETY: `query` is a valid dictionary.
    status(unsafe { SecItemDelete(query.get()) })
}

/// The dictionary of the generic-password item `account` of `service`, with the pair `extra`. The dictionary retains
/// each key and value.
#[expect(unsafe_code, reason = "CFDictionaryCreate over arrays of valid CF objects")]
fn query(service: &str, account: &str, extra: Option<(Ref, Ref)>) -> Result<Owned, Error> {
    let (service, account) = (string(service)?, string(account)?);
    let (key, value) = extra.unwrap_or((ptr::null(), ptr::null()));
    let keys = [kSecClass, kSecAttrService, kSecAttrAccount, key];
    let values = [kSecClassGenericPassword, service.get(), account.get(), value];
    let count = if extra.is_some() { 4 } else { 3 };
    // SAFETY: the first `count` entries of each array are valid CF objects. The CF type callbacks retain them, so the
    // dictionary does not depend on the owners of this function.
    let query = unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            count,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
    };
    Owned::new(query).ok_or(OUT_OF_MEMORY)
}

/// The CF string of `text`.
#[expect(unsafe_code, reason = "CFStringCreateWithBytes copies the bytes of `text`")]
fn string(text: &str) -> Result<Owned, Error> {
    // SAFETY: `text` is UTF-8 of `text.len()` bytes, and a slice has at most `isize::MAX` bytes. The call copies them.
    let string = unsafe { CFStringCreateWithBytes(ptr::null(), text.as_ptr(), text.len().cast_signed(), UTF8, 0) };
    Owned::new(string).ok_or(OUT_OF_MEMORY)
}

/// The result of the status `code` of a keychain call.
const fn status(code: i32) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        DUPLICATE_ITEM => Err(Error::Exists),
        ITEM_NOT_FOUND => Err(Error::Unknown),
        code => Err(Error::Vault(code)),
    }
}
