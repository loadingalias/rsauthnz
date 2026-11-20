//! The system ABI of the Keychain custody: the owned declarations of CoreFoundation and Security, and the owners of
//! their objects.

use alloc::boxed::Box;
use core::ffi::{c_char, c_void};
use core::ptr::{self, NonNull};
use core::slice;
use std::ffi::CString;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;

use rscrypto::{SecretVec, SecretVecConstructionError};

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
/// The login keychain of the user, under the home directory: the file-based keychain that TN3137 names.
const LOGIN: &str = "Library/Keychains/login.keychain-db";

/// `CFAllocatorContext`: the callbacks of an allocator, and the value `info` that each callback gets.
#[repr(C)]
struct AllocatorContext {
    version: isize,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    copy_description: Option<unsafe extern "C" fn(*const c_void) -> Ref>,
    allocate: Option<unsafe extern "C" fn(isize, usize, *mut c_void) -> *mut c_void>,
    reallocate: Option<unsafe extern "C" fn(*mut c_void, isize, usize, *mut c_void) -> *mut c_void>,
    deallocate: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    preferred_size: Option<unsafe extern "C" fn(isize, usize, *mut c_void) -> isize>,
}

#[link(name = "CoreFoundation", kind = "framework")]
#[expect(unsafe_code, reason = "the system ABI of the CF object calls")]
unsafe extern "C" {
    safe static kCFBooleanTrue: Ref;
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    static kCFTypeArrayCallBacks: c_void;
    fn CFAllocatorCreate(allocator: Ref, context: *const AllocatorContext) -> Ref;
    fn CFStringCreateWithBytes(allocator: Ref, bytes: *const u8, len: isize, encoding: u32, external: u8) -> Ref;
    fn CFDataCreateWithBytesNoCopy(allocator: Ref, bytes: *const u8, len: isize, deallocator: Ref) -> Ref;
    fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: *const c_void) -> Ref;
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
    safe static kSecUseKeychain: Ref;
    safe static kSecMatchSearchList: Ref;
    fn SecKeychainOpen(path: *const c_char, keychain: *mut Ref) -> i32;
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

/// The secret data of a new item: a `CFData` whose bytes CoreFoundation owns. When the last reference to it goes,
/// CoreFoundation gives the bytes to [`clear`], which clears them and frees them. Thus no reference that the keychain
/// keeps can outlive the bytes, and no copy of them stays in freed memory.
pub(super) struct Secret(Owned);

impl Secret {
    /// The secret data of `len` bytes that `fill` writes, in memory that rscrypto clears when it drops.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] with [`ErrorKind::OutOfMemory`] if an allocation refuses, and each error of `fill`.
    #[expect(
        unsafe_code,
        reason = "CoreFoundation takes the ownership of the bytes through the deallocator of the data"
    )]
    pub(super) fn new(len: usize, fill: impl FnOnce(&mut [u8]) -> Result<(), Error>) -> Result<Self, Error> {
        let bytes = SecretVec::try_fill_with(len, fill).map_err(|error| match error {
            SecretVecConstructionError::Allocation(_) => OUT_OF_MEMORY,
            SecretVecConstructionError::Fill(error) => error,
        })?;
        // The box keeps the bytes in their allocation. Its pointer is the `info` of the deallocator.
        let (start, len) = (bytes.as_bytes().as_ptr(), bytes.len());
        let owner = Box::into_raw(Box::new(bytes));
        let context = AllocatorContext {
            version: 0,
            info: owner.cast(),
            retain: None,
            release: None,
            copy_description: None,
            allocate: None,
            reallocate: None,
            deallocate: Some(clear),
            preferred_size: None,
        };
        // SAFETY: the context is valid for the call, which copies it. An allocator with no `allocate` serves only as
        // the deallocator of the bytes of one data object.
        let deallocator = Owned::new(unsafe { CFAllocatorCreate(ptr::null(), &raw const context) });
        let Some(deallocator) = deallocator else {
            // SAFETY: no allocator exists, so this is the one owner of the box.
            drop(unsafe { Box::from_raw(owner) });
            return Err(OUT_OF_MEMORY);
        };
        // SAFETY: `start` points to `len` bytes, and a slice has at most `isize::MAX` bytes. The bytes live in the box
        // until the deallocator frees it. The data object retains the deallocator, which this owner then releases.
        let data = unsafe { CFDataCreateWithBytesNoCopy(ptr::null(), start, len.cast_signed(), deallocator.get()) };
        Owned::new(data).map(Self).ok_or_else(|| {
            // SAFETY: CoreFoundation gives no data object, and it takes the bytes only with the object it creates, so
            // this is the one owner of the box.
            drop(unsafe { Box::from_raw(owner) });
            OUT_OF_MEMORY
        })
    }
}

/// The deallocator of the bytes of a [`Secret`]: it drops the box `info` that owns them, so rscrypto clears and frees
/// them.
///
/// # Safety
///
/// `info` is the box of [`Secret::new`], and this is its one call: CoreFoundation calls it once, when the data object
/// of the allocator goes.
#[expect(unsafe_code, reason = "the callback of CoreFoundation that ends the box of a secret")]
unsafe extern "C" fn clear(_: *mut c_void, info: *mut c_void) {
    // SAFETY: `info` is the box that `Secret::new` gave to the one data object of this allocator, and CoreFoundation
    // calls the deallocator once, when that object goes.
    drop(unsafe { Box::from_raw(info.cast::<SecretVec>()) });
}

/// The login keychain of the user of the process: its file under the home directory. The default keychain and the
/// keychain search list of the user can name other keychains, so each operation names this one.
///
/// # Errors
///
/// [`Error::Storage`] if the process has no home directory, and [`Error::Vault`] with the status of a refusal.
#[expect(unsafe_code, reason = "SecKeychainOpen gives a new reference to a keychain")]
fn login() -> Result<Owned, Error> {
    let path = std::env::home_dir()
        .ok_or(Error::Storage(ErrorKind::NotFound))?
        .join(LOGIN);
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Storage(ErrorKind::InvalidInput))?;
    let mut keychain = ptr::null();
    // SAFETY: `path` is a NUL-terminated string, and `keychain` is a valid place for the result.
    status(unsafe { SecKeychainOpen(path.as_ptr(), &raw mut keychain) })?;
    Owned::new(keychain).ok_or(OUT_OF_MEMORY)
}

/// The search list of one keychain, `keychain`.
#[expect(unsafe_code, reason = "CFArrayCreate over one valid CF object")]
fn only(keychain: &Owned) -> Result<Owned, Error> {
    let values = [keychain.get()];
    // SAFETY: the array has one valid CF object, and the CF type callbacks retain it.
    let list = unsafe { CFArrayCreate(ptr::null(), values.as_ptr(), 1, &raw const kCFTypeArrayCallBacks) };
    Owned::new(list).ok_or(OUT_OF_MEMORY)
}

/// Adds the item `account` of `service` to the login keychain, with the data `data`.
///
/// # Errors
///
/// [`Error::Exists`] if the item exists. [`Error::Vault`] with the status of another refusal.
#[expect(unsafe_code, reason = "SecItemAdd of a valid dictionary")]
pub(super) fn add(service: &str, account: &str, data: Secret) -> Result<(), Error> {
    let keychain = login()?;
    let attributes = query(
        service,
        account,
        [(kSecValueData, data.0.get()), (kSecUseKeychain, keychain.get())],
    )?;
    // The dictionary retains the data, so the data ends when the dictionary and this owner drop.
    drop(data);
    // SAFETY: `attributes` is a valid dictionary, and a null result place asks for no result.
    status(unsafe { SecItemAdd(attributes.get(), ptr::null_mut()) })
}

/// The data of the item `account` of `service` in the login keychain.
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
    let list = only(&login()?)?;
    let query = query(
        service,
        account,
        [(kSecReturnData, kCFBooleanTrue), (kSecMatchSearchList, list.get())],
    )?;
    let mut result = ptr::null();
    // SAFETY: `query` is a valid dictionary, and `result` is a valid place for the result.
    status(unsafe { SecItemCopyMatching(query.get(), &raw mut result) })?;
    let result = Owned::new(result).ok_or(Error::Mismatch)?;
    // SAFETY: `result` is a valid CF object.
    (unsafe { CFGetTypeID(result.get()) } == CFDataGetTypeID()).ok_or(Error::Mismatch)?;
    Ok(Data(result))
}

/// Deletes the item `account` of `service` from the login keychain.
///
/// # Errors
///
/// [`Error::Unknown`] if the item does not exist. [`Error::Vault`] with the status of another refusal.
#[expect(unsafe_code, reason = "SecItemDelete of a valid query")]
pub(super) fn delete(service: &str, account: &str) -> Result<(), Error> {
    let list = only(&login()?)?;
    let query = query(service, account, [(kSecMatchSearchList, list.get())])?;
    // SAFETY: `query` is a valid dictionary.
    status(unsafe { SecItemDelete(query.get()) })
}

/// The dictionary of the generic-password item `account` of `service`, with the pairs `extra`. The dictionary retains
/// each key and value.
#[expect(unsafe_code, reason = "CFDictionaryCreate over arrays of valid CF objects")]
fn query<const N: usize>(service: &str, account: &str, extra: [(Ref, Ref); N]) -> Result<Owned, Error> {
    let (service, account) = (string(service)?, string(account)?);
    let base = [
        (kSecClass, kSecClassGenericPassword),
        (kSecAttrService, service.get()),
        (kSecAttrAccount, account.get()),
    ];
    let (keys, values): (alloc::vec::Vec<Ref>, alloc::vec::Vec<Ref>) = base.into_iter().chain(extra).unzip();
    // SAFETY: each entry of each array is a valid CF object, and the arrays have one length. The CF type callbacks
    // retain them, so the dictionary does not depend on the owners of this function.
    let query = unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            keys.len().cast_signed(),
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
