//! The key-file permissions of Windows: the user of the process owns the key file, and its protected DACL allows only
//! that user. The declarations are the system ABI of `advapi32` and `kernel32`.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::DropGuard;
use core::ptr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

use crate::custody::Error;

type RawHandle = *mut c_void;
type Sid = *mut c_void;

/// `GetCurrentProcessToken()`: the pseudo-handle -4 of the access token of the process. It needs no close.
const CURRENT_PROCESS_TOKEN: RawHandle = ptr::without_provenance_mut(usize::MAX - 3);
/// `INVALID_HANDLE_VALUE`: the handle -1.
const INVALID_HANDLE_VALUE: RawHandle = ptr::without_provenance_mut(usize::MAX);
/// `TokenUser` of `TOKEN_INFORMATION_CLASS`.
const TOKEN_USER: i32 = 1;
const SDDL_REVISION_1: u32 = 1;
const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_NEW: u32 = 1;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// `SE_FILE_OBJECT` of `SE_OBJECT_TYPE`.
const SE_FILE_OBJECT: i32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 4;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// `SE_DACL_PROTECTED` of `SECURITY_DESCRIPTOR_CONTROL`: the DACL takes no entry that a parent passes on.
const SE_DACL_PROTECTED: u16 = 0x1000;
/// The offset of the SID in an `ACCESS_ALLOWED_ACE`: after its header and its access mask.
const ACE_SID_OFFSET: usize = 8;
/// The most UTF-16 units in the text form of a SID: "S-1-", an authority of up to 15 digits, and 15 sub-authorities
/// of up to 11 characters each.
const SID_TEXT_MAX: usize = 192;

/// The buffer of a `TOKEN_USER`: 16 bytes, then a SID of at most 68 bytes.
type TokenBuffer = [u64; 16];
#[expect(clippy::cast_possible_truncation, reason = "the buffer has 128 bytes")]
const TOKEN_BYTES: u32 = size_of::<TokenBuffer>() as u32;
#[expect(clippy::cast_possible_truncation, reason = "the structure has 24 bytes")]
const ATTRIBUTES_BYTES: u32 = size_of::<SecurityAttributes>() as u32;

/// `SECURITY_ATTRIBUTES`.
#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit: i32,
}

/// `TOKEN_USER`: a `SID_AND_ATTRIBUTES`.
#[repr(C)]
struct TokenUser {
    sid: Sid,
    attributes: u32,
}

/// The header of an `ACL`.
#[repr(C)]
struct Acl {
    revision: u8,
    sbz1: u8,
    size: u16,
    count: u16,
    sbz2: u16,
}

/// `ACE_HEADER`.
#[repr(C)]
struct AceHeader {
    kind: u8,
    flags: u8,
    size: u16,
}

#[link(name = "advapi32", kind = "raw-dylib")]
#[expect(unsafe_code, reason = "the system ABI of the token and security-descriptor calls")]
unsafe extern "system" {
    fn GetTokenInformation(
        token: RawHandle,
        class: i32,
        information: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: Sid, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        length: *mut u32,
    ) -> i32;
    fn GetSecurityInfo(
        handle: RawHandle,
        kind: i32,
        information: u32,
        owner: *mut Sid,
        group: *mut Sid,
        dacl: *mut *mut Acl,
        sacl: *mut *mut Acl,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn EqualSid(a: Sid, b: Sid) -> i32;
    fn GetSecurityDescriptorControl(descriptor: *mut c_void, control: *mut u16, revision: *mut u32) -> i32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
#[expect(unsafe_code, reason = "the system ABI of the file and memory calls")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const SecurityAttributes,
        disposition: u32,
        flags: u32,
        template: RawHandle,
    ) -> RawHandle;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

/// Creates the key file `path`. The user of the process is its owner, and its protected DACL allows only that user.
/// The descriptor applies when the file is created, so no other account can open the file at any time. It refuses
/// a file that exists.
#[expect(unsafe_code, reason = "CreateFileW with a security descriptor that std cannot give")]
pub(super) fn create(path: &Path) -> io::Result<File> {
    with_user(|user| {
        let text = descriptor_text(user)?;
        let mut descriptor = ptr::null_mut();
        // SAFETY: `text` is a NUL-terminated UTF-16 string, and `descriptor` is a valid place for the result.
        let done = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        };
        if done == 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = DropGuard::new(descriptor, |descriptor| {
            // SAFETY: the conversion allocated the descriptor with LocalAlloc, and this is its last use.
            unsafe { LocalFree(descriptor) };
        });
        let attributes = SecurityAttributes {
            length: ATTRIBUTES_BYTES,
            descriptor: *descriptor,
            inherit: 0,
        };
        let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
        if name.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        name.push(0);
        // SAFETY: `name` is NUL-terminated, `attributes` and its descriptor live until the call returns, and a null
        // template is valid.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW gave a new handle that nothing else owns.
        Ok(unsafe { File::from_raw_handle(handle) })
    })
}

/// Opens the key file `path` to read it.
pub(super) fn open(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Refuses a key file whose owner is not the user of the process, or whose DACL allows another account or is not
/// protected. A DACL that is not protected takes the entries that a later change of a parent passes on.
#[expect(
    unsafe_code,
    reason = "GetSecurityInfo reads the owner and the DACL, which std cannot read"
)]
pub(super) fn check(file: &File) -> Result<(), Error> {
    with_user(|user| {
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: the handle stays open while `file` lives, and each out pointer is a valid place for its result.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &raw mut owner,
                ptr::null_mut(),
                &raw mut dacl,
                ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if status != 0 {
            return Err(
                i32::try_from(status).map_or(Error::Permissions, |code| io::Error::from_raw_os_error(code).into())
            );
        }
        let descriptor = DropGuard::new(descriptor, |descriptor| {
            // SAFETY: GetSecurityInfo allocated the descriptor with LocalAlloc, and this is its last use.
            unsafe { LocalFree(descriptor) };
        });
        let (mut control, mut revision) = (0, 0);
        // SAFETY: the descriptor is the valid descriptor that GetSecurityInfo gave, and each out pointer is a valid
        // place for its result.
        if unsafe { GetSecurityDescriptorControl(*descriptor, &raw mut control, &raw mut revision) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: `owner` and `dacl` point into the descriptor, which lives until this closure returns, and `user` is
        // a valid SID.
        let only_user = !owner.is_null() && unsafe { EqualSid(owner, user) != 0 && allows_only(dacl, user) };
        (only_user && control & SE_DACL_PROTECTED != 0).ok_or(Error::Permissions)
    })
}

/// Whether `dacl` has one entry, and it allows `user`. A null DACL allows each account.
///
/// # Safety
///
/// `dacl` is null or points to a valid ACL, and `user` is a valid SID.
#[expect(unsafe_code, reason = "reads the first ACE of an ACL that GetSecurityInfo gave")]
unsafe fn allows_only(dacl: *const Acl, user: Sid) -> bool {
    if dacl.is_null() {
        return false;
    }
    // SAFETY: the caller gives a valid ACL. Its first ACE follows its header, and the condition reads the ACE only
    // when the ACL has one. The SID of an ACCESS_ALLOWED_ACE follows its header and its mask.
    unsafe {
        let ace = dacl.add(1).cast::<AceHeader>();
        (*dacl).count == 1
            && (*ace).kind == ACCESS_ALLOWED_ACE_TYPE
            && EqualSid(ace.byte_add(ACE_SID_OFFSET).cast_mut().cast(), user) != 0
    }
}

/// The SDDL text of the descriptor of a key file: the owner is `user`, and the protected DACL allows only `user`.
#[expect(unsafe_code, reason = "ConvertSidToStringSidW gives a string that LocalFree frees")]
fn descriptor_text(user: Sid) -> io::Result<Vec<u16>> {
    let mut text = ptr::null_mut();
    // SAFETY: `user` is a valid SID, and `text` is a valid place for the result.
    if unsafe { ConvertSidToStringSidW(user, &raw mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let text = DropGuard::new(text, |text| {
        // SAFETY: the conversion allocated the string with LocalAlloc, and this is its last use.
        unsafe { LocalFree(text.cast()) };
    });
    // SAFETY: the conversion gave a NUL-terminated string, and the search stops at its NUL.
    let len = (0..SID_TEXT_MAX)
        .find(|&at| unsafe { text.add(at).read() } == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    // SAFETY: the `len` units before the NUL are the initialized text of the SID.
    let sid = unsafe { core::slice::from_raw_parts(*text, len) };
    let mut out = Vec::new();
    out.extend("O:".encode_utf16());
    out.extend_from_slice(sid);
    out.extend("D:P(A;;FA;;;".encode_utf16());
    out.extend_from_slice(sid);
    out.extend(")\0".encode_utf16());
    Ok(out)
}

/// Runs `f` with the SID of the user of the process.
#[expect(unsafe_code, reason = "GetTokenInformation fills a TOKEN_USER that std cannot read")]
fn with_user<T, E: From<io::Error>>(f: impl FnOnce(Sid) -> Result<T, E>) -> Result<T, E> {
    let mut buffer: TokenBuffer = [0; 16];
    let mut returned = 0;
    // SAFETY: `buffer` has `TOKEN_BYTES` bytes and the alignment of a TOKEN_USER, and the pseudo-handle needs no
    // close.
    let done = unsafe {
        GetTokenInformation(
            CURRENT_PROCESS_TOKEN,
            TOKEN_USER,
            buffer.as_mut_ptr().cast(),
            TOKEN_BYTES,
            &raw mut returned,
        )
    };
    if done == 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the call wrote a TOKEN_USER at the start of `buffer`. Its SID points into `buffer`, which lives until
    // `f` returns.
    let sid = unsafe { buffer.as_ptr().cast::<TokenUser>().read().sid };
    f(sid)
}

/// Windows gives no flush of a directory through std. The flush of the key file is the durability of enroll and
/// delete.
pub(super) const fn sync_dir(_: &Path) -> Result<(), Error> {
    Ok(())
}
