//! The key-file permissions of Linux and macOS: a regular file of the effective user, the mode `0600`, and on macOS no
//! extended ACL entry. The flags of the open are the system ABI of each target.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::custody::Error;

// `O_NOFOLLOW` and `O_NONBLOCK` of `<fcntl.h>`. Linux gives other values on other architectures, so each target names
// its values, and another target does not build.
cfg_select! {
    target_os = "macos" => {
        const NO_FOLLOW: i32 = 0x0100;
        const NON_BLOCK: i32 = 0x0004;
    }
    all(target_os = "linux", target_arch = "x86_64") => {
        const NO_FOLLOW: i32 = 0o400_000;
        const NON_BLOCK: i32 = 0o4_000;
    }
    all(target_os = "linux", target_arch = "aarch64") => {
        const NO_FOLLOW: i32 = 0o100_000;
        const NON_BLOCK: i32 = 0o4_000;
    }
    _ => {
        compile_error!("the native custody declares the open flags of macOS, and of Linux on x86_64 and aarch64 only");
    }
}

#[expect(unsafe_code, reason = "the system ABI of the user ID of the process")]
unsafe extern "C" {
    safe fn geteuid() -> u32;
}

/// Creates the key file `path` with the mode `0600`. It refuses a file that exists.
pub(super) fn create(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

/// Opens the key file `path` to read it. The open follows no link at `path`, so a link refuses. A FIFO or a device at
/// `path` does not block the open, and [`check`] then refuses it.
pub(super) fn open(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(NO_FOLLOW | NON_BLOCK)
        .open(path)
}

/// Refuses a key file that is not a regular file of the effective user of the process, or that another account can
/// read or change: a mode bit of the group or of others, or an extended ACL entry on macOS. With a POSIX ACL on Linux,
/// the group bits are the mask of the ACL, so they also cover each named entry. The checks read the open descriptor,
/// so a change of the path after the open does not change them.
pub(super) fn check(file: &File) -> Result<(), Error> {
    let metadata = file.metadata()?;
    let own = metadata.file_type().is_file() && metadata.uid() == geteuid();
    (own && metadata.permissions().mode() & 0o077 == 0 && !extended_acl(file)?).ok_or(Error::Permissions)
}

/// Makes the entries of `dir` durable.
pub(super) fn sync_dir(dir: &Path) -> Result<(), Error> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

cfg_select! {
    target_os = "macos" => {
        /// Whether `file` has an entry in its extended ACL. A macOS ACL entry gives access that the mode bits do not
        /// limit, and a new file takes the inherited entries of its directory.
        #[expect(
            unsafe_code,
            reason = "three libSystem ACL calls on a descriptor that `file` keeps open"
        )]
        fn extended_acl(file: &File) -> Result<bool, Error> {
            use core::ffi::{c_int, c_void};
            use std::os::fd::AsRawFd;

            /// `ACL_TYPE_EXTENDED` of `<sys/acl.h>`.
            const ACL_TYPE_EXTENDED: c_int = 0x100;
            /// `ACL_FIRST_ENTRY` of `<sys/acl.h>`.
            const ACL_FIRST_ENTRY: c_int = 0;

            unsafe extern "C" {
                fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
                fn acl_get_entry(acl: *mut c_void, id: c_int, entry: *mut *mut c_void) -> c_int;
                fn acl_free(object: *mut c_void) -> c_int;
            }

            // SAFETY: the descriptor stays open while `file` lives, and the call only reads its ACL.
            let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
            if acl.is_null() {
                // ENOENT: the file has no extended ACL.
                let error = io::Error::last_os_error();
                return if error.kind() == io::ErrorKind::NotFound {
                    Ok(false)
                } else {
                    Err(error.into())
                };
            }
            let mut entry = core::ptr::null_mut();
            // SAFETY: `acl` is the valid ACL that acl_get_fd_np gave, and `entry` is a valid place for the result.
            let first = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) };
            // SAFETY: `acl` came from acl_get_fd_np, and nothing uses it or `entry` after this call.
            unsafe { acl_free(acl) };
            Ok(first == 0)
        }
    }
    _ => {
        /// Linux has no ACL entry that the mode bits do not limit.
        const fn extended_acl(_: &File) -> Result<bool, Error> {
            Ok(false)
        }
    }
}
