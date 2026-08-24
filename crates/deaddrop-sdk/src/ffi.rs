//! C ABI. Python/Go/Swift/Kotlin bindings should link this, not crate internals.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

#[unsafe(no_mangle)]
pub extern "C" fn dd_version() -> *mut c_char {
    CString::new(deaddrop_core::PROTOCOL_LABEL)
        .unwrap()
        .into_raw()
}

/// # Safety
/// `s` must be a malloc'd string from this ABI or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dd_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dd_protocol_version() -> c_int {
    deaddrop_core::PROTOCOL_VERSION as c_int
}

/// # Safety
/// `path` is a UTF-8 C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dd_node_open(path: *const c_char) -> c_int {
    if path.is_null() {
        return -1;
    }
    let p = unsafe { CStr::from_ptr(path) }.to_string_lossy();
    match crate::DeadDrop::open_dir(std::path::Path::new(p.as_ref())) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
