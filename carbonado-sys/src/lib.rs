//! Low-level FFI to Lean AOT `libcarbonado` (see `include/carbonado.h`, `docs/ABI.md`).

#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_void};

pub const CARBONADO_ABI_VERSION: u32 = 1;

pub const CARBONADO_OK: c_int = 0;
pub const CARBONADO_ERR_INVALID_ARGUMENT: c_int = 1;
pub const CARBONADO_ERR_INVALID_KEY_LENGTH: c_int = 2;
pub const CARBONADO_ERR_AUTHENTICATION: c_int = 3;
pub const CARBONADO_ERR_INVALID_MAGIC: c_int = 4;
pub const CARBONADO_ERR_INVALID_HEADER: c_int = 5;
pub const CARBONADO_ERR_FEC: c_int = 6;
pub const CARBONADO_ERR_BAO: c_int = 7;
pub const CARBONADO_ERR_ZSTD: c_int = 8;
pub const CARBONADO_ERR_SCRUB_UNNECESSARY: c_int = 9;
pub const CARBONADO_ERR_SCRUB_FAILED: c_int = 10;
pub const CARBONADO_ERR_NOT_IMPLEMENTED: c_int = 11;
pub const CARBONADO_ERR_INTERNAL: c_int = 12;

extern "C" {
    pub fn carbonado_abi_version() -> u32;
    pub fn carbonado_free(p: *mut c_void);
    pub fn carbonado_encode(
        master: *const u8,
        master_len: usize,
        plaintext: *const u8,
        plaintext_len: usize,
        format: u8,
        nonce: *const u8,
        nonce_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
        hash_out: *mut u8,
    ) -> c_int;
    pub fn carbonado_decode(
        master: *const u8,
        master_len: usize,
        hash: *const u8,
        hash_len: usize,
        body: *const u8,
        body_len: usize,
        padding: u32,
        format: u8,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn carbonado_encode_headered(
        master: *const u8,
        master_len: usize,
        plaintext: *const u8,
        plaintext_len: usize,
        format: u8,
        nonce: *const u8,
        nonce_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn carbonado_decode_headered(
        master: *const u8,
        master_len: usize,
        archive: *const u8,
        archive_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn carbonado_verification_key(format: u8, key_out: *mut u8) -> c_int;
}

/// Safe wrapper: free a buffer returned by libcarbonado.
///
/// # Safety
/// `p` must be null or a pointer returned by libcarbonado.
pub unsafe fn free(p: *mut u8) {
    carbonado_free(p as *mut c_void);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_matches_header() {
        // Only runs when linked against libcarbonado (CARBONADO_LEAN_LIB set).
        if std::env::var_os("CARBONADO_LEAN_LIB").is_none() {
            eprintln!("skip: CARBONADO_LEAN_LIB unset");
            return;
        }
        let v = unsafe { carbonado_abi_version() };
        assert_eq!(v, CARBONADO_ABI_VERSION);
    }
}
