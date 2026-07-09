//! Dual-backend dispatch (docs/TEST_CONTRACT.md, docs/ABI.md).
//!
//! - `backend-rust` (default): pure Rust implementation in this crate.
//! - `backend-lean`: Lean AOT `libcarbonado` via `carbonado-sys` (G8 dual-backend).
//!
//! Both features must not be enabled together for a single build that links both
//! engines into conflicting paths; prefer one engine per `cargo test` invocation.

#[cfg(all(feature = "backend-lean", feature = "backend-rust"))]
compile_error!(
    "enable only one of `backend-lean` or `backend-rust` (dual-backend CI runs them separately)"
);

#[cfg(not(any(feature = "backend-lean", feature = "backend-rust")))]
compile_error!("enable `backend-lean` or `backend-rust` (see docs/TEST_CONTRACT.md)");

#[cfg(feature = "backend-rust")]
#[allow(dead_code)] // dispatch hooks land as encode/decode call sites migrate
pub mod rust_engine {
    //! Marker: pure Rust paths are the default implementation modules (`encoding`, `decoding`, …).
    pub const NAME: &str = "rust";
}

#[cfg(feature = "backend-lean")]
pub mod lean {
    //! Lean AOT backend via C ABI (`carbonado-sys` / `libcarbonado`).
    use crate::error::CarbonadoError;
    use carbonado_sys as sys;

    pub const NAME: &str = "lean";

    /// ABI version from the linked libcarbonado (requires `CARBONADO_LEAN_LIB`).
    pub fn abi_version() -> u32 {
        unsafe { sys::carbonado_abi_version() }
    }

    /// Map C ABI codes to `CarbonadoError` (docs/ABI.md). Refined as mapping matures.
    pub fn map_err(code: i32) -> CarbonadoError {
        match code {
            sys::CARBONADO_ERR_INVALID_ARGUMENT => CarbonadoError::InvalidHeaderLength,
            sys::CARBONADO_ERR_INVALID_KEY_LENGTH => {
                CarbonadoError::HashDecodeError(32, 0) // refine when dedicated key variant exists
            }
            sys::CARBONADO_ERR_AUTHENTICATION => CarbonadoError::AuthenticationFailed,
            sys::CARBONADO_ERR_INVALID_MAGIC => {
                CarbonadoError::InvalidMagicNumber("lean-backend".into())
            }
            sys::CARBONADO_ERR_INVALID_HEADER => CarbonadoError::InvalidHeaderLength,
            sys::CARBONADO_ERR_FEC => CarbonadoError::UnevenFecChunks,
            sys::CARBONADO_ERR_BAO => CarbonadoError::InvalidScrubbedHash,
            sys::CARBONADO_ERR_ZSTD => CarbonadoError::ZstdError("lean-backend zstd".into()),
            sys::CARBONADO_ERR_SCRUB_UNNECESSARY => CarbonadoError::UnnecessaryScrub,
            sys::CARBONADO_ERR_SCRUB_FAILED => CarbonadoError::InvalidScrubbedHash,
            sys::CARBONADO_ERR_NOT_IMPLEMENTED => CarbonadoError::ZstdError(
                "lean-backend: C ABI encode/decode not fully wired (Phase 1; stubs return NOT_IMPLEMENTED)"
                    .into(),
            ),
            sys::CARBONADO_ERR_INTERNAL => {
                CarbonadoError::ZstdError("lean-backend internal error".into())
            }
            _ => CarbonadoError::ZstdError(format!("lean-backend unknown error {code}")),
        }
    }

    /// Headered encode via Lean AOT (explicit 16-byte nonce when encrypted).
    pub fn encode_headered(
        master: &[u8],
        plaintext: &[u8],
        format: u8,
        nonce: Option<&[u8; 16]>,
    ) -> Result<Vec<u8>, CarbonadoError> {
        let (nonce_ptr, nonce_len) = match nonce {
            Some(n) => (n.as_ptr(), 16usize),
            None => (std::ptr::null(), 0usize),
        };
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::carbonado_encode_headered(
                master.as_ptr(),
                master.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                format,
                nonce_ptr,
                nonce_len,
                &mut out,
                &mut out_len,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        if out.is_null() {
            return Err(map_err(sys::CARBONADO_ERR_INTERNAL));
        }
        let v = unsafe { Vec::from_raw_parts(out, out_len, out_len) };
        // from_raw_parts takes ownership; do not free via carbonado_free.
        Ok(v)
    }

    /// Headered decode via Lean AOT.
    pub fn decode_headered(master: &[u8], archive: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::carbonado_decode_headered(
                master.as_ptr(),
                master.len(),
                archive.as_ptr(),
                archive.len(),
                &mut out,
                &mut out_len,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        if out.is_null() {
            return Err(map_err(sys::CARBONADO_ERR_INTERNAL));
        }
        Ok(unsafe { Vec::from_raw_parts(out, out_len, out_len) })
    }
}
