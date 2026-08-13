//! Dual-backend dispatch (docs/TEST_CONTRACT.md, docs/ABI.md).
//!
//! - `backend-rust` (default): pure Rust implementation in this crate.
//! - `backend-lean`: Lean AOT `libcarbonado` via `carbonado-sys` (G8 dual-backend).
//!
//! Both features must not be enabled together for a single build that links both
//! engines into conflicting paths; prefer one engine per `cargo test` invocation.
//!
//! ## Phase 2–3 dispatch surface (`backend-lean`)
//!
//! Lean C ABI is used for: low-level [`crate::encode`]/crate::decode`],
//! [`crate::encode_outboard`]/crate::decode_outboard`],
//! [`crate::scrub`]/crate::scrub_outboard`], [`crate::verify_slice`]/crate::extract_slice`],
//! headered [`crate::file::encode`]/crate::file::decode`], stream buffer helpers
//! (`stream_encode_buffer` / `stream_decode_buffer` / outboard buffer), **R5/W1 E1**
//! stream I/O (`stream_encode_inboard` / `stream_decode` / **encrypted**
//! `stream_*_outboard` via spool-to-buffer; **W1b public** `stream_*_outboard` is rust S4
//! composition — not Lean spool), and [`lean::verification_key`] for AOT parity checks.
//!
//! ### Phase 3 directory (composition — no new directory C symbols)
//!
//! [`crate::file::encode_directory`] / [`crate::file::decode_directory`] keep:
//! - **Rust:** FS walk, path fail-closed checks, **rkyv** `FilepackManifest` v2 wire
//!   (normative Adamantine payload body), Adamantine envelope/payload framing,
//!   centralized Bao+FEC bundle assembly, catalog COTS trailer.
//! - **Lean (via existing ABI):** segment bare mains via `encode_outboard` /
//!   `decode_outboard` (embedded-nonce layout); catalog container via
//!   `encode_headered` / `decode_headered` (`file::encode` / `file::decode`).
//!
//! Dual-suite catalogs are therefore **rkyv** (same bytes as `backend-rust`), not
//! Lean-only CFP2. **W3:** pure Lean Directory/CLI also emit rkyv (wire-compatible);
//! dual-suite encode remains Rust rkyv composition SSOT. CFP2 is dual-decode fallback only.
//!
//! ### Phase 4 PQC / CLI / OTS (composition)
//!
//! - **SLH-DSA (G10-A dual-suite + R9 pure Lean):** dual-suite product path may use
//!   Rust `crypto::slh_*` + `bitcoinpqc` under both backends (composition). Lean holds
//!   wire parse/build + bind-to-root (`Carbonado/Slh.lean`). **R9/G10:** pure Lean
//!   `signRoot` / `verifyRoot` are live via `carbonado_slh_*` + libbitcoinpqc pin in
//!   `libcarbonado` — dual-suite need not switch from composition.
//! - **CLI dual path (honest):**
//!   - **Dual-engine:** directory CLI → `encode_directory` / `decode_directory`
//!     (Lean segment/catalog crypto); buffer single-file APIs (`file::encode`,
//!     `encode_outboard`, headered decode) dispatch to Lean under `backend-lean`.
//!   - **R5 E1 + W1 stream dual:** `stream_encode_inboard` / `stream_decode` and
//!     **encrypted** `stream_*_outboard` spool-to-buffer → Lean C ABI (O(logical) E1).
//!     **W1b public** `stream_encode_outboard` / `stream_decode_outboard` use rust S4
//!     geometric composition under lean (**E2 O(chunk/stripe)** when !Compression;
//!     Compression under lean is O(logical) bulk zstd; G9 no-compress wire bit-match;
//!     not pure Lean stream). `encode_stream` uses Lean via `stream_encode_inboard`.
//!     **W1a:** `file::decode_stream` verifies `header_mac` then spools body → Lean
//!     `decode_headered` (E1).
//!   - Build with `--features "backend-lean,pqc,ots,cli"` + `CARBONADO_LEAN_*` for a
//!     lean-**linked** binary. Default `cargo build --bin carbonado` remains rust-engine.
//! - **Directory OTS:** offline CBOTS stubs in Rust (`ots` feature); composition
//!   over Lean container crypto — no Lean-native stamping.
//!
//! **G8 full closed at R7** under `backend-lean`: freeze = unfiltered
//! `just test-lean-ci` (`cargo test --no-default-features --features
//! "backend-lean,pqc,ots,cli"`). Former residual suites (`format`, `codec`,
//! `header_tamper`, `format_amplification`, `streaming`/`streaming_limits`,
//! `seekable_slices`, `sharding`, `fec_chaos`, `bin_*`) are freeze-green.
//!
//! **Post-G8 residuals** (purity / feature-policy / composition honesty — not dual-suite red):
//! ~~pure-Lean rkyv encode~~ **W3 closed** (Lean `encodeRkyvManifest` + Directory/CLI; dual-suite
//! catalog encode still Rust rkyv composition SSOT), ~~stream E2 / dual honesty~~ **W1a+W1b closed** (public outboard S4
//! composition E2; pure Lean chunked C residual), G9 Compression/directory encode bit-match
//! (**W2** permanent W2a/W2b), ~~codecode/decodec~~ **W2d closed**, ~~W4a inboard O(slice) retain~~
//! **closed**, **W4b** permanent full-buffer C outboard slice, **W4c** permanent buffer-only zstd
//! under lean, **W4d** permanent FEC O(body) + async encoded spool,
//! `streaming_async` / `parallel_determinism` permanently feature-gated off freeze (R10:
//! freeze never requires `async` / `parallel`; Lean RS is serial).
//!
//! **R9 closed (optional pure Lean depth):** G10 SLH-DSA live in `libcarbonado`
//! (`carbonado_slh_*` + Lean `@[extern]`); seekable outboard slice C
//! (`carbonado_verify_slice_outboard` / Lean range verify); rkyv dual-decode residual
//! documented (composition remains SSOT for dual-suite directory wire).
//!
//! **R10 closed (async dual policy):** dual freeze **never** requires `async`
//! (`streaming_async` stays feature-gated → 0 tests under lean freeze). Optional
//! `stream_decode_async` stages the encoded body then calls dual-aware
//! [`crate::stream::stream_decode`] (R5 E1 under `backend-lean`; S4 pipeline under
//! `backend-rust`) — no silent pure-Rust pipeline when lean+async are both enabled.
//! WASM async remains `NotImplemented`.
//!
//! **R1 fail-closed (outboard Option semantics):** `None` means missing sidecar and
//! must error when the format bit requires it (`MissingVerificationOutboard` /
//! `MissingFecParity`). `Some(&[])` is a present empty outboard (valid for single-leaf
//! Bao trees) and is allowed through. Guarded in [`lean::decode_outboard`] before C.

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
    use crate::structs::{EncodeInfo, Encoded, OutboardEncoded};
    use carbonado_sys as sys;

    pub const NAME: &str = "lean";

    /// ABI version from the linked libcarbonado (requires `CARBONADO_LEAN_LIB`).
    pub fn abi_version() -> u32 {
        unsafe { sys::carbonado_abi_version() }
    }

    /// Map C ABI codes to `CarbonadoError` (docs/ABI.md).
    pub fn map_err(code: i32) -> CarbonadoError {
        match code {
            // P2 residual: no dedicated InvalidArgument variant (docs/ABI.md error table).
            // Includes Lean-only wrong-length SLH/meta on encodeHeaderedBytes if ever
            // surfaced via C; typed Rust Option<&[u8; N]> cannot express those lengths.
            sys::CARBONADO_ERR_INVALID_ARGUMENT => {
                CarbonadoError::InternalStateError("lean-backend invalid argument".into())
            }
            sys::CARBONADO_ERR_INVALID_KEY_LENGTH => CarbonadoError::InvalidKeyLength,
            sys::CARBONADO_ERR_AUTHENTICATION => CarbonadoError::AuthenticationFailed,
            sys::CARBONADO_ERR_INVALID_MAGIC => {
                CarbonadoError::InvalidMagicNumber("lean-backend".into())
            }
            // Truncated/malformed header, body bounds, or short inboard Bao prefix
            // (`invalidPrefix` / `invalidHeaderLength` via ofPipelineError).
            sys::CARBONADO_ERR_INVALID_HEADER => CarbonadoError::InvalidHeaderLength,
            sys::CARBONADO_ERR_FEC => CarbonadoError::UnevenFecChunks,
            // Stream truncation / trailing data / root-length / residual slice geometry
            // that was not pre-checked in `lean::verify_slice`. Bao *auth* failures use
            // CARBONADO_ERR_AUTHENTICATION (R4).
            sys::CARBONADO_ERR_BAO => {
                CarbonadoError::BaoResponseTruncated("lean-backend bao/verify".into())
            }
            sys::CARBONADO_ERR_ZSTD => CarbonadoError::ZstdError("lean-backend zstd".into()),
            sys::CARBONADO_ERR_SCRUB_UNNECESSARY => CarbonadoError::UnnecessaryScrub,
            sys::CARBONADO_ERR_SCRUB_FAILED => CarbonadoError::InvalidScrubbedHash,
            sys::CARBONADO_ERR_SCRUB_REQUIRES_VERIFICATION => {
                CarbonadoError::ScrubRequiresVerification
            }
            sys::CARBONADO_ERR_NOT_IMPLEMENTED => CarbonadoError::NotImplemented,
            sys::CARBONADO_ERR_INTERNAL => {
                CarbonadoError::InternalStateError("lean-backend internal error".into())
            }
            _ => CarbonadoError::InternalStateError(format!("lean-backend unknown error {code}")),
        }
    }

    /// Copy a libcarbonado `malloc` buffer into a Rust `Vec`, then free via C.
    ///
    /// Avoids `Vec::from_raw_parts` over foreign allocators (jemalloc/mimalloc-safe).
    fn take_buf(out: *mut u8, out_len: usize) -> Result<Vec<u8>, CarbonadoError> {
        if out.is_null() {
            if out_len == 0 {
                return Ok(Vec::new());
            }
            return Err(map_err(sys::CARBONADO_ERR_INTERNAL));
        }
        let mut v = Vec::with_capacity(out_len);
        // SAFETY: `out` is a non-null malloc buffer of length `out_len` from libcarbonado.
        unsafe {
            v.extend_from_slice(std::slice::from_raw_parts(out, out_len));
            sys::carbonado_free(out as *mut _);
        }
        Ok(v)
    }

    /// Free a raw libcarbonado buffer if non-null (best-effort cleanup on multi-out failures).
    fn free_raw(p: *mut u8) {
        if !p.is_null() {
            unsafe { sys::carbonado_free(p as *mut _) };
        }
    }

    /// Format-keyed Bao verification key (32 bytes).
    pub fn verification_key(format: u8) -> Result<[u8; 32], CarbonadoError> {
        let mut key = [0u8; 32];
        let rc = unsafe { sys::carbonado_verification_key(format, key.as_mut_ptr()) };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        Ok(key)
    }

    /// Low-level body encode (≈ `encoding::encode`). Returns body, Bao root, padding + meta.
    ///
    /// # `EncodeInfo` (R3)
    ///
    /// Stage counters (`bytes_compressed`, `bytes_encrypted`) and FEC/Bao geometry
    /// (`padding_len`, `chunk_len`, `bytes_ecc`, `verifiable_slice_count`) are filled
    /// from the Lean pack. Skipped stages report **0** (matches Rust stream path).
    pub fn encode(
        master: &[u8],
        plaintext: &[u8],
        format: u8,
        nonce: Option<&[u8; 16]>,
    ) -> Result<Encoded, CarbonadoError> {
        let (nonce_ptr, nonce_len) = match nonce {
            Some(n) => (n.as_ptr(), 16usize),
            None => (std::ptr::null(), 0usize),
        };
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let mut hash_out = [0u8; 32];
        let mut padding_len = 0u32;
        let mut chunk_len = 0u32;
        let mut bytes_ecc = 0u32;
        let mut verifiable_slice_count = 0u32;
        let mut bytes_compressed = 0u32;
        let mut bytes_encrypted = 0u32;
        let rc = unsafe {
            sys::carbonado_encode(
                master.as_ptr(),
                master.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                format,
                nonce_ptr,
                nonce_len,
                &mut out,
                &mut out_len,
                hash_out.as_mut_ptr(),
                &mut padding_len,
                &mut chunk_len,
                &mut bytes_ecc,
                &mut verifiable_slice_count,
                &mut bytes_compressed,
                &mut bytes_encrypted,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        let body = take_buf(out, out_len)?;
        let hash = crate::utils::decode_bao_hash(&hash_out)?;
        let chunk_slice_count = if verifiable_slice_count > 0 {
            verifiable_slice_count / 8
        } else {
            0
        };
        let input_len = plaintext.len() as u32;
        let info = EncodeInfo {
            input_len,
            output_len: body.len() as u32,
            bytes_compressed,
            compression_factor: bytes_compressed as f32 / input_len.max(1) as f32,
            bytes_encrypted,
            bytes_ecc,
            bytes_verifiable: body.len() as u32,
            // Match Rust stream: empty input → 0.0 (not 1.0).
            amplification_factor: body.len() as f32 / input_len.max(1) as f32,
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count,
        };
        Ok(Encoded(body, hash, info))
    }

    /// Low-level body decode (≈ `decoding::decode` buffer path).
    pub fn decode(
        master: &[u8],
        hash: &[u8],
        body: &[u8],
        padding: u32,
        format: u8,
    ) -> Result<Vec<u8>, CarbonadoError> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::carbonado_decode(
                master.as_ptr(),
                master.len(),
                hash.as_ptr(),
                hash.len(),
                body.as_ptr(),
                body.len(),
                padding,
                format,
                &mut out,
                &mut out_len,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        take_buf(out, out_len)
    }

    /// Headered encode via Lean AOT (explicit 16-byte nonce when encrypted).
    ///
    /// `slh_public_key` / `metadata`: when `None`, header fields are zeros (matches Rust).
    ///
    /// Returns the full archive (`Header || body`) and pipeline [`EncodeInfo`] stage
    /// counters (R3: compress/encrypt + FEC/Bao geometry from Lean pack).
    pub fn encode_headered(
        master: &[u8],
        plaintext: &[u8],
        format: u8,
        nonce: Option<&[u8; 16]>,
        slh_public_key: Option<&[u8; 32]>,
        metadata: Option<&[u8; 8]>,
    ) -> Result<(Vec<u8>, EncodeInfo), CarbonadoError> {
        let (nonce_ptr, nonce_len) = match nonce {
            Some(n) => (n.as_ptr(), 16usize),
            None => (std::ptr::null(), 0usize),
        };
        let slh_ptr = slh_public_key
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());
        let meta_ptr = metadata.map(|m| m.as_ptr()).unwrap_or(std::ptr::null());
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let mut padding_len = 0u32;
        let mut chunk_len = 0u32;
        let mut bytes_ecc = 0u32;
        let mut verifiable_slice_count = 0u32;
        let mut bytes_compressed = 0u32;
        let mut bytes_encrypted = 0u32;
        let rc = unsafe {
            sys::carbonado_encode_headered(
                master.as_ptr(),
                master.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                format,
                nonce_ptr,
                nonce_len,
                slh_ptr,
                meta_ptr,
                &mut out,
                &mut out_len,
                &mut padding_len,
                &mut chunk_len,
                &mut bytes_ecc,
                &mut verifiable_slice_count,
                &mut bytes_compressed,
                &mut bytes_encrypted,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        let archive = take_buf(out, out_len)?;
        let body_len = archive.len().saturating_sub(crate::file::Header::LEN) as u32;
        let chunk_slice_count = if verifiable_slice_count > 0 {
            verifiable_slice_count / 8
        } else {
            0
        };
        let input_len = plaintext.len() as u32;
        let info = EncodeInfo {
            input_len,
            output_len: body_len,
            bytes_compressed,
            compression_factor: bytes_compressed as f32 / input_len.max(1) as f32,
            bytes_encrypted,
            bytes_ecc,
            bytes_verifiable: body_len,
            // Match Rust stream: empty input → 0.0 (not 1.0).
            amplification_factor: body_len as f32 / input_len.max(1) as f32,
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count,
        };
        Ok((archive, info))
    }

    /// Headered decode via Lean AOT → (Header, plaintext).
    pub fn decode_headered(
        master: &[u8],
        archive: &[u8],
    ) -> Result<(crate::file::Header, Vec<u8>), CarbonadoError> {
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
        let plaintext = take_buf(out, out_len)?;
        // Reconstruct Header from archive prefix (already MAC-verified inside Lean).
        if archive.len() < crate::file::Header::LEN {
            return Err(CarbonadoError::InvalidHeaderLength);
        }
        let header = crate::file::Header::try_from(&archive[..crate::file::Header::LEN])?;
        Ok((header, plaintext))
    }

    /// Outboard encode via Lean AOT.
    ///
    /// `header_path`: when true (and encrypted), bare main is `[tag|ct]` with nonce
    /// out-of-band (matches `file::encode_outboard`). When false, embedded `[nonce|tag|ct]`
    /// (matches low-level `encoding::encode_outboard`).
    pub fn encode_outboard(
        master: &[u8],
        plaintext: &[u8],
        format: u8,
        nonce: Option<&[u8; 16]>,
        header_path: bool,
    ) -> Result<OutboardEncoded, CarbonadoError> {
        let (nonce_ptr, nonce_len) = match nonce {
            Some(n) => (n.as_ptr(), 16usize),
            None => (std::ptr::null(), 0usize),
        };
        let mut main_out: *mut u8 = std::ptr::null_mut();
        let mut main_len: usize = 0;
        let mut ob_out: *mut u8 = std::ptr::null_mut();
        let mut ob_len: usize = 0;
        let mut par_out: *mut u8 = std::ptr::null_mut();
        let mut par_len: usize = 0;
        let mut hash_out = [0u8; 32];
        let mut padding_len = 0u32;
        let mut chunk_len = 0u32;
        let mut bytes_compressed = 0u32;
        let mut bytes_encrypted = 0u32;
        let rc = unsafe {
            sys::carbonado_encode_outboard(
                master.as_ptr(),
                master.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                format,
                nonce_ptr,
                nonce_len,
                u8::from(header_path),
                &mut main_out,
                &mut main_len,
                &mut ob_out,
                &mut ob_len,
                &mut par_out,
                &mut par_len,
                hash_out.as_mut_ptr(),
                &mut padding_len,
                &mut chunk_len,
                &mut bytes_compressed,
                &mut bytes_encrypted,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        // Take all three buffers with cleanup on any failure (no leaked mallocs).
        let main = match take_buf(main_out, main_len) {
            Ok(v) => v,
            Err(e) => {
                free_raw(ob_out);
                free_raw(par_out);
                return Err(e);
            }
        };
        let ob_bytes = match take_buf(ob_out, ob_len) {
            Ok(v) => v,
            Err(e) => {
                free_raw(par_out);
                return Err(e);
            }
        };
        let par_bytes = take_buf(par_out, par_len)?;
        let fmt = crate::constants::Format::from(format);
        // Match Rust stream_encode_outboard_buffer: Verification ⇒ Some(ob) even when
        // empty (valid single-leaf post-order outboard); Fec ⇒ Some(parity) similarly.
        let verification_outboard = if fmt.contains(crate::constants::Format::Verification) {
            Some(ob_bytes)
        } else {
            None
        };
        let fec_parity = if fmt.contains(crate::constants::Format::Fec) {
            Some(par_bytes)
        } else {
            None
        };
        let hash = crate::utils::decode_bao_hash(&hash_out)?;
        // Match Rust: outboard bytes_ecc is the FEC parity sidecar length, not main.len().
        let bytes_ecc = fec_parity.as_ref().map(|p| p.len() as u32).unwrap_or(0);
        let verifiable_slice_count = if fmt.contains(crate::constants::Format::Fec) && chunk_len > 0
        {
            // 8 shards × chunk_len / SLICE_LEN for inboard-equivalent bookkeeping.
            (chunk_len * 8) / crate::constants::SLICE_LEN
        } else {
            0
        };
        let input_len = plaintext.len() as u32;
        let info = EncodeInfo {
            input_len,
            output_len: main.len() as u32,
            bytes_compressed,
            compression_factor: bytes_compressed as f32 / input_len.max(1) as f32,
            bytes_encrypted,
            bytes_ecc,
            bytes_verifiable: main.len() as u32,
            // Match Rust stream: empty input → 0.0 (not 1.0).
            amplification_factor: main.len() as f32 / input_len.max(1) as f32,
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count: if verifiable_slice_count > 0 {
                verifiable_slice_count / 8
            } else {
                0
            },
        };
        Ok(OutboardEncoded {
            main,
            verification_outboard,
            fec_parity,
            hash,
            info,
        })
    }

    /// Outboard decode via Lean AOT.
    ///
    /// `header_path` / `nonce` must match encode-time layout (see [`encode_outboard`]).
    #[allow(clippy::too_many_arguments)]
    pub fn decode_outboard(
        master: &[u8],
        hash: &[u8],
        main: &[u8],
        verification_outboard: Option<&[u8]>,
        fec_parity: Option<&[u8]>,
        padding: u32,
        format: u8,
        nonce: Option<&[u8; 16]>,
        header_path: bool,
    ) -> Result<Vec<u8>, CarbonadoError> {
        // Mirror Rust stream_decode_outboard: `None` (missing sidecar) is distinct from
        // `Some(&[])` (empty outboard for single-leaf trees). Fail closed before C.
        let fmt = crate::constants::Format::from(format);
        if fmt.contains(crate::constants::Format::Verification) && verification_outboard.is_none() {
            return Err(CarbonadoError::MissingVerificationOutboard);
        }
        if fmt.contains(crate::constants::Format::Fec) && fec_parity.is_none() {
            return Err(CarbonadoError::MissingFecParity);
        }
        let ob = verification_outboard.unwrap_or(&[]);
        let par = fec_parity.unwrap_or(&[]);
        let (nonce_ptr, nonce_len) = match nonce {
            Some(n) => (n.as_ptr(), 16usize),
            None => (std::ptr::null(), 0usize),
        };
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::carbonado_decode_outboard(
                master.as_ptr(),
                master.len(),
                hash.as_ptr(),
                hash.len(),
                main.as_ptr(),
                main.len(),
                ob.as_ptr(),
                ob.len(),
                par.as_ptr(),
                par.len(),
                padding,
                format,
                u8::from(header_path),
                nonce_ptr,
                nonce_len,
                &mut out,
                &mut out_len,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        take_buf(out, out_len)
    }

    /// Inboard scrub via Lean AOT.
    pub fn scrub(
        body: &[u8],
        hash: &[u8],
        padding: u32,
        format: u8,
    ) -> Result<Vec<u8>, CarbonadoError> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::carbonado_scrub(
                body.as_ptr(),
                body.len(),
                hash.as_ptr(),
                hash.len(),
                padding,
                format,
                &mut out,
                &mut out_len,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        take_buf(out, out_len)
    }

    /// Outboard scrub via Lean AOT.
    pub fn scrub_outboard(
        main: &[u8],
        verification_outboard: Option<&[u8]>,
        fec_parity: Option<&[u8]>,
        hash: &[u8],
        padding: u32,
        chunk_len: u32,
        format: u8,
    ) -> Result<Vec<u8>, CarbonadoError> {
        let fmt = crate::constants::Format::from(format);
        if !fmt.contains(crate::constants::Format::Verification) {
            return Err(CarbonadoError::ScrubRequiresVerification);
        }
        let Some(ob) = verification_outboard else {
            return Err(CarbonadoError::MissingVerificationOutboard);
        };
        // Fec + None: do not fail closed here. Pristine path can still return
        // UnnecessaryScrub without parity when verify ok; recovery needs parity.
        // Call Lean with empty parity (`unwrap_or`); if FEC err on recovery,
        // map MissingFecParity when parity was None (post-C remap below).
        let par = fec_parity.unwrap_or(&[]);
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::carbonado_scrub_outboard(
                main.as_ptr(),
                main.len(),
                ob.as_ptr(),
                ob.len(),
                par.as_ptr(),
                par.len(),
                hash.as_ptr(),
                hash.len(),
                padding,
                chunk_len,
                format,
                &mut out,
                &mut out_len,
            )
        };
        if rc != sys::CARBONADO_OK {
            // Distinct missing-sidecar modes before collapsing to scrub/FEC.
            if rc == sys::CARBONADO_ERR_FEC
                && fmt.contains(crate::constants::Format::Fec)
                && fec_parity.is_none()
            {
                return Err(CarbonadoError::MissingFecParity);
            }
            return Err(map_err(rc));
        }
        take_buf(out, out_len)
    }

    /// Inboard verify_slice via Lean AOT (W4a: O(slice) retained output in Lean).
    ///
    /// Geometry pre-checks mirror pure-Rust [`crate::stream::slice::verify_slice_inboard_seekable`]
    /// order so dual-suite diagnostics keep `InvalidHeaderLength` / `HashDecodeError` /
    /// `InvalidSliceIndex {..}` fields. Bao auth failures map via ABI
    /// `CARBONADO_ERR_AUTHENTICATION` (R4 / docs/ABI.md).
    ///
    /// **Memory honesty:** Lean retains O(slice) after auth walk; this dispatcher still
    /// passes the full `body` buffer to C (caller-owned input). `count == 0` returns
    /// empty here without calling C (matches pure-Rust short-circuit).
    pub fn verify_slice(
        body: &[u8],
        index: u32,
        count: u32,
        hash: &[u8],
        format: u8,
    ) -> Result<Vec<u8>, CarbonadoError> {
        // Match pure-Rust order (stream/slice.rs::verify_slice_inboard_seekable):
        // 1. count==0 → Ok([])
        // 2. content_len prefix (InvalidHeaderLength if < 8)
        // 3. content_len==0 → InvalidSliceIndex
        // 4. decode_bao_hash (HashDecodeError if len != 32)
        // 5. OOB slice_byte_range → InvalidSliceIndex
        // 6. C verify (auth / truncation / …)
        if count == 0 {
            return Ok(vec![]);
        }
        // Short inboard prefix (<8 B) → InvalidHeaderLength (Rust `inboard_bao_content_len_prefix`).
        // Also enforced in Lean (`invalidPrefix` → ERR_INVALID_HEADER after R4 ofPipelineError).
        if body.len() < 8 {
            return Err(CarbonadoError::InvalidHeaderLength);
        }
        let content_len = u64::from_le_bytes(
            body[0..8]
                .try_into()
                .map_err(|_| CarbonadoError::InvalidHeaderLength)?,
        );
        // Empty-content slice index — structured fields the C ABI cannot carry.
        if content_len == 0 {
            return Err(CarbonadoError::InvalidSliceIndex { index, content_len });
        }
        // Hash length before OOB (pure-Rust order: bad-hash+OOB → HashDecodeError first).
        let _root = crate::utils::decode_bao_hash(hash)?;
        // OOB slice index — need structured fields the C ABI cannot carry.
        let slice_byte_start = u64::from(index) * u64::from(crate::constants::SLICE_LEN);
        if slice_byte_start >= content_len {
            return Err(CarbonadoError::InvalidSliceIndex { index, content_len });
        }

        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::carbonado_verify_slice(
                body.as_ptr(),
                body.len(),
                hash.as_ptr(),
                hash.len(),
                index,
                count,
                format,
                &mut out,
                &mut out_len,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        take_buf(out, out_len)
    }

    /// Seekable outboard verify_slice via Lean AOT (R9; W4b permanent full-buffer C).
    ///
    /// Geometry pre-checks mirror pure-Rust
    /// [`crate::stream::slice::verify_slice_outboard`] for dual-suite diagnostics.
    /// C ABI takes full main + outboard buffers (no ReadAt callback); Lean walks
    /// O(slice + height) over the requested range.
    pub fn verify_slice_outboard(
        data: &[u8],
        outboard_bytes: &[u8],
        data_len: u64,
        index: u32,
        count: u32,
        hash: &[u8],
        format: u8,
    ) -> Result<Vec<u8>, CarbonadoError> {
        if count == 0 {
            return Ok(vec![]);
        }
        if data_len == 0 {
            return Err(CarbonadoError::InvalidSliceIndex {
                index,
                content_len: data_len,
            });
        }
        if data_len as usize != data.len() {
            return Err(CarbonadoError::OutboardVerificationFailed(format!(
                "data_len {data_len} != data buffer {}",
                data.len()
            )));
        }
        let _root = crate::utils::decode_bao_hash(hash)?;
        let slice_byte_start = u64::from(index) * u64::from(crate::constants::SLICE_LEN);
        if slice_byte_start >= data_len {
            return Err(CarbonadoError::InvalidSliceIndex {
                index,
                content_len: data_len,
            });
        }

        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::carbonado_verify_slice_outboard(
                data.as_ptr(),
                data.len(),
                outboard_bytes.as_ptr(),
                outboard_bytes.len(),
                hash.as_ptr(),
                hash.len(),
                index,
                count,
                format,
                &mut out,
                &mut out_len,
            )
        };
        if rc != sys::CARBONADO_OK {
            return Err(map_err(rc));
        }
        take_buf(out, out_len)
    }
}
