//! Carbonado streaming encode pipelines (inboard + outboard).

use std::io::{Read, Seek, SeekFrom, Write};

use bao::Hash;

use crate::{
    constants::{Format, FEC_M, SLICE_LEN},
    error::CarbonadoError,
    stream::{
        compress::stream_compress,
        crypto_stream::{
            stream_encrypt, stream_encrypt_embedded_with_nonce, stream_encrypt_with_nonce_seek,
        },
        fec::{feed_inboard_fec_stripe, write_inboard_stripe, FecStripeReadAt},
        spool::SeekableSpool,
    },
    structs::{EncodeInfo, OutboardEncoded},
};

// Outboard S4 geometric pipeline (backend-rust always; backend-lean W1b public E2).
use crate::stream::bao::stream_verification_outboard;
// Buffer-path helpers (rust engine encode_buffer only).
#[cfg(feature = "backend-rust")]
use crate::stream::{
    bao::{verification_inboard_buffer, verification_outboard_buffer},
    compress::compress_buffer,
    crypto_stream::stream_encrypt_with_nonce,
    fec::{encode_inboard_buffer, encode_outboard_parity_buffer},
};

struct CountingReader<R> {
    inner: R,
    count: u64,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

/// Statistics from [`stream_preprocess`].
#[derive(Clone, Copy, Debug)]
pub struct PreprocessStats {
    pub bare_len: u64,
    pub input_len: u64,
    pub bytes_compressed: u32,
}

/// Run compress → encrypt into `body_sink`.
///
/// When `header_path_encrypt` is true (file layer), encrypted output is `[tag|ct]` with
/// nonce written to `payload_nonce`. When false (CLI/low-level), nonce is embedded
/// in the sink as `[nonce|tag|ct]`.
///
/// **`fixed_nonce`:** when `Some(n)` and Encryption is set, use `n` literally (including
/// all-zero — dual-backend identical). When `None`, draw a CSPRNG nonce (production).
/// Prefer CSPRNG for live archives; fixed nonces are for tests/determinism only — see
/// AGENTS §2.1.4 (nonce uniqueness; reuse under the same master is catastrophic).
pub fn stream_preprocess<R: Read, W: Read + Write + Seek>(
    master_key: &[u8],
    format: Format,
    mut input: R,
    body_sink: &mut W,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
    fixed_nonce: Option<[u8; 16]>,
) -> Result<PreprocessStats, CarbonadoError> {
    body_sink
        .seek(std::io::SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;
    let mut input_len = 0u64;
    if format.contains(Format::Compression) {
        let mut counter = CountingReader {
            inner: &mut input,
            count: 0,
        };
        stream_compress(&mut counter, &mut *body_sink)?;
        input_len = counter.count;
        body_sink.rewind().map_err(CarbonadoError::StdIoError)?;
    } else {
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = input.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
            if n == 0 {
                break;
            }
            input_len += n as u64;
            body_sink
                .write_all(&buf[..n])
                .map_err(CarbonadoError::StdIoError)?;
        }
    }
    body_sink.rewind().map_err(CarbonadoError::StdIoError)?;
    let bytes_compressed = if format.contains(Format::Compression) {
        reader_len(body_sink)? as u32
    } else {
        0
    };

    let bare_len = if format.contains(Format::Encryption) {
        let comp_len = reader_len(body_sink)?;
        body_sink
            .seek(SeekFrom::Start(0))
            .map_err(CarbonadoError::StdIoError)?;
        if header_path_encrypt {
            match fixed_nonce {
                Some(n) => *payload_nonce = n,
                None => {
                    getrandom::getrandom(payload_nonce)
                        .map_err(|_| CarbonadoError::RandomnessError)?;
                }
            }
            encrypt_preprocess_sink(master_key, *payload_nonce, body_sink, comp_len)?;
        } else {
            let mut encrypted_spool = SeekableSpool::new()?;
            match fixed_nonce {
                Some(n) => {
                    stream_encrypt_embedded_with_nonce(
                        master_key,
                        n,
                        std::io::Read::by_ref(body_sink).take(comp_len),
                        &mut encrypted_spool,
                    )?;
                    *payload_nonce = n;
                }
                None => {
                    let (_len, nonce) = stream_encrypt(
                        master_key,
                        std::io::Read::by_ref(body_sink).take(comp_len),
                        &mut encrypted_spool,
                    )?;
                    *payload_nonce = nonce;
                }
            }
            replace_preprocess_encrypted(body_sink, &mut encrypted_spool)?;
        }
        reader_len(body_sink)?
    } else {
        reader_len(body_sink)?
    };
    body_sink.rewind().map_err(CarbonadoError::StdIoError)?;
    Ok(PreprocessStats {
        bare_len,
        input_len,
        bytes_compressed,
    })
}

/// [`stream_preprocess`] for [`SeekableSpool`] sinks — encrypt replace uses
/// [`SeekableSpool::overwrite_from`] so file size matches ciphertext (no stale tail bytes).
#[cfg_attr(feature = "backend-lean", allow(dead_code))] // rust stream_encode_inboard only
pub(crate) fn stream_preprocess_spool<R: Read>(
    master_key: &[u8],
    format: Format,
    mut input: R,
    body_sink: &mut SeekableSpool,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
    fixed_nonce: Option<[u8; 16]>,
) -> Result<PreprocessStats, CarbonadoError> {
    body_sink.rewind()?;
    let mut input_len = 0u64;
    if format.contains(Format::Compression) {
        let mut counter = CountingReader {
            inner: &mut input,
            count: 0,
        };
        stream_compress(&mut counter, &mut *body_sink)?;
        input_len = counter.count;
        body_sink.rewind()?;
    } else {
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = input.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
            if n == 0 {
                break;
            }
            input_len += n as u64;
            body_sink
                .write_all(&buf[..n])
                .map_err(CarbonadoError::StdIoError)?;
        }
    }
    body_sink.rewind()?;
    let bytes_compressed = if format.contains(Format::Compression) {
        body_sink.content_len()? as u32
    } else {
        0
    };

    let bare_len = if format.contains(Format::Encryption) {
        let comp_len = body_sink.content_len()?;
        body_sink.rewind()?;
        if header_path_encrypt {
            match fixed_nonce {
                Some(n) => *payload_nonce = n,
                None => {
                    getrandom::getrandom(payload_nonce)
                        .map_err(|_| CarbonadoError::RandomnessError)?;
                }
            }
            encrypt_preprocess_spool(master_key, *payload_nonce, body_sink, comp_len)?;
        } else {
            let mut encrypted_spool = SeekableSpool::new()?;
            match fixed_nonce {
                Some(n) => {
                    stream_encrypt_embedded_with_nonce(
                        master_key,
                        n,
                        std::io::Read::by_ref(body_sink).take(comp_len),
                        &mut encrypted_spool,
                    )?;
                    *payload_nonce = n;
                }
                None => {
                    let (_len, nonce) = stream_encrypt(
                        master_key,
                        std::io::Read::by_ref(body_sink).take(comp_len),
                        &mut encrypted_spool,
                    )?;
                    *payload_nonce = nonce;
                }
            }
            body_sink.overwrite_from(&mut encrypted_spool)?;
        }
        body_sink.content_len()?
    } else {
        body_sink.content_len()?
    };
    body_sink.rewind()?;
    Ok(PreprocessStats {
        bare_len,
        input_len,
        bytes_compressed,
    })
}

/// Encrypt `len` bytes from `sink` in place via a temp spool (no full-body `Vec`).
fn encrypt_preprocess_sink<W: Read + Write + Seek>(
    master_key: &[u8],
    nonce: [u8; 16],
    sink: &mut W,
    len: u64,
) -> Result<(), CarbonadoError> {
    sink.seek(SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;
    let mut encrypted = SeekableSpool::new()?;
    stream_encrypt_with_nonce_seek(
        master_key,
        nonce,
        std::io::Read::by_ref(sink).take(len),
        &mut encrypted,
    )?;
    replace_preprocess_encrypted(sink, &mut encrypted)
}

/// Header-path encrypt for [`SeekableSpool`] preprocess sinks (uses [`SeekableSpool::overwrite_from`]).
#[cfg_attr(feature = "backend-lean", allow(dead_code))] // rust stream_preprocess_spool only
pub(crate) fn encrypt_preprocess_spool(
    master_key: &[u8],
    nonce: [u8; 16],
    sink: &mut SeekableSpool,
    len: u64,
) -> Result<(), CarbonadoError> {
    sink.rewind()?;
    let mut encrypted = SeekableSpool::new()?;
    stream_encrypt_with_nonce_seek(
        master_key,
        nonce,
        std::io::Read::by_ref(sink).take(len),
        &mut encrypted,
    )?;
    sink.overwrite_from(&mut encrypted)
}

/// Copy encrypted spool back into a seekable preprocess sink (no full-body `Vec`).
fn replace_preprocess_encrypted<W: Read + Write + Seek>(
    sink: &mut W,
    src: &mut SeekableSpool,
) -> Result<(), CarbonadoError> {
    src.rewind()?;
    sink.seek(SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;
    std::io::copy(src, sink).map_err(CarbonadoError::StdIoError)?;
    sink.seek(SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;
    Ok(())
}

fn reader_len<R: Read + Seek>(r: &mut R) -> Result<u64, CarbonadoError> {
    r.seek(std::io::SeekFrom::End(0))
        .map_err(CarbonadoError::StdIoError)
}

/// Primary inboard encode (buffer). Used by [`crate::encoding::encode`].
///
/// Under `backend-lean`, composes over Lean C ABI body encode (same engine as
/// [`crate::encode`]) so streaming buffer tests do not silently use pure Rust.
///
/// Encrypted formats draw a random nonce (embedded layout). For a fixed nonce
/// (G9 fixtures), use [`stream_encode_buffer_with_nonce`].
pub fn stream_encode_buffer(
    master_key: &[u8],
    input: &[u8],
    format: u8,
) -> Result<(Vec<u8>, Hash, EncodeInfo), CarbonadoError> {
    stream_encode_buffer_with_nonce(master_key, input, format, None)
}

/// Inboard body encode with optional fixed nonce for encrypted formats.
///
/// When `explicit_nonce` is `Some(n)` and the Encryption bit is set, the low-level
/// embedded layout is `[nonce(16) | tag(64) | ct]` with `n` (including all-zero).
/// When `None`, encrypted formats use a CSPRNG nonce. Public formats ignore the nonce.
///
/// Production defaults are unchanged: [`stream_encode_buffer`] / [`crate::encode`] pass `None`.
///
/// # Safety / intended use
///
/// Fixed nonces are for **tests and determinism only**. Prefer [`stream_encode_buffer`]
/// for production. Nonce reuse under the same master is catastrophic (AGENTS §2.1.4).
pub fn stream_encode_buffer_with_nonce(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
) -> Result<(Vec<u8>, Hash, EncodeInfo), CarbonadoError> {
    #[cfg(feature = "backend-lean")]
    {
        let nonce = if format & 1 != 0 {
            match explicit_nonce {
                Some(n) => Some(n),
                None => {
                    let mut n = [0u8; 16];
                    getrandom::getrandom(&mut n).map_err(|_| CarbonadoError::RandomnessError)?;
                    Some(n)
                }
            }
        } else {
            None
        };
        let crate::structs::Encoded(body, hash, info) =
            crate::backend::lean::encode(master_key, input, format, nonce.as_ref())?;
        Ok((body, hash, info))
    }
    #[cfg(feature = "backend-rust")]
    {
        stream_encode_buffer_rust(master_key, input, format, explicit_nonce)
    }
}

#[cfg(feature = "backend-rust")]
fn stream_encode_buffer_rust(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
) -> Result<(Vec<u8>, Hash, EncodeInfo), CarbonadoError> {
    let fmt = Format::from(format);
    let input_len = input.len() as u32;
    let mut body = input.to_vec();
    let mut bytes_compressed = 0u32;
    let mut bytes_encrypted = 0u32;

    if fmt.contains(Format::Compression) {
        body = compress_buffer(input)?;
        bytes_compressed = body.len() as u32;
    }
    if fmt.contains(Format::Encryption) {
        body = {
            let mut out = SeekableSpool::new()?;
            match explicit_nonce {
                Some(nonce) => {
                    stream_encrypt_embedded_with_nonce(
                        master_key,
                        nonce,
                        std::io::Cursor::new(&body),
                        &mut out,
                    )?;
                }
                None => {
                    let (_len, _nonce) =
                        stream_encrypt(master_key, std::io::Cursor::new(&body), &mut out)?;
                }
            }
            let mut buf = Vec::new();
            out.rewind()?;
            std::io::copy(&mut out, &mut buf).map_err(CarbonadoError::StdIoError)?;
            buf
        };
        bytes_encrypted = body.len() as u32;
    }

    let (after_fec, padding_len, chunk_len, bytes_ecc) = if fmt.contains(Format::Fec) {
        let (encoded, pl, cl) = encode_inboard_buffer(&body)?;
        let be = encoded.len() as u32;
        (encoded, pl, cl, be)
    } else {
        (body, 0, 0, 0)
    };

    let verifiable_slice_count = if fmt.contains(Format::Fec) {
        bytes_ecc / SLICE_LEN
    } else {
        0
    };
    if fmt.contains(Format::Fec) && !verifiable_slice_count.is_multiple_of(8) {
        return Err(CarbonadoError::InvalidVerifiableSliceCount(
            verifiable_slice_count,
        ));
    }

    let (verifiable, hash) = if fmt.contains(Format::Verification) {
        verification_inboard_buffer(&after_fec, format)?
    } else {
        (after_fec, Hash::from([0u8; 32]))
    };

    let bytes_verifiable = verifiable.len() as u32;
    Ok((
        verifiable,
        hash,
        EncodeInfo {
            input_len,
            output_len: bytes_verifiable,
            bytes_compressed,
            bytes_encrypted,
            bytes_ecc,
            bytes_verifiable,
            compression_factor: bytes_compressed as f32 / input_len.max(1) as f32,
            amplification_factor: bytes_verifiable as f32 / input_len.max(1) as f32,
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count: verifiable_slice_count / 8,
        },
    ))
}

/// Primary outboard encode (buffer). Used by [`crate::encoding::encode_outboard`].
///
/// When `explicit_nonce` is `Some`, encrypted output is `[tag(64) | ct]` (header path).
/// When `None`, encrypted output embeds the nonce (low-level path).
///
/// Under `backend-lean`, composes over Lean C ABI with matching layout:
/// `explicit_nonce.is_some()` → `header_path=true` (`[tag|ct]`); else embedded-nonce.
pub fn stream_encode_outboard_buffer(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
) -> Result<OutboardEncoded, CarbonadoError> {
    #[cfg(feature = "backend-lean")]
    {
        let header_path = explicit_nonce.is_some();
        let nonce = if format & 1 != 0 {
            if let Some(n) = explicit_nonce {
                Some(n)
            } else {
                let mut n = [0u8; 16];
                getrandom::getrandom(&mut n).map_err(|_| CarbonadoError::RandomnessError)?;
                Some(n)
            }
        } else {
            None
        };
        crate::backend::lean::encode_outboard(
            master_key,
            input,
            format,
            nonce.as_ref(),
            header_path,
        )
    }
    #[cfg(feature = "backend-rust")]
    {
        stream_encode_outboard_buffer_rust(master_key, input, format, explicit_nonce)
    }
}

#[cfg(feature = "backend-rust")]
fn stream_encode_outboard_buffer_rust(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
) -> Result<OutboardEncoded, CarbonadoError> {
    let fmt = Format::from(format);
    let input_len = input.len() as u32;
    let mut bytes_compressed = 0u32;

    let compressed = if fmt.contains(Format::Compression) {
        let c = compress_buffer(input)?;
        bytes_compressed = c.len() as u32;
        c
    } else {
        input.to_vec()
    };

    let post_comp_or_enc;
    let bytes_encrypted;
    if fmt.contains(Format::Encryption) {
        post_comp_or_enc = {
            let mut out = SeekableSpool::new()?;
            if let Some(nonce) = explicit_nonce {
                stream_encrypt_with_nonce(
                    master_key,
                    nonce,
                    std::io::Cursor::new(&compressed),
                    &mut out,
                )?;
            } else {
                stream_encrypt(master_key, std::io::Cursor::new(&compressed), &mut out)?;
            }
            let mut buf = Vec::new();
            out.rewind()?;
            std::io::copy(&mut out, &mut buf).map_err(CarbonadoError::StdIoError)?;
            buf
        };
        bytes_encrypted = post_comp_or_enc.len() as u32;
    } else {
        post_comp_or_enc = compressed;
        bytes_encrypted = 0;
    }

    let (post_fec_or_bare, padding_len, chunk_len, bytes_ecc, fec_parity, vslice, cslice) =
        if fmt.contains(Format::Fec) {
            let (pl, cl, parity) = encode_outboard_parity_buffer(&post_comp_or_enc)?;
            let would_bytes = (FEC_M as u32) * cl;
            let vs = would_bytes / SLICE_LEN;
            if !vs.is_multiple_of(8) {
                return Err(CarbonadoError::InvalidVerifiableSliceCount(vs));
            }
            (
                post_comp_or_enc,
                pl,
                cl,
                parity.len() as u32,
                Some(parity),
                vs,
                vs / 8,
            )
        } else {
            (post_comp_or_enc, 0, 0, 0, None, 0, 0)
        };

    let (main_for_return, bao_out, hash, bytes_verifiable) = if fmt.contains(Format::Verification) {
        let bv = post_fec_or_bare.len() as u32;
        let (ob, h) = verification_outboard_buffer(&post_fec_or_bare, format)?;
        (post_fec_or_bare, Some(ob), h, bv)
    } else {
        let bv = post_fec_or_bare.len() as u32;
        (post_fec_or_bare, None, Hash::from([0; 32]), bv)
    };

    Ok(OutboardEncoded {
        main: main_for_return,
        verification_outboard: bao_out,
        fec_parity,
        hash,
        info: EncodeInfo {
            input_len,
            output_len: bytes_verifiable,
            bytes_compressed,
            bytes_encrypted,
            bytes_ecc,
            bytes_verifiable,
            compression_factor: bytes_compressed as f32 / input_len.max(1) as f32,
            amplification_factor: bytes_verifiable as f32 / input_len.max(1) as f32,
            padding_len,
            chunk_len,
            verifiable_slice_count: vslice,
            chunk_slice_count: cslice,
        },
    })
}

/// Stream outboard encode to writers (public + encrypted).
///
/// # Memory / dual-backend matrix (W1b)
///
/// | Backend | Path | Peak RAM | Engine |
/// |---------|------|----------|--------|
/// | `backend-rust` | all formats | **O(chunk/stripe)** S4 (compress streams) | rust geometric + streaming EtM |
/// | `backend-lean` | **public non-Compression** (c0/c4/c8/c12) | **O(chunk/stripe) E2** | rust S4 geometric composition (G9 **no-compress** wire bit-match; c4/c12 evidenced); **not** pure-Lean stream |
/// | `backend-lean` | **public + Compression** (c2/c6/c10/c14) | **O(logical)** at bulk zstd | same S4 composition; compress uses Lean-parity buffer zstd (not E2) |
/// | `backend-lean` | **encrypted** | O(logical) E1 | Lean `encode_outboard` (crypto dual) |
///
/// Buffer APIs ([`stream_encode_outboard_buffer`]) remain Lean under `backend-lean` always.
/// Pure Lean chunked stream residual remains (no streaming C ABI). See docs/LIMITS.md.
///
/// **Encrypted nonces:** both backends always draw a CSPRNG nonce for this stream API
/// (dual-identical). For a fixed nonce (tests/G9), use [`stream_encode_outboard_buffer`]
/// with `Some(nonce)` (header-path layout when `Some`).
#[allow(clippy::too_many_arguments)]
pub fn stream_encode_outboard<M: Read + Write + Seek, O: Write, P: Write>(
    master_key: &[u8],
    input: impl Read,
    format: u8,
    main_out: &mut M,
    bao_out: Option<&mut O>,
    parity_out: Option<&mut P>,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
) -> Result<(Hash, EncodeInfo), CarbonadoError> {
    #[cfg(feature = "backend-lean")]
    {
        let fmt = Format::from(format);
        // W1b: public → S4 composition (E2 only when !Compression; see rustdoc matrix).
        // Encrypted stays Lean E1 dual crypto.
        if !fmt.contains(Format::Encryption) {
            stream_encode_outboard_s4(
                master_key,
                input,
                format,
                main_out,
                bao_out,
                parity_out,
                payload_nonce,
                header_path_encrypt,
            )
        } else {
            stream_encode_outboard_lean(
                master_key,
                input,
                format,
                main_out,
                bao_out,
                parity_out,
                payload_nonce,
                header_path_encrypt,
            )
        }
    }
    #[cfg(feature = "backend-rust")]
    {
        stream_encode_outboard_s4(
            master_key,
            input,
            format,
            main_out,
            bao_out,
            parity_out,
            payload_nonce,
            header_path_encrypt,
        )
    }
}

/// Lean E1: disk-spool plaintext (O(chunk) ingest) → `lean::encode_outboard` → write-all.
///
/// Peak RAM remains O(logical) at the Lean buffer boundary (encrypted dual crypto).
#[cfg(feature = "backend-lean")]
#[allow(clippy::too_many_arguments)]
fn stream_encode_outboard_lean<M: Write + Seek, O: Write, P: Write>(
    master_key: &[u8],
    input: impl Read,
    format: u8,
    main_out: &mut M,
    mut bao_out: Option<&mut O>,
    mut parity_out: Option<&mut P>,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
) -> Result<(Hash, EncodeInfo), CarbonadoError> {
    use crate::filepack_manifest::MAX_SEGMENT_MAIN_LEN;

    let fmt = Format::from(format);
    // Fail-closed before Lean work: required sidecar writers must be present when
    // format bits demand them (decode-side lean::decode_outboard already enforces
    // the symmetric Missing* contract). Rust stream path hard-requires Bao writer
    // for Verification; FEC writer is fail-closed here for dual-backend symmetry
    // with decode (silent drop of Lean-produced parity would diverge API contracts).
    if fmt.contains(Format::Verification) && bao_out.is_none() {
        return Err(CarbonadoError::MissingVerificationOutboard);
    }
    if fmt.contains(Format::Fec) && parity_out.is_none() {
        return Err(CarbonadoError::MissingFecParity);
    }

    // Disk-backed ingest (O(chunk) during copy); materialize once for Lean buffer ABI.
    let plaintext = SeekableSpool::spool_then_materialize(input, Some(MAX_SEGMENT_MAIN_LEN))?;

    // Always CSPRNG when encrypted (matches rust `stream_preprocess(..., fixed_nonce=None)`).
    // Fixed-nonce outboard: `stream_encode_outboard_buffer(..., Some(nonce))`.
    let encrypted = fmt.contains(Format::Encryption);
    if encrypted {
        getrandom::getrandom(payload_nonce).map_err(|_| CarbonadoError::RandomnessError)?;
    } else {
        *payload_nonce = [0u8; 16];
    }
    let nonce = if encrypted {
        Some(*payload_nonce)
    } else {
        None
    };

    let oenc = crate::backend::lean::encode_outboard(
        master_key,
        &plaintext,
        format,
        nonce.as_ref(),
        header_path_encrypt,
    )?;
    // Free plaintext before writing outputs (avoid simultaneous pt + main peak).
    drop(plaintext);

    main_out
        .seek(SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;
    main_out
        .write_all(&oenc.main)
        .map_err(CarbonadoError::StdIoError)?;

    if let Some(ob_writer) = bao_out.as_mut() {
        if let Some(ref ob) = oenc.verification_outboard {
            ob_writer
                .write_all(ob)
                .map_err(CarbonadoError::StdIoError)?;
        }
    }
    if let Some(par_writer) = parity_out.as_mut() {
        if let Some(ref par) = oenc.fec_parity {
            par_writer
                .write_all(par)
                .map_err(CarbonadoError::StdIoError)?;
        }
    }

    Ok((oenc.hash, oenc.info))
}

/// S4 outboard encode: O(chunk/stripe) peak RAM (public geometric + encrypted EtM spool).
///
/// Under `backend-lean` this is the **W1b public** composition path (caller gates Encryption).
/// Peak is E2 O(chunk/stripe) only when !Compression; Compression under lean is O(logical) bulk zstd.
#[allow(clippy::too_many_arguments)]
fn stream_encode_outboard_s4<M: Read + Write + Seek, O: Write, P: Write>(
    master_key: &[u8],
    input: impl Read,
    format: u8,
    main_out: &mut M,
    mut bao_out: Option<&mut O>,
    mut parity_out: Option<&mut P>,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
) -> Result<(Hash, EncodeInfo), CarbonadoError> {
    let fmt = Format::from(format);
    // Fail-closed: required sidecar writers when format bits demand them (matches
    // lean E1 stream_encode_outboard_lean + decode Missing* contract).
    if fmt.contains(Format::Verification) && bao_out.is_none() {
        return Err(CarbonadoError::MissingVerificationOutboard);
    }
    if fmt.contains(Format::Fec) && parity_out.is_none() {
        return Err(CarbonadoError::MissingFecParity);
    }
    // Stream outboard uses CSPRNG when encrypted (`fixed_nonce = None`). Deterministic
    // encrypted outboard goldens use [`stream_encode_outboard_buffer`] with `Some(nonce)`.
    let stats = stream_preprocess(
        master_key,
        fmt,
        input,
        main_out,
        payload_nonce,
        header_path_encrypt,
        None,
    )?;
    let bare_len = stats.bare_len;
    main_out.rewind().map_err(CarbonadoError::StdIoError)?;

    let (padding_len, chunk_len, bytes_ecc, _fec_parity_len) = if fmt.contains(Format::Fec) {
        if bare_len == 0 {
            (0, 0, 0, 0)
        } else {
            let (stripe, pl, cl) = feed_inboard_fec_stripe(bare_len as usize, &mut *main_out)?;
            // parity_out is Some after fail-closed check above.
            let par = parity_out
                .as_mut()
                .ok_or(CarbonadoError::MissingFecParity)?;
            let par_len = crate::stream::fec::write_outboard_parity(&stripe, par)?;
            main_out.rewind().map_err(CarbonadoError::StdIoError)?;
            (pl, cl, par_len as u32, par_len as u32)
        }
    } else {
        (0, 0, 0, 0)
    };

    let hash = if fmt.contains(Format::Verification) {
        let ob = bao_out
            .as_mut()
            .ok_or(CarbonadoError::MissingVerificationOutboard)?;
        stream_verification_outboard(&mut *main_out, bare_len, format, ob)?
    } else {
        Hash::from([0u8; 32])
    };

    let verifiable_slice_count = if fmt.contains(Format::Fec) {
        ((FEC_M as u32) * chunk_len) / SLICE_LEN
    } else {
        0
    };
    if fmt.contains(Format::Fec) && !verifiable_slice_count.is_multiple_of(8) {
        return Err(CarbonadoError::InvalidVerifiableSliceCount(
            verifiable_slice_count,
        ));
    }

    Ok((
        hash,
        EncodeInfo {
            input_len: stats.input_len as u32,
            output_len: bare_len as u32,
            bytes_compressed: stats.bytes_compressed,
            bytes_encrypted: if fmt.contains(Format::Encryption) {
                bare_len as u32
            } else {
                0
            },
            bytes_ecc,
            bytes_verifiable: bare_len as u32,
            compression_factor: stats.bytes_compressed as f32 / stats.input_len.max(1) as f32,
            amplification_factor: bare_len as f32 / stats.input_len.max(1) as f32,
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count: verifiable_slice_count / 8,
        },
    ))
}

/// Stream inboard encode body from an in-memory staging buffer.
pub fn stream_encode_inboard_body_from_bytes<W: Write>(
    body: &[u8],
    preprocess: PreprocessStats,
    format: u8,
    output: &mut W,
) -> Result<(Hash, EncodeInfo), CarbonadoError> {
    stream_encode_inboard_body(std::io::Cursor::new(body), preprocess, format, output)
}

/// Stream inboard encode body to `output` from post-preprocess source.
///
/// `preprocess` carries original [`PreprocessStats::input_len`] plus post-compress/encrypt
/// [`PreprocessStats::bare_len`] for accurate [`EncodeInfo`] bookkeeping.
///
/// FEC (`Format::Fec`) feeds `data` incrementally via [`FecInboardEncoder`] — peak encode
/// memory is O(stripe), not O(bare_len). Verification reads the FEC stripe via
/// [`FecStripeReadAt`] without flattening to a staging `Vec` (S3).
pub fn stream_encode_inboard_body<D: Read + Seek, W: Write>(
    mut data: D,
    preprocess: PreprocessStats,
    format: u8,
    output: &mut W,
) -> Result<(Hash, EncodeInfo), CarbonadoError> {
    let fmt = Format::from(format);
    let content_len = preprocess.bare_len;

    let (padding_len, chunk_len, bytes_ecc, hash, bytes_verifiable) = if fmt.contains(Format::Fec) {
        if content_len == 0 {
            let (hash, bytes_verifiable) = if fmt.contains(Format::Verification) {
                let (h, written) =
                    crate::stream::bao::stream_verification_inboard(&[][..], 0, format, output)?;
                (h, written as u32)
            } else {
                (Hash::from([0; 32]), 0)
            };
            (0, 0, 0, hash, bytes_verifiable)
        } else {
            data.rewind().map_err(CarbonadoError::StdIoError)?;
            // S2: `Read::take(content_len)` + `feed_inboard_fec_stripe` — regression:
            // `streaming_limits::stream_encode_inboard_body_fec_bounded_read_contract`
            let (stripe, padding_len, chunk_len) =
                feed_inboard_fec_stripe(content_len as usize, &mut data)?;
            let bytes_ecc = (FEC_M as u32) * chunk_len;

            if fmt.contains(Format::Verification) {
                let stripe_view = FecStripeReadAt::new(&stripe);
                let fec_len = stripe_view.len();
                let (h, written) = crate::stream::bao::stream_verification_inboard(
                    stripe_view,
                    fec_len,
                    format,
                    output,
                )?;
                (padding_len, chunk_len, bytes_ecc, h, written as u32)
            } else {
                let written = write_inboard_stripe(&stripe, output)? as u32;
                (
                    padding_len,
                    chunk_len,
                    bytes_ecc,
                    Hash::from([0; 32]),
                    written,
                )
            }
        }
    } else if fmt.contains(Format::Verification) {
        data.rewind().map_err(CarbonadoError::StdIoError)?;
        let (h, written) = crate::stream::bao::stream_verification_inboard(
            crate::stream::bao::SeekReadAt::new(data, content_len),
            content_len,
            format,
            output,
        )?;
        (0, 0, 0, h, written as u32)
    } else {
        data.rewind().map_err(CarbonadoError::StdIoError)?;
        let written = stream_copy(&mut data, content_len, output)? as u32;
        (0, 0, 0, Hash::from([0; 32]), written)
    };

    let verifiable_slice_count = if fmt.contains(Format::Fec) {
        bytes_ecc / SLICE_LEN
    } else {
        0
    };
    if fmt.contains(Format::Fec) && !verifiable_slice_count.is_multiple_of(8) {
        return Err(CarbonadoError::InvalidVerifiableSliceCount(
            verifiable_slice_count,
        ));
    }

    let bytes_compressed = if fmt.contains(Format::Compression) {
        preprocess.bytes_compressed
    } else {
        0
    };
    let bytes_encrypted = if fmt.contains(Format::Encryption) {
        preprocess.bare_len as u32
    } else {
        0
    };
    let compression_factor = if fmt.contains(Format::Compression) {
        preprocess.bytes_compressed as f32 / preprocess.input_len.max(1) as f32
    } else {
        0.0
    };

    Ok((
        hash,
        EncodeInfo {
            input_len: preprocess.input_len as u32,
            output_len: bytes_verifiable,
            bytes_compressed,
            bytes_encrypted,
            bytes_ecc,
            bytes_verifiable,
            compression_factor,
            amplification_factor: bytes_verifiable as f32 / preprocess.input_len.max(1) as f32,
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count: verifiable_slice_count / 8,
        },
    ))
}

fn stream_copy<R: Read, W: Write>(
    data: &mut R,
    len: u64,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let mut remaining = len;
    let mut buf = [0u8; 64 * 1024];
    let mut copied = 0u64;
    while remaining > 0 {
        let cap = buf.len().min(remaining as usize);
        let n = data
            .read(&mut buf[..cap])
            .map_err(CarbonadoError::StdIoError)?;
        if n == 0 {
            return Err(CarbonadoError::StdIoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream_copy: short read",
            )));
        }
        output
            .write_all(&buf[..n])
            .map_err(CarbonadoError::StdIoError)?;
        remaining -= n as u64;
        copied += n as u64;
    }
    Ok(copied)
}

/// Fused inboard encode: preprocess into a disk spool, then FEC/Bao directly to `output`.
///
/// Under `backend-lean` (R5 E1 / W1b residual): disk-spool plaintext → Lean body encode
/// (embedded-nonce via [`crate::backend::lean::encode`]) or headered encode when
/// `header_path_encrypt` (strip header, write body only). Peak RAM O(logical) at Lean
/// buffer boundary — not stream E2. Public **outboard** stream is W1b E2 (see
/// [`stream_encode_outboard`]). See docs/LIMITS.md.
///
/// Encrypted formats draw a CSPRNG nonce. For a fixed nonce (including all-zero), use
/// [`stream_encode_inboard_with_nonce`].
pub fn stream_encode_inboard<R: Read, W: Write>(
    master_key: &[u8],
    input: R,
    format: u8,
    output: &mut W,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
) -> Result<(Hash, EncodeInfo, PreprocessStats), CarbonadoError> {
    stream_encode_inboard_with_nonce(
        master_key,
        input,
        format,
        output,
        payload_nonce,
        header_path_encrypt,
        None,
    )
}

/// Like [`stream_encode_inboard`], with optional fixed AES-CTR nonce when encrypted.
///
/// When `fixed_nonce` is `Some(n)`, both backends use `n` literally (including all-zero).
/// When `None`, a CSPRNG nonce is drawn. **Test/determinism only** for fixed nonces —
/// nonce reuse under the same master is catastrophic (AGENTS §2.1.4). Prefer
/// [`stream_encode_inboard`] for production.
pub fn stream_encode_inboard_with_nonce<R: Read, W: Write>(
    master_key: &[u8],
    input: R,
    format: u8,
    output: &mut W,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
    fixed_nonce: Option<[u8; 16]>,
) -> Result<(Hash, EncodeInfo, PreprocessStats), CarbonadoError> {
    #[cfg(feature = "backend-lean")]
    {
        stream_encode_inboard_lean(
            master_key,
            input,
            format,
            output,
            payload_nonce,
            header_path_encrypt,
            fixed_nonce,
        )
    }
    #[cfg(feature = "backend-rust")]
    {
        let fmt = Format::from(format);
        let mut spool = SeekableSpool::new()?;
        let stats = stream_preprocess_spool(
            master_key,
            fmt,
            input,
            &mut spool,
            payload_nonce,
            header_path_encrypt,
            fixed_nonce,
        )?;
        let (hash, info) = stream_encode_inboard_body(&mut spool, stats, format, output)?;
        Ok((hash, info, stats))
    }
}

/// Lean E1 fused inboard: disk-spool plaintext → lean encode / encode_headered → write body.
///
/// Peak RAM O(logical) at Lean buffer boundary (W1b residual for inboard stream).
#[cfg(feature = "backend-lean")]
fn stream_encode_inboard_lean<R: Read, W: Write>(
    master_key: &[u8],
    input: R,
    format: u8,
    output: &mut W,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
    fixed_nonce: Option<[u8; 16]>,
) -> Result<(Hash, EncodeInfo, PreprocessStats), CarbonadoError> {
    use crate::filepack_manifest::MAX_SEGMENT_MAIN_LEN;

    let plaintext = SeekableSpool::spool_then_materialize(input, Some(MAX_SEGMENT_MAIN_LEN))?;

    let encrypted = format & 1 != 0;
    if encrypted {
        match fixed_nonce {
            Some(n) => *payload_nonce = n,
            None => {
                getrandom::getrandom(payload_nonce).map_err(|_| CarbonadoError::RandomnessError)?;
            }
        }
    } else {
        *payload_nonce = [0u8; 16];
    }

    let nonce_ref: Option<&[u8; 16]> = if encrypted { Some(payload_nonce) } else { None };

    let (body, hash, info) = if header_path_encrypt {
        // Header-path: Lean builds Header||body; return body only + nonce from header.
        let (archive, info) = crate::backend::lean::encode_headered(
            master_key, &plaintext, format, nonce_ref, None, None,
        )?;
        drop(plaintext);
        if archive.len() < crate::file::Header::LEN {
            return Err(CarbonadoError::InvalidHeaderLength);
        }
        let header = crate::file::Header::try_from(&archive[..crate::file::Header::LEN])?;
        *payload_nonce = header.payload_nonce;
        let body = archive[crate::file::Header::LEN..].to_vec();
        drop(archive);
        (body, header.hash, info)
    } else {
        let crate::structs::Encoded(body, hash, info) =
            crate::backend::lean::encode(master_key, &plaintext, format, nonce_ref)?;
        drop(plaintext);
        (body, hash, info)
    };

    output
        .write_all(&body)
        .map_err(CarbonadoError::StdIoError)?;

    let bare_len = if encrypted {
        info.bytes_encrypted as u64
    } else if info.bytes_compressed > 0 {
        info.bytes_compressed as u64
    } else {
        info.input_len as u64
    };
    let stats = PreprocessStats {
        bare_len,
        input_len: info.input_len as u64,
        bytes_compressed: info.bytes_compressed,
    };
    Ok((hash, info, stats))
}
