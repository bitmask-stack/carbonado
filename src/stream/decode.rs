//! Carbonado streaming decode pipelines (inboard + outboard).

use std::io::{copy, Cursor, Read, Seek, SeekFrom, Write};

use crate::{
    constants::{Format, FEC_M},
    error::CarbonadoError,
    stream::{
        bao::{read_inboard_bao_content_len_prefix, stream_verification_inboard_decode_with_len},
        crypto_stream::{stream_decrypt_seek, stream_decrypt_with_nonce_seek},
        fec::{stream_decode_inboard, FecInboardWriteAt},
        spool::{SeekWriteAt, SeekableSpool},
    },
};

/// Primary inboard decode (buffer). Used by [`crate::decoding::decode`].
pub fn stream_decode_buffer(
    master_key: &[u8],
    hash: &[u8],
    input: &[u8],
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    let mut out = Vec::new();
    stream_decode_inboard_pipeline(
        master_key,
        hash,
        Cursor::new(input),
        padding,
        format,
        None,
        &mut out,
    )?;
    Ok(out)
}

/// Primary outboard decode (buffer). Used by [`crate::decoding::decode_outboard`].
#[allow(clippy::too_many_arguments)]
pub fn stream_decode_outboard_buffer(
    master_key: &[u8],
    hash: &[u8],
    main: &[u8],
    verification_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    padding: u32,
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
) -> Result<Vec<u8>, CarbonadoError> {
    let mut out = Vec::new();
    stream_decode_outboard(
        master_key,
        hash,
        Cursor::new(main),
        verification_outboard.map(Cursor::new),
        fec_parity.map(Cursor::new),
        padding,
        format,
        explicit_nonce,
        &mut out,
    )?;
    Ok(out)
}

/// Stream inboard decode from `input` to `output`.
///
/// **Nonce layout:** this API expects the low-level embedded-nonce ciphertext layout
/// `[nonce(16) | tag(64) | ct]` produced by [`crate::encoding::encode`] /
/// [`stream_encode_buffer`]. Header-path bodies (`[tag(64) | ct]` with nonce in
/// [`crate::structs::Header::payload_nonce`]) require [`crate::file::decode_stream`] or
/// [`stream_decrypt_header_path`] after Bao/FEC reverse — not this function alone.
///
/// Pass `encoded_body_len` when the reader may contain trailing bytes after the encoded
/// body (FEC c8, compressed c4). When `Some`, excess or truncated input is rejected.
pub fn stream_decode<R: Read, W: Write>(
    master_key: &[u8],
    hash: &[u8],
    input: R,
    padding: u32,
    format: u8,
    encoded_body_len: Option<u64>,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    stream_decode_inboard_pipeline(
        master_key,
        hash,
        input,
        padding,
        format,
        encoded_body_len,
        output,
    )
}

/// Core inboard decode: Bao verify → FEC → decrypt → decompress.
pub(crate) fn stream_decode_inboard_pipeline<R: Read, W: Write>(
    master_key: &[u8],
    hash: &[u8],
    input: R,
    padding: u32,
    format: u8,
    encoded_body_len: Option<u64>,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let fmt = Format::from(format);
    let mut post_preprocess = SeekableSpool::new()?;
    stream_decode_inboard_bao_fec_into(
        input,
        hash,
        padding,
        fmt,
        encoded_body_len,
        &mut post_preprocess,
    )?;
    post_preprocess.rewind()?;
    let body_len = post_preprocess.content_len()?;
    stream_decode_post_preprocess_seek(
        master_key,
        &mut post_preprocess,
        fmt,
        Some(body_len),
        output,
    )
}

/// Reject any byte beyond a bounded encoded-body read (same contract as streaming EtM trailing-ct check).
fn reject_trailing_body<R: Read>(input: &mut R, declared: u64) -> Result<(), CarbonadoError> {
    let mut extra = [0u8; 1];
    match input.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err(CarbonadoError::EncodedBodyExceedsDeclaredLength { declared }),
        Err(e) => Err(CarbonadoError::StdIoError(e)),
    }
}

/// Bao/FEC reverse into `sink` (no decrypt/decompress).
///
/// `sink` must be seekable so non-FEC verification can use [`SeekWriteAt`] (O(chunk) RAM).
pub(crate) fn stream_decode_inboard_bao_fec_into<R: Read, W: Write + Seek>(
    mut input: R,
    hash: &[u8],
    padding: u32,
    fmt: Format,
    encoded_body_len: Option<u64>,
    sink: &mut W,
) -> Result<(), CarbonadoError> {
    if fmt.contains(Format::Verification) {
        stream_decode_verified_inboard(&mut input, hash, fmt.bits(), padding, fmt, sink)?;
        if let Some(declared) = encoded_body_len {
            reject_trailing_body(&mut input, declared)?;
        }
        return Ok(());
    }

    if fmt.contains(Format::Fec) {
        stream_decode_inboard_fec_into(&mut input, padding, encoded_body_len, sink)
    } else {
        stream_copy_encoded_body(&mut input, encoded_body_len, sink)
    }
}

/// Incremental inboard FEC decode (c8) without `read_to_end` when `encoded_body_len` is known.
fn stream_decode_inboard_fec_into<R: Read, W: Write>(
    input: &mut R,
    padding: u32,
    encoded_body_len: Option<u64>,
    sink: &mut W,
) -> Result<(), CarbonadoError> {
    let body_len = match encoded_body_len {
        Some(len) => len,
        None => {
            let mut body = Vec::new();
            input
                .read_to_end(&mut body)
                .map_err(CarbonadoError::StdIoError)?;
            if body.is_empty() {
                return Ok(());
            }
            let len = body.len() as u64;
            if !len.is_multiple_of(FEC_M as u64) {
                return Err(CarbonadoError::UnevenFecChunks);
            }
            let chunk_len = (len / FEC_M as u64) as usize;
            return stream_decode_inboard(&mut Cursor::new(body), padding, chunk_len, sink)
                .map(|_| ());
        }
    };

    if body_len == 0 {
        return Ok(());
    }
    if !body_len.is_multiple_of(FEC_M as u64) {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let chunk_len = (body_len / FEC_M as u64) as usize;
    let mut limited = input.take(body_len);
    stream_decode_inboard(&mut limited, padding, chunk_len, sink)?;
    if limited.limit() > 0 {
        return Err(CarbonadoError::StdIoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated FEC body",
        )));
    }
    reject_trailing_body(input, body_len)
}

fn stream_copy_encoded_body<R: Read, W: Write>(
    input: &mut R,
    encoded_body_len: Option<u64>,
    sink: &mut W,
) -> Result<(), CarbonadoError> {
    match encoded_body_len {
        Some(len) => {
            let mut limited = input.take(len);
            copy(&mut limited, sink).map_err(CarbonadoError::StdIoError)?;
            if limited.limit() > 0 {
                return Err(CarbonadoError::StdIoError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated encoded body",
                )));
            }
            reject_trailing_body(input, len)
        }
        None => copy(input, sink)
            .map_err(CarbonadoError::StdIoError)
            .map(|_| ()),
    }
}

/// Verification inboard reverse (c6/c12/c14/c15) into `sink`.
///
/// **Memory tier:**
/// - Non-FEC (c6): Bao → [`SeekWriteAt`] on `sink` — **O(chunk)** RAM (disk-backed).
/// - FEC (c12/c14/c15): [`FecInboardWriteAt`] retains O(FEC body) shard buffers (one
///   segment-wide stripe under current geometry), then [`FecInboardWriteAt::finish_into`]
///   streams logical bytes without a second full-logical `Vec`.
///
/// See `doc/STREAMING_PARALLELISM.md`.
fn stream_decode_verified_inboard<R: Read, W: Write + Seek>(
    input: &mut R,
    hash: &[u8],
    format: u8,
    padding: u32,
    fmt: Format,
    sink: &mut W,
) -> Result<(), CarbonadoError> {
    let content_len = read_inboard_bao_content_len_prefix(input)?;

    if fmt.contains(Format::Fec) {
        let mut fec_sink = FecInboardWriteAt::new(content_len, padding)?;
        stream_verification_inboard_decode_with_len(
            input,
            content_len,
            hash,
            format,
            &mut fec_sink,
        )?;
        fec_sink.finish_into(sink)?;
    } else {
        let mut logical = SeekWriteAt::new(sink, content_len);
        stream_verification_inboard_decode_with_len(
            input,
            content_len,
            hash,
            format,
            &mut logical,
        )?;
        logical.finish()?;
    }
    Ok(())
}

fn stream_decode_post_preprocess_seek<R: Read + Seek, W: Write>(
    master_key: &[u8],
    mut input: R,
    fmt: Format,
    body_len: Option<u64>,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    if fmt.contains(Format::Encryption) {
        // Low-level embedded-nonce layout: `[nonce(16) | tag(64) | ct]`.
        let ct_len = body_len.map(|n| n.saturating_sub(80));
        if fmt.contains(Format::Compression) {
            let mut decrypted = SeekableSpool::new()?;
            stream_decrypt_seek(master_key, input, &mut decrypted, ct_len)?;
            decrypted.rewind()?;
            crate::stream::compress::stream_decompress(decrypted, output)
        } else {
            stream_decrypt_seek(master_key, input, output, ct_len)
        }
    } else if fmt.contains(Format::Compression) {
        crate::stream::compress::stream_decompress(input, output)
    } else if let Some(len) = body_len {
        let mut limited = input.take(len);
        copy(&mut limited, output).map_err(CarbonadoError::StdIoError)
    } else {
        copy(&mut input, output).map_err(CarbonadoError::StdIoError)
    }
}

/// Stream outboard decode (incremental Bao/FEC/decrypt chain).
#[allow(clippy::too_many_arguments)]
pub fn stream_decode_outboard<M: Read, O: Read, P: Read, W: Write>(
    master_key: &[u8],
    hash: &[u8],
    mut main: M,
    verification_outboard: Option<O>,
    fec_parity: Option<P>,
    padding: u32,
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let fmt = Format::from(format);
    let mut after_bao_spool = SeekableSpool::new()?;

    if fmt.contains(Format::Verification) {
        let mut ob_reader =
            verification_outboard.ok_or(CarbonadoError::MissingVerificationOutboard)?;
        let mut ob_spool = SeekableSpool::new()?;
        copy(&mut ob_reader, &mut ob_spool).map_err(CarbonadoError::StdIoError)?;
        ob_spool.rewind()?;
        let ob_len = ob_spool.content_len()?;
        let mut main_spool = SeekableSpool::new()?;
        copy(&mut main, &mut main_spool).map_err(CarbonadoError::StdIoError)?;
        main_spool.rewind()?;
        let main_len = main_spool.content_len()?;
        let main_view = crate::stream::bao::SeekReadAt::new(&mut main_spool, main_len);
        let ob_view = crate::stream::bao::SeekReadAt::new(&mut ob_spool, ob_len);
        crate::stream::bao::stream_verification_outboard_verify(
            main_view, main_len, ob_view, hash, format,
        )?;
        main_spool.rewind()?;
        copy(&mut main_spool, &mut after_bao_spool).map_err(CarbonadoError::StdIoError)?;
    } else {
        copy(&mut main, &mut after_bao_spool).map_err(CarbonadoError::StdIoError)?;
    }
    after_bao_spool.rewind()?;

    let mut after_fec_spool = SeekableSpool::new()?;
    if fmt.contains(Format::Fec) {
        let mut par_reader = fec_parity.ok_or(CarbonadoError::MissingFecParity)?;
        let mut par_spool = SeekableSpool::new()?;
        copy(&mut par_reader, &mut par_spool).map_err(CarbonadoError::StdIoError)?;
        par_spool.rewind()?;
        let main_len = after_bao_spool.content_len()? as usize;
        crate::stream::fec::stream_decode_outboard(
            &mut after_bao_spool,
            &mut par_spool,
            padding,
            main_len,
            &mut after_fec_spool,
        )?;
    } else {
        copy(&mut after_bao_spool, &mut after_fec_spool).map_err(CarbonadoError::StdIoError)?;
    }
    after_fec_spool.rewind()?;

    if fmt.contains(Format::Encryption) {
        let fec_body_len = after_fec_spool.content_len()?;
        if let Some(nonce) = explicit_nonce {
            let ct_len = fec_body_len.saturating_sub(64);
            if fmt.contains(Format::Compression) {
                let mut decrypted = SeekableSpool::new()?;
                stream_decrypt_with_nonce_seek(
                    master_key,
                    nonce,
                    &mut after_fec_spool,
                    &mut decrypted,
                    Some(ct_len),
                )?;
                decrypted.rewind()?;
                crate::stream::compress::stream_decompress(decrypted, output)
            } else {
                stream_decrypt_with_nonce_seek(
                    master_key,
                    nonce,
                    &mut after_fec_spool,
                    output,
                    Some(ct_len),
                )
            }
        } else {
            let ct_len = fec_body_len.saturating_sub(80);
            if fmt.contains(Format::Compression) {
                let mut decrypted = SeekableSpool::new()?;
                stream_decrypt_seek(
                    master_key,
                    &mut after_fec_spool,
                    &mut decrypted,
                    Some(ct_len),
                )?;
                decrypted.rewind()?;
                crate::stream::compress::stream_decompress(decrypted, output)
            } else {
                stream_decrypt_seek(master_key, &mut after_fec_spool, output, Some(ct_len))
            }
        }
    } else if fmt.contains(Format::Compression) {
        crate::stream::compress::stream_decompress(after_fec_spool, output)
    } else {
        copy(&mut after_fec_spool, output).map_err(CarbonadoError::StdIoError)
    }
}

/// Header path decrypt with explicit nonce (`[tag(64) | ct]`).
pub fn stream_decrypt_header_path<R: Read + Seek, W: Write>(
    master_key: &[u8],
    nonce: [u8; 16],
    mut input: R,
    format: u8,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let fmt = Format::from(format);
    let ct_len = input
        .seek(SeekFrom::End(0))
        .map_err(CarbonadoError::StdIoError)?
        .saturating_sub(64);
    input
        .seek(SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;

    if fmt.contains(Format::Compression) {
        let mut decrypted = SeekableSpool::new()?;
        stream_decrypt_with_nonce_seek(
            master_key,
            nonce,
            &mut input,
            &mut decrypted,
            Some(ct_len),
        )?;
        decrypted.rewind()?;
        crate::stream::compress::stream_decompress(decrypted, output)
    } else {
        stream_decrypt_with_nonce_seek(master_key, nonce, input, output, Some(ct_len))
    }
}
