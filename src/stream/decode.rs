//! Carbonado streaming decode pipelines (inboard + outboard).

use std::io::{Cursor, Read, Write};

use crate::{
    constants::Format,
    decoding,
    error::CarbonadoError,
    stream::{
        compress::decompress_buffer,
        crypto_stream::{stream_decrypt, stream_decrypt_with_nonce},
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
    let fmt = Format::from(format);
    let verified = if fmt.contains(Format::Bao) {
        decoding::bao(input, hash, format)?
    } else {
        input.to_vec()
    };
    let decoded = if fmt.contains(Format::Zfec) {
        decoding::zfec(&verified, padding)?
    } else {
        verified
    };
    let decrypted = if fmt.contains(Format::Encrypted) {
        let mut out = Vec::new();
        stream_decrypt(master_key, Cursor::new(&decoded), &mut out)?;
        out
    } else {
        decoded
    };
    if fmt.contains(Format::Snappy) {
        decompress_buffer(&decrypted)
    } else {
        Ok(decrypted)
    }
}

/// Primary outboard decode (buffer). Used by [`crate::decoding::decode_outboard`].
///
/// `explicit_nonce`: header-path decrypt (`[tag | ct]`); `None` uses embedded nonce (low-level).
#[allow(clippy::too_many_arguments)]
pub fn stream_decode_outboard_buffer(
    master_key: &[u8],
    hash: &[u8],
    main: &[u8],
    bao_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    padding: u32,
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);
    let after_bao = if fmt.contains(Format::Bao) {
        let ob = bao_outboard.ok_or(CarbonadoError::MissingBaoOutboard)?;
        decoding::bao_with_outboard(main, ob, hash, format)?
    } else {
        main.to_vec()
    };
    let after_fec = if fmt.contains(Format::Zfec) {
        let par = fec_parity.ok_or(CarbonadoError::MissingFecParity)?;
        decoding::zfec_with_parity(&after_bao, par, padding)?
    } else {
        after_bao
    };
    let decrypted = if fmt.contains(Format::Encrypted) {
        let mut out = Vec::new();
        if let Some(nonce) = explicit_nonce {
            stream_decrypt_with_nonce(master_key, nonce, Cursor::new(&after_fec), &mut out)?;
        } else {
            stream_decrypt(master_key, Cursor::new(&after_fec), &mut out)?;
        }
        out
    } else {
        after_fec
    };
    if fmt.contains(Format::Snappy) {
        decompress_buffer(&decrypted)
    } else {
        Ok(decrypted)
    }
}

/// Stream inboard decode from `input` to `output`.
///
/// Note: the body is fully buffered before Bao/FEC reverse (known P2 limitation).
pub fn stream_decode<R: Read, W: Write>(
    master_key: &[u8],
    hash: &[u8],
    input: R,
    padding: u32,
    format: u8,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let mut body = Vec::new();
    let mut reader = input;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    let recovered = stream_decode_buffer(master_key, hash, &body, padding, format)?;
    output
        .write_all(&recovered)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(recovered.len() as u64)
}

/// Stream outboard decode.
///
/// `explicit_nonce`: required for encrypted header-path outboard (`[tag|ct]` main).
#[allow(clippy::too_many_arguments)]
pub fn stream_decode_outboard<M: Read, O: Read, P: Read, W: Write>(
    master_key: &[u8],
    hash: &[u8],
    mut main: M,
    bao_outboard: Option<O>,
    fec_parity: Option<P>,
    padding: u32,
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let mut main_bytes = Vec::new();
    main.read_to_end(&mut main_bytes)
        .map_err(CarbonadoError::StdIoError)?;
    let bao_ob = if let Some(mut ob) = bao_outboard {
        let mut v = Vec::new();
        ob.read_to_end(&mut v).map_err(CarbonadoError::StdIoError)?;
        Some(v)
    } else {
        None
    };
    let fec_p = if let Some(mut par) = fec_parity {
        let mut v = Vec::new();
        par.read_to_end(&mut v)
            .map_err(CarbonadoError::StdIoError)?;
        Some(v)
    } else {
        None
    };
    let recovered = stream_decode_outboard_buffer(
        master_key,
        hash,
        &main_bytes,
        bao_ob.as_deref(),
        fec_p.as_deref(),
        padding,
        format,
        explicit_nonce,
    )?;
    output
        .write_all(&recovered)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(recovered.len() as u64)
}

/// Header path decrypt with explicit nonce.
pub fn stream_decrypt_header_path<R: Read, W: Write>(
    master_key: &[u8],
    nonce: [u8; 16],
    input: R,
    format: u8,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let mut body = Vec::new();
    let mut reader = input;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    let mut decrypted = Vec::new();
    stream_decrypt_with_nonce(master_key, nonce, Cursor::new(&body), &mut decrypted)?;
    let fmt = Format::from(format);
    if fmt.contains(Format::Snappy) {
        stream_decompress_to(decrypted, output)
    } else {
        output
            .write_all(&decrypted)
            .map_err(CarbonadoError::StdIoError)?;
        Ok(decrypted.len() as u64)
    }
}

fn stream_decompress_to<W: Write>(input: Vec<u8>, output: &mut W) -> Result<u64, CarbonadoError> {
    crate::stream::compress::stream_decompress(Cursor::new(input), output)
}
