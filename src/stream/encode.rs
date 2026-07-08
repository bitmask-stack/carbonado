//! Carbonado streaming encode pipelines (inboard + outboard).

use std::io::{Read, Seek, Write};

use bao::Hash;

use crate::{
    constants::{Format, FEC_M, SLICE_LEN},
    error::CarbonadoError,
    stream::{
        bao::{bao_inboard_buffer, bao_outboard_buffer, stream_bao_outboard},
        compress::{compress_buffer, stream_compress},
        crypto_stream::{
            stream_encrypt, stream_encrypt_with_nonce, stream_encrypt_with_nonce_seek,
        },
        fec::{encode_inboard_buffer, encode_outboard_parity_buffer, FecInboardEncoder},
    },
    structs::{EncodeInfo, OutboardEncoded},
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
/// random nonce written to `payload_nonce`. When false (CLI/low-level), nonce is embedded
/// in the sink as `[nonce|tag|ct]`.
pub fn stream_preprocess<R: Read, W: Read + Write + Seek>(
    master_key: &[u8],
    format: Format,
    mut input: R,
    body_sink: &mut W,
    payload_nonce: &mut [u8; 16],
    header_path_encrypt: bool,
) -> Result<PreprocessStats, CarbonadoError> {
    body_sink
        .seek(std::io::SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;
    let mut input_len = 0u64;
    if format.contains(Format::Snappy) {
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
    let bytes_compressed = if format.contains(Format::Snappy) {
        reader_len(body_sink)? as u32
    } else {
        0
    };

    let bare_len = if format.contains(Format::Encrypted) {
        let comp_len = reader_len(body_sink)?;
        let comp = read_seek_to_vec(body_sink, comp_len)?;
        body_sink
            .seek(std::io::SeekFrom::Start(0))
            .map_err(CarbonadoError::StdIoError)?;
        if header_path_encrypt {
            getrandom::getrandom(payload_nonce).map_err(|_| CarbonadoError::RandomnessError)?;
            stream_encrypt_with_nonce_seek(
                master_key,
                *payload_nonce,
                std::io::Cursor::new(&comp),
                body_sink,
            )?;
        } else {
            let mut encrypted = Vec::new();
            let (_len, nonce) =
                stream_encrypt(master_key, std::io::Cursor::new(&comp), &mut encrypted)?;
            *payload_nonce = nonce;
            rewrite_sink(body_sink, &encrypted)?;
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

fn rewrite_sink<W: Write + Seek>(sink: &mut W, data: &[u8]) -> Result<(), CarbonadoError> {
    sink.seek(std::io::SeekFrom::Start(0))
        .map_err(CarbonadoError::StdIoError)?;
    sink.write_all(data).map_err(CarbonadoError::StdIoError)?;
    sink.rewind().map_err(CarbonadoError::StdIoError)?;
    Ok(())
}

fn reader_len<R: Read + Seek>(r: &mut R) -> Result<u64, CarbonadoError> {
    r.seek(std::io::SeekFrom::End(0))
        .map_err(CarbonadoError::StdIoError)
}

/// Primary inboard encode (buffer). Used by [`crate::encoding::encode`].
pub fn stream_encode_buffer(
    master_key: &[u8],
    input: &[u8],
    format: u8,
) -> Result<(Vec<u8>, Hash, EncodeInfo), CarbonadoError> {
    let fmt = Format::from(format);
    let input_len = input.len() as u32;
    let mut body = input.to_vec();
    let mut bytes_compressed = 0u32;
    let mut bytes_encrypted = 0u32;

    if fmt.contains(Format::Snappy) {
        body = compress_buffer(input)?;
        bytes_compressed = body.len() as u32;
    }
    if fmt.contains(Format::Encrypted) {
        body = {
            let mut out = Vec::new();
            let (_len, _nonce) = stream_encrypt(master_key, &body[..], &mut out)?;
            out
        };
        bytes_encrypted = body.len() as u32;
    }

    let (after_fec, padding_len, chunk_len, bytes_ecc) = if fmt.contains(Format::Zfec) {
        let (encoded, pl, cl) = encode_inboard_buffer(&body)?;
        let be = encoded.len() as u32;
        (encoded, pl, cl, be)
    } else {
        (body, 0, 0, 0)
    };

    let verifiable_slice_count = if fmt.contains(Format::Zfec) {
        bytes_ecc / SLICE_LEN
    } else {
        0
    };
    if fmt.contains(Format::Zfec) && !verifiable_slice_count.is_multiple_of(8) {
        return Err(CarbonadoError::InvalidVerifiableSliceCount(
            verifiable_slice_count,
        ));
    }

    let (verifiable, hash) = if fmt.contains(Format::Bao) {
        bao_inboard_buffer(&after_fec, format)?
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
pub fn stream_encode_outboard_buffer(
    master_key: &[u8],
    input: &[u8],
    format: u8,
    explicit_nonce: Option<[u8; 16]>,
) -> Result<OutboardEncoded, CarbonadoError> {
    let fmt = Format::from(format);
    let input_len = input.len() as u32;
    let mut bytes_compressed = 0u32;

    let compressed = if fmt.contains(Format::Snappy) {
        let c = compress_buffer(input)?;
        bytes_compressed = c.len() as u32;
        c
    } else {
        input.to_vec()
    };

    let post_comp_or_enc;
    let bytes_encrypted;
    if fmt.contains(Format::Encrypted) {
        post_comp_or_enc = {
            let mut out = Vec::new();
            if let Some(nonce) = explicit_nonce {
                stream_encrypt_with_nonce(master_key, nonce, &compressed[..], &mut out)?;
            } else {
                stream_encrypt(master_key, &compressed[..], &mut out)?;
            }
            out
        };
        bytes_encrypted = post_comp_or_enc.len() as u32;
    } else {
        post_comp_or_enc = compressed;
        bytes_encrypted = 0;
    }

    let (post_zfec_or_bare, padding_len, chunk_len, bytes_ecc, fec_parity, vslice, cslice) =
        if fmt.contains(Format::Zfec) {
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

    let (main_for_return, bao_out, hash, bytes_verifiable) = if fmt.contains(Format::Bao) {
        let bv = post_zfec_or_bare.len() as u32;
        let (ob, h) = bao_outboard_buffer(&post_zfec_or_bare, format)?;
        (post_zfec_or_bare, Some(ob), h, bv)
    } else {
        let bv = post_zfec_or_bare.len() as u32;
        (post_zfec_or_bare, None, Hash::from([0; 32]), bv)
    };

    Ok(OutboardEncoded {
        main: main_for_return,
        bao_outboard: bao_out,
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
#[allow(clippy::too_many_arguments)]
pub fn stream_encode_outboard<M: Read + Write + Seek, O: Write, P: Write>(
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
    let stats = stream_preprocess(
        master_key,
        fmt,
        input,
        main_out,
        payload_nonce,
        header_path_encrypt,
    )?;
    let bare_len = stats.bare_len;
    main_out.rewind().map_err(CarbonadoError::StdIoError)?;

    let (padding_len, chunk_len, bytes_ecc, _fec_parity_len) = if fmt.contains(Format::Zfec) {
        if bare_len == 0 {
            (0, 0, 0, 0)
        } else {
            let mut enc = FecInboardEncoder::new(bare_len as usize)?;
            let stripe = if let Some(s) = enc.feed(&mut *main_out)? {
                s
            } else {
                enc.finish()?.ok_or(CarbonadoError::UnevenZfecChunks)?
            };
            let pl = enc.padding_len();
            let cl = enc.chunk_len();
            let mut par_len = 0u64;
            if let Some(par) = parity_out.as_mut() {
                par_len = crate::stream::fec::write_outboard_parity(&stripe, par)?;
            }
            main_out.rewind().map_err(CarbonadoError::StdIoError)?;
            (pl, cl, par_len as u32, par_len as u32)
        }
    } else {
        (0, 0, 0, 0)
    };

    let hash = if fmt.contains(Format::Bao) {
        let ob = bao_out.as_mut().ok_or(CarbonadoError::MissingBaoOutboard)?;
        stream_bao_outboard(&mut *main_out, bare_len, format, ob)?
    } else {
        Hash::from([0u8; 32])
    };

    let verifiable_slice_count = if fmt.contains(Format::Zfec) {
        ((FEC_M as u32) * chunk_len) / SLICE_LEN
    } else {
        0
    };
    if fmt.contains(Format::Zfec) && !verifiable_slice_count.is_multiple_of(8) {
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
            bytes_encrypted: if fmt.contains(Format::Encrypted) {
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
pub fn stream_encode_inboard_body<D: Read + Seek, W: Write>(
    mut data: D,
    preprocess: PreprocessStats,
    format: u8,
    output: &mut W,
) -> Result<(Hash, EncodeInfo), CarbonadoError> {
    let fmt = Format::from(format);
    let content_len = preprocess.bare_len;
    let tmp = read_seek_to_vec(&mut data, content_len)?;
    let (after_fec, padding_len, chunk_len, bytes_ecc) = if fmt.contains(Format::Zfec) {
        let (enc, pl, cl) = encode_inboard_buffer(&tmp)?;
        let be = enc.len() as u32;
        (enc, pl, cl, be)
    } else {
        (tmp, 0, 0, 0)
    };

    let verifiable_slice_count = if fmt.contains(Format::Zfec) {
        bytes_ecc / SLICE_LEN
    } else {
        0
    };
    if fmt.contains(Format::Zfec) && !verifiable_slice_count.is_multiple_of(8) {
        return Err(CarbonadoError::InvalidVerifiableSliceCount(
            verifiable_slice_count,
        ));
    }

    let (hash, bytes_verifiable) = if fmt.contains(Format::Bao) {
        let (h, written) = crate::stream::bao::stream_bao_inboard(
            &after_fec[..],
            after_fec.len() as u64,
            format,
            output,
        )?;
        (h, written as u32)
    } else {
        output
            .write_all(&after_fec)
            .map_err(CarbonadoError::StdIoError)?;
        (Hash::from([0; 32]), after_fec.len() as u32)
    };

    let bytes_compressed = if fmt.contains(Format::Snappy) {
        preprocess.bytes_compressed
    } else {
        0
    };
    let bytes_encrypted = if fmt.contains(Format::Encrypted) {
        preprocess.bare_len as u32
    } else {
        0
    };
    let compression_factor = if fmt.contains(Format::Snappy) {
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
            amplification_factor: bytes_verifiable as f32 / preprocess.bare_len.max(1) as f32,
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count: verifiable_slice_count / 8,
        },
    ))
}

fn read_seek_to_vec<R: Read + Seek>(data: &mut R, len: u64) -> Result<Vec<u8>, CarbonadoError> {
    data.rewind().map_err(CarbonadoError::StdIoError)?;
    let mut out = vec![0u8; len as usize];
    data.read_exact(&mut out)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(out)
}
