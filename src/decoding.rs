use std::io::Cursor;

use log::trace;

pub use crate::stream::compress::decompress_buffer as decompress;
pub use crate::stream::decode::{stream_decode_buffer, stream_decode_outboard_buffer};

use crate::{
    constants::{FEC_K, FEC_M, FEC_STRIPE_INBOARD_LEN, Format, SLICE_LEN},
    encoding,
    error::CarbonadoError,
    stream::fec::{concat_data_leaves, encode_stripes, reconstruct_stripe},
    stream::{classify_inboard_leaves, verify_slice_inboard_seekable, verify_slice_outboard},
    structs::EncodeInfo,
    utils::decode_bao_hash,
};
use log::warn;

pub fn verification_with_outboard(
    bare: &[u8],
    outboard: &[u8],
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verifying bare data with outboard sidecar (keyed 4KB bao-tree)");
    if bare.is_empty() && outboard.is_empty() {
        return Ok(vec![]);
    }
    crate::stream::bao::stream_verification_outboard_verify(
        bare,
        bare.len() as u64,
        outboard,
        hash,
        format,
    )?;
    Ok(bare.to_vec())
}

/// Outboard FEC recovery from bare main + `.par` parity (public API).
#[allow(dead_code)] // integration tests + direct callers; streaming path uses `stream::fec`
pub fn fec_with_parity(
    input: &[u8],
    parity: &[u8],
    padding: u32,
) -> Result<Vec<u8>, CarbonadoError> {
    trace!("forward error correcting from bare + parity sidecar (reed-solomon outboard)");
    crate::stream::fec::decode_outboard_stripes(input, parity, padding)
}

pub fn fec(input: &[u8], padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    trace!("forward error correcting (reed-solomon)");
    if input.is_empty() {
        return Ok(vec![]);
    }
    const STRIPE: usize = FEC_STRIPE_INBOARD_LEN as usize;
    const LEAF: usize = SLICE_LEN as usize;
    let (stripes, remainder) = input.as_chunks::<STRIPE>();
    if !remainder.is_empty() {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let mut logical = Vec::new();
    for stripe in stripes {
        let (leaves, leaf_rem) = stripe.as_chunks::<LEAF>();
        debug_assert!(leaf_rem.is_empty());
        let mut shards: Vec<Option<Vec<u8>>> = leaves.iter().map(|c| Some(c.to_vec())).collect();
        let rebuilt = reconstruct_stripe(&mut shards)?;
        for s in rebuilt.iter().take(FEC_K) {
            logical.extend_from_slice(s);
        }
    }
    if padding as usize > logical.len() {
        return Err(CarbonadoError::ScrubbedLengthMismatch(
            logical.len(),
            padding as usize,
        ));
    }
    logical.truncate(logical.len() - padding as usize);
    Ok(logical)
}

pub fn verification(input: &[u8], hash: &[u8], format: u8) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verifying (bao-tree 4KB keyed)");
    let content_len = crate::stream::bao::inboard_bao_content_len_prefix(input)?;
    let mut logical = crate::stream::fec::LogicalBufferWriteAt::new(content_len);
    crate::stream::bao::stream_verification_inboard_decode_with_len(
        Cursor::new(&input[8..]),
        content_len,
        hash,
        format,
        &mut logical,
    )?;
    logical.into_inner()
}

/// S5 scrub-entry oracle (integration-test hook).
#[doc(hidden)]
pub fn verify_inboard_keyed_oracle(
    input: &[u8],
    hash: &[u8],
    format: u8,
) -> Result<(), CarbonadoError> {
    crate::stream::bao::verify_inboard_keyed(input, hash, format)
}

pub fn decode(
    master_key: &[u8],
    hash: &[u8],
    input: &[u8],
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    stream_decode_buffer(master_key, hash, input, padding, format)
}

pub fn decode_outboard(
    master_key: &[u8],
    hash: &[u8],
    main: &[u8],
    verification_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    stream_decode_outboard_buffer(
        master_key,
        hash,
        main,
        verification_outboard,
        fec_parity,
        padding,
        format,
        None,
    )
}

/// Outboard decode with an optional RFC 8878 dictionary from the Adamantine bundle.
///
/// When the compressed frame names a Dictionary_ID, `dict` must be the matching trained
/// dictionary bytes. Missing dict is [`CarbonadoError::MissingZstdDictionary`].
#[allow(clippy::too_many_arguments)]
pub fn decode_outboard_with_dict(
    master_key: &[u8],
    hash: &[u8],
    main: &[u8],
    verification_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    padding: u32,
    format: u8,
    dict: Option<&[u8]>,
) -> Result<Vec<u8>, CarbonadoError> {
    crate::stream::decode::stream_decode_outboard_buffer_with_dict(
        master_key,
        hash,
        main,
        verification_outboard,
        fec_parity,
        padding,
        format,
        None,
        dict,
    )
}

pub fn extract_slice(
    encoded: &[u8],
    index: u32,
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    verify_slice(encoded, index, 1, hash, format)
}

pub fn verify_slice(
    input: &[u8],
    index: u32,
    count: u32,
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verify_slice seekable index={index} count={count} format=0x{format:02x}");
    verify_slice_inboard_seekable(input, index, count, hash, format)
}

/// Recover a damaged inboard Bao+FEC archive per 16 KiB stripe.
///
/// Bao-verify each 4 KiB leaf. Failed leaves are erasures in that stripe.
/// Reconstruct when the stripe has at least 4 good leaves; five bad leaves in
/// one stripe yields [`CarbonadoError::InvalidScrubbedHash`]. Re-Bao of the
/// reconstructed body must match `hash`.
///
/// Pristine archives return [`CarbonadoError::UnnecessaryScrub`].
pub fn scrub(
    input: &[u8],
    hash: &[u8],
    encode_info: &EncodeInfo,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);
    if !fmt.contains(Format::Verification) {
        return Err(CarbonadoError::ScrubRequiresVerification);
    }
    let hash = decode_bao_hash(hash)?;
    let padding = encode_info.padding_len;

    match crate::stream::bao::verify_inboard_keyed(input, hash.as_bytes(), format) {
        Ok(()) => Err(CarbonadoError::UnnecessaryScrub),
        Err(e) => {
            warn!("Data failed to verify with error: {e}. Scrubbing...");
            if !fmt.contains(Format::Fec) {
                return Err(CarbonadoError::InvalidScrubbedHash);
            }
            let leaves = classify_inboard_leaves(input, hash.as_bytes(), format)
                .map_err(|_| CarbonadoError::InvalidScrubbedHash)?;
            if leaves.is_empty() || !leaves.len().is_multiple_of(FEC_M) {
                return Err(CarbonadoError::InvalidScrubbedHash);
            }
            let mut logical = Vec::new();
            for stripe in leaves.chunks(FEC_M) {
                let good = stripe.iter().filter(|l| l.is_some()).count();
                if good < FEC_K {
                    return Err(CarbonadoError::InvalidScrubbedHash);
                }
                let mut shards: Vec<Option<Vec<u8>>> = stripe.to_vec();
                let rebuilt = reconstruct_stripe(&mut shards)
                    .map_err(|_| CarbonadoError::InvalidScrubbedHash)?;
                for s in rebuilt.iter().take(FEC_K) {
                    logical.extend_from_slice(s);
                }
            }
            if padding as usize > logical.len() {
                return Err(CarbonadoError::ScrubbedLengthMismatch(
                    logical.len(),
                    padding as usize,
                ));
            }
            logical.truncate(logical.len() - padding as usize);
            let (scrubbed, sp, _) = encoding::encode_inboard_buffer(&logical)?;
            if sp != padding {
                return Err(CarbonadoError::ScrubbedPaddingMismatch);
            }
            let (verif, got_h) = encoding::verification_inboard_buffer(&scrubbed, format)?;
            if got_h == hash && verif.len() == input.len() {
                Ok(verif)
            } else {
                Err(CarbonadoError::InvalidScrubbedHash)
            }
        }
    }
}

pub fn scrub_outboard(
    bare: &[u8],
    verification_outboard: Option<&[u8]>,
    fec_parity: Option<&[u8]>,
    encode_info: &EncodeInfo,
    format: u8,
    hash: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    let fmt = Format::from(format);
    if !fmt.contains(Format::Verification) {
        return Err(CarbonadoError::ScrubRequiresVerification);
    }

    let Some(ob) = verification_outboard else {
        return Err(CarbonadoError::MissingVerificationOutboard);
    };

    let good = crate::stream::bao::stream_verification_outboard_verify(
        bare,
        bare.len() as u64,
        ob,
        hash,
        format,
    )
    .is_ok();

    if good {
        return Err(CarbonadoError::UnnecessaryScrub);
    }

    if !fmt.contains(Format::Fec) {
        return Err(CarbonadoError::InvalidScrubbedHash);
    }
    let Some(par) = fec_parity else {
        return Err(CarbonadoError::MissingFecParity);
    };

    let padding = encode_info.padding_len;
    const LEAF: usize = SLICE_LEN as usize;
    const PARITY_STRIPE: usize = (FEC_M - FEC_K) * LEAF;
    let (parity_stripes, remainder) = par.as_chunks::<PARITY_STRIPE>();
    if !remainder.is_empty() {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let n_stripes = parity_stripes.len();
    let padded_total = n_stripes * FEC_K * LEAF;
    let pad = padding as usize;
    if pad > padded_total {
        return Err(CarbonadoError::ScrubbedLengthMismatch(padded_total, pad));
    }
    let logical_len = padded_total - pad;
    let data_len = bare.len() as u64;

    let mut logical = Vec::with_capacity(padded_total);
    for (stripe_idx, parity_stripe) in parity_stripes.iter().enumerate() {
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; FEC_M];
        for (symbol, shard) in shards.iter_mut().take(FEC_K).enumerate() {
            let leaf_index = (stripe_idx * FEC_K + symbol) as u32;
            match verify_slice_outboard(bare, ob, data_len, leaf_index, 1, hash, format) {
                Ok(bytes) if bytes.len() == LEAF => *shard = Some(bytes),
                _ => {}
            }
        }
        let (parity_leaves, leaf_rem) = parity_stripe.as_chunks::<LEAF>();
        debug_assert!(leaf_rem.is_empty());
        for (shard, chunk) in shards[FEC_K..].iter_mut().zip(parity_leaves) {
            *shard = Some(chunk.to_vec());
        }
        let good = shards.iter().filter(|s| s.is_some()).count();
        if good < FEC_K {
            return Err(CarbonadoError::InvalidScrubbedHash);
        }
        let rebuilt = reconstruct_stripe(&mut shards)?;
        for s in rebuilt.iter().take(FEC_K) {
            logical.extend_from_slice(s);
        }
    }
    logical.truncate(logical_len);

    if verification_with_outboard(&logical, ob, hash, format).is_ok() {
        Ok(logical)
    } else {
        // Reconstruct may have included padding zeros; re-encode data leaves and
        // compare against the Bao root of the original (unpadded) main.
        let (stripes, sp, _) = encode_stripes(&logical)?;
        if sp != padding {
            return Err(CarbonadoError::InvalidScrubbedHash);
        }
        let data = concat_data_leaves(&stripes);
        let recovered = if data.len() >= logical_len {
            data[..logical_len].to_vec()
        } else {
            data
        };
        if verification_with_outboard(&recovered, ob, hash, format).is_ok() {
            Ok(recovered)
        } else {
            Err(CarbonadoError::InvalidScrubbedHash)
        }
    }
}
