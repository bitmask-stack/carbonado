use log::trace;

use crate::{
    error::CarbonadoError,
    stream::encode::{stream_encode_buffer, stream_encode_outboard_buffer},
    structs::Encoded,
};

/// Encode data into Carbonado format (delegates to streaming pipeline).
pub fn encode(master_key: &[u8], input: &[u8], format: u8) -> Result<Encoded, CarbonadoError> {
    let (verifiable, hash, info) = stream_encode_buffer(master_key, input, format)?;
    Ok(Encoded(verifiable, hash, info))
}

/// Outboard variant for public and encrypted formats.
pub fn encode_outboard(
    master_key: &[u8],
    input: &[u8],
    format: u8,
) -> Result<crate::structs::OutboardEncoded, CarbonadoError> {
    trace!("encode_outboard format=0x{format:02x}");
    stream_encode_outboard_buffer(master_key, input, format, None)
}

// Scrub recovery re-exports
pub use crate::stream::bao::verification_inboard_buffer;
pub use crate::stream::fec::encode_inboard_buffer;
