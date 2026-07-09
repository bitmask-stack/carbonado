//! Pipeline I/O abstractions: sync (canonical) and async (adapter layer).
//!
//! Sync [`PipelineSource`] / [`PipelineSink`] match the Phase 1 stage graph (`Read` / `Write`).
//! When the `async` feature is enabled, [`AsyncPipelineSource`] / [`AsyncPipelineSink`] wrap
//! `futures_lite` async I/O traits and bridge into the same sync pipeline via spool adapters.

use std::io::{Read, Seek, Write};

/// Canonical sync byte source for the streaming pipeline.
pub trait PipelineSource: Read {}
impl<T: Read> PipelineSource for T {}

/// Canonical sync byte sink for the streaming pipeline.
pub trait PipelineSink: Write {}
impl<T: Write> PipelineSink for T {}

/// Sync source that supports seek (post-preprocess decrypt / decompress passes).
pub trait PipelineSeekSource: PipelineSource + Seek {}
impl<T: Read + Seek> PipelineSeekSource for T {}

#[cfg(feature = "async")]
pub use async_io::*;

#[cfg(feature = "async")]
mod async_io {
    use std::io::{ErrorKind, Read, Write};

    use futures_lite::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use crate::{constants::SLICE_LEN, error::CarbonadoError};

    /// Async adapter source (`AsyncRead`); not required for default sync builds.
    pub trait AsyncPipelineSource: AsyncRead {}
    impl<T: AsyncRead + ?Sized> AsyncPipelineSource for T {}

    /// Async adapter sink (`AsyncWrite`); not required for default sync builds.
    pub trait AsyncPipelineSink: AsyncWrite {}
    impl<T: AsyncWrite + ?Sized> AsyncPipelineSink for T {}

    /// Truncation message context for bounded async staging (parity with sync `decode.rs`).
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum BoundedCopyTruncation {
        /// Non-FEC encoded body (`stream_copy_encoded_body`).
        EncodedBody,
        /// FEC-encoded body (`stream_decode_inboard_fec_into`).
        FecBody,
    }

    impl BoundedCopyTruncation {
        pub(crate) fn message(self) -> &'static str {
            match self {
                Self::EncodedBody => "truncated encoded body",
                Self::FecBody => "truncated FEC body",
            }
        }
    }

    const COPY_BUF: usize = SLICE_LEN as usize;

    /// Copy up to `limit` bytes from `reader` into sync `writer`.
    ///
    /// When `limit` is `Some(n)`, exactly `n` bytes must be available or `UnexpectedEof` is returned
    /// with a message matching the sync bounded-read path (`truncation` selects FEC vs encoded body).
    pub async fn async_copy_bounded<R, W>(
        reader: &mut R,
        writer: &mut W,
        limit: Option<u64>,
        truncation: BoundedCopyTruncation,
    ) -> Result<u64, CarbonadoError>
    where
        R: AsyncRead + Unpin,
        W: Write,
    {
        let mut buf = [0u8; COPY_BUF];
        let mut total = 0u64;
        let max = limit.unwrap_or(u64::MAX);

        while total < max {
            let cap = buf.len().min((max - total) as usize);
            let n = reader
                .read(&mut buf[..cap])
                .await
                .map_err(CarbonadoError::StdIoError)?;
            if n == 0 {
                if limit.is_some() {
                    return Err(CarbonadoError::StdIoError(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        truncation.message(),
                    )));
                }
                break;
            }
            writer
                .write_all(&buf[..n])
                .map_err(CarbonadoError::StdIoError)?;
            total += n as u64;
        }
        Ok(total)
    }

    /// Copy all remaining bytes from sync `reader` into async `writer`.
    pub async fn async_copy_all<R, W>(reader: &mut R, writer: &mut W) -> Result<u64, CarbonadoError>
    where
        R: Read,
        W: AsyncWrite + Unpin,
    {
        let mut buf = [0u8; COPY_BUF];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
            if n == 0 {
                break;
            }
            writer
                .write_all(&buf[..n])
                .await
                .map_err(CarbonadoError::StdIoError)?;
            total += n as u64;
        }
        writer.flush().await.map_err(CarbonadoError::StdIoError)?;
        Ok(total)
    }

    /// Reject any byte beyond a bounded encoded-body read (parity with sync `reject_trailing_body`).
    pub async fn async_reject_trailing<R>(
        reader: &mut R,
        declared: u64,
    ) -> Result<(), CarbonadoError>
    where
        R: AsyncRead + Unpin,
    {
        let mut extra = [0u8; 1];
        match reader.read(&mut extra).await {
            Ok(0) => Ok(()),
            Ok(_) => Err(CarbonadoError::EncodedBodyExceedsDeclaredLength { declared }),
            Err(e) => Err(CarbonadoError::StdIoError(e)),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bounded_copy_truncation_messages_match_sync_decode() {
            assert_eq!(
                BoundedCopyTruncation::EncodedBody.message(),
                "truncated encoded body"
            );
            assert_eq!(
                BoundedCopyTruncation::FecBody.message(),
                "truncated FEC body"
            );
        }
    }
}
