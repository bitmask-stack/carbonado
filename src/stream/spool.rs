//! Disk-backed seekable buffer for streaming crypto passes (O(chunk) RAM).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::CarbonadoError;
use crate::stream::fec::write_past_content_len_error;

static SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Temp-file spool: write during MAC pass, rewind for decrypt pass.
pub struct SeekableSpool {
    file: File,
    path: PathBuf,
}

impl SeekableSpool {
    pub fn new() -> Result<Self, CarbonadoError> {
        let mut path = std::env::temp_dir();
        let name = format!(
            "carbonado-spool-{}-{}.tmp",
            std::process::id(),
            rand_spool_suffix()
        );
        path.push(name);
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path).map_err(CarbonadoError::StdIoError)?;
        Ok(Self { file, path })
    }

    pub fn rewind(&mut self) -> Result<(), CarbonadoError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(CarbonadoError::StdIoError)?;
        Ok(())
    }

    /// Current file size (always from the underlying file, not a write counter).
    pub fn content_len(&mut self) -> Result<u64, CarbonadoError> {
        let pos = self
            .file
            .stream_position()
            .map_err(CarbonadoError::StdIoError)?;
        let end = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(CarbonadoError::StdIoError)?;
        self.file
            .seek(SeekFrom::Start(pos))
            .map_err(CarbonadoError::StdIoError)?;
        Ok(end)
    }

    /// Truncate and replace contents from `src` (used after encrypt preprocess).
    pub fn overwrite_from(&mut self, src: &mut Self) -> Result<(), CarbonadoError> {
        src.rewind()?;
        self.file.set_len(0).map_err(CarbonadoError::StdIoError)?;
        self.rewind()?;
        io::copy(src, self).map_err(CarbonadoError::StdIoError)?;
        self.rewind()?;
        src.rewind()?;
        Ok(())
    }
}

impl Read for SeekableSpool {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for SeekableSpool {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for SeekableSpool {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

impl Drop for SeekableSpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn rand_spool_suffix() -> u64 {
    let mut buf = [0u8; 8];
    if getrandom::getrandom(&mut buf).is_ok() {
        return u64::from_le_bytes(buf);
    }
    SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// [`positioned_io::WriteAt`] over a seekable sink — O(chunk) RAM (no full logical `Vec`).
///
/// Used for non-FEC keyed Bao inboard decode so verification formats without FEC (c4/c6)
/// no longer retain O(logical) buffer memory. Completeness uses the same max-end-offset
/// contract as the former `LogicalBufferWriteAt` (bao-tree full-range decode fills
/// `[0, content_len)`).
pub(crate) struct SeekWriteAt<'a, W: Write + Seek> {
    inner: &'a mut W,
    content_len: u64,
    filled: u64,
}

impl<'a, W: Write + Seek> SeekWriteAt<'a, W> {
    pub fn new(inner: &'a mut W, content_len: u64) -> Self {
        Self {
            inner,
            content_len,
            filled: 0,
        }
    }

    pub fn finish(self) -> Result<(), CarbonadoError> {
        if self.filled != self.content_len {
            return Err(CarbonadoError::StdIoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "bao decode incomplete: got {} of {} bytes",
                    self.filled, self.content_len
                ),
            )));
        }
        Ok(())
    }
}

impl<W: Write + Seek> positioned_io::WriteAt for SeekWriteAt<'_, W> {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if offset >= self.content_len || offset.saturating_add(data.len() as u64) > self.content_len
        {
            return Err(write_past_content_len_error());
        }
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.write_all(data)?;
        self.filled = self.filled.max(offset + data.len() as u64);
        Ok(data.len())
    }

    fn write_all_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.write_at(offset, data)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
