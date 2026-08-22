//! Writer that splits NFS output into `hif_%06d.nfs` files.
//!
//! Real Wii U VC titles split the NFS data into 250 MiB (`0xFA00000` = 262,144,000-byte)
//! files. The 0x200 EGGS header counts toward the first file. Verified against a retail base
//! title, whose first NFS file is exactly 262,144,000 bytes.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Maximum size of a single `hif_*.nfs` file (250 MiB).
pub const NFS_FILE_SIZE: u64 = 0xFA0_0000; // 262,144,000

/// Splits a byte stream across sequentially-numbered `hif_%06d.nfs` files.
pub struct SplitWriter {
    dir: PathBuf,
    index: u32,
    current: Option<BufWriter<File>>,
    written_in_current: u64,
    total_written: u64,
}

impl SplitWriter {
    /// Create a split writer targeting `dir` (which must already exist).
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let mut w = SplitWriter {
            dir: dir.into(),
            index: 0,
            current: None,
            written_in_current: 0,
            total_written: 0,
        };
        w.open_next()?;
        Ok(w)
    }

    fn file_path(dir: &Path, index: u32) -> PathBuf {
        dir.join(format!("hif_{index:06}.nfs"))
    }

    fn open_next(&mut self) -> Result<()> {
        let path = Self::file_path(&self.dir, self.index);
        let file = File::create(&path).map_err(|e| Error::io(&path, e))?;
        self.current = Some(BufWriter::new(file));
        self.written_in_current = 0;
        Ok(())
    }

    /// Write all of `data`, rolling over to a new file at the 250 MB boundary.
    pub fn write_all(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let remaining = NFS_FILE_SIZE - self.written_in_current;
            if remaining == 0 {
                let writer = self.current.as_mut().expect("writer open");
                writer.flush().map_err(|e| Error::io(&self.dir, e))?;
                self.index += 1;
                self.open_next()?;
                continue;
            }
            let take = remaining.min(data.len() as u64) as usize;
            let path = Self::file_path(&self.dir, self.index);
            let writer = self.current.as_mut().expect("writer open");
            writer.write_all(&data[..take]).map_err(|e| Error::io(&path, e))?;
            self.written_in_current += take as u64;
            self.total_written += take as u64;
            data = &data[take..];
        }
        Ok(())
    }

    /// Number of files produced so far (1-based count).
    pub fn file_count(&self) -> u32 { self.index + 1 }

    /// Total bytes written across all files (including the header).
    pub fn total_written(&self) -> u64 { self.total_written }

    /// Flush and finalize; returns the number of files written.
    pub fn finish(mut self) -> Result<u32> {
        if let Some(writer) = self.current.as_mut() {
            writer.flush().map_err(|e| Error::io(&self.dir, e))?;
        }
        Ok(self.file_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_at_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SplitWriter::new(dir.path()).unwrap();
        // Write just over one file's worth to force a rollover.
        let chunk = vec![0xABu8; 1_000_000];
        let mut total = 0u64;
        while total < NFS_FILE_SIZE + 1 {
            w.write_all(&chunk).unwrap();
            total += chunk.len() as u64;
        }
        let count = w.finish().unwrap();
        assert_eq!(count, 2, "should roll over into a second file");
        let f0 = dir.path().join("hif_000000.nfs");
        let f1 = dir.path().join("hif_000001.nfs");
        assert_eq!(std::fs::metadata(&f0).unwrap().len(), NFS_FILE_SIZE);
        assert!(std::fs::metadata(&f1).unwrap().len() > 0);
    }
}
