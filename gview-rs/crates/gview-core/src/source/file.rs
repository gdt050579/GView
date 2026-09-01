//! File-backed [`DataSource`] (C++ `AppCUI::OS::File` parity).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use super::DataSource;

/// A read-only file on disk.
///
/// The size is captured once at open time, matching the C++ behavior
/// where `DataCache::Init` snapshots `fileObj->GetSize()`.
pub struct FileSource {
    file: Mutex<File>,
    size: u64,
}

impl FileSource {
    /// Opens `path` for reading and records its current size.
    ///
    /// # Errors
    /// Returns any I/O error from opening the file or querying its
    /// metadata.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            size,
        })
    }
}

impl DataSource for FileSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        // Out-of-range reads are Ok(0), never an OS seek error (on
        // Windows, seeking past i64::MAX fails outright).
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let mut file = self
            .file
            .lock()
            .map_err(|_| std::io::Error::other("file source lock poisoned"))?;
        file.seek(SeekFrom::Start(offset))?;
        let mut total = 0_usize;
        while total < buf.len() {
            let dst = buf.get_mut(total..).unwrap_or(&mut []);
            match file.read(dst) {
                Ok(0) => break,
                Ok(n) => total = total.saturating_add(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic golden pattern: byte at position `i` is
    /// `(i * 7 + 3) mod 256`.
    fn golden(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(7).wrapping_add(3) & 0xFF) as u8)
            .collect()
    }

    fn write_temp(data: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("golden.bin");
        std::fs::write(&path, data).expect("write temp file");
        (dir, path)
    }

    #[test]
    fn golden_file_arbitrary_offsets() {
        let data = golden(4096);
        let (_dir, path) = write_temp(&data);
        let src = FileSource::open(&path).expect("open");
        assert_eq!(src.size(), 4096);

        for &(offset, len) in &[(0_u64, 16_usize), (1, 1), (100, 300), (4000, 96), (4095, 1)] {
            let mut buf = vec![0_u8; len];
            let n = src.read_at(offset, &mut buf).expect("read");
            assert_eq!(n, len, "offset {offset} len {len}");
            let start = usize::try_from(offset).expect("offset fits usize");
            let end = start.saturating_add(len);
            assert_eq!(&buf[..n], &data[start..end]);
        }
    }

    #[test]
    fn golden_file_short_read_at_eof() {
        let data = golden(100);
        let (_dir, path) = write_temp(&data);
        let src = FileSource::open(&path).expect("open");

        let mut buf = [0_u8; 64];
        let n = src.read_at(90, &mut buf).expect("read");
        assert_eq!(n, 10);
        assert_eq!(&buf[..10], &data[90..100]);

        assert_eq!(src.read_at(100, &mut buf).expect("read at end"), 0);
        assert_eq!(src.read_at(1000, &mut buf).expect("read past end"), 0);
        assert_eq!(
            src.read_at(u64::MAX, &mut buf).expect("read far past end"),
            0
        );
    }

    #[test]
    fn empty_file() {
        let (_dir, path) = write_temp(&[]);
        let src = FileSource::open(&path).expect("open");
        assert_eq!(src.size(), 0);
        let mut buf = [0_u8; 8];
        assert_eq!(src.read_at(0, &mut buf).expect("read"), 0);
        assert_eq!(src.read_at(5, &mut buf).expect("read"), 0);
    }

    #[test]
    fn one_byte_file() {
        let (_dir, path) = write_temp(&[0xCD]);
        let src = FileSource::open(&path).expect("open");
        assert_eq!(src.size(), 1);
        let mut buf = [0_u8; 8];
        assert_eq!(src.read_at(0, &mut buf).expect("read"), 1);
        assert_eq!(buf[0], 0xCD);
        assert_eq!(src.read_at(1, &mut buf).expect("read"), 0);
    }

    #[test]
    fn zero_length_read() {
        let data = golden(10);
        let (_dir, path) = write_temp(&data);
        let src = FileSource::open(&path).expect("open");
        let mut buf = [0_u8; 0];
        assert_eq!(src.read_at(5, &mut buf).expect("read"), 0);
    }
}
