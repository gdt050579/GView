//! Memory-backed [`DataSource`] (C++ `AppCUI::OS::MemoryFile` parity).

use super::DataSource;
use crate::offset::try_slice;

/// An in-memory byte buffer acting as a data source.
///
/// C++ `MemoryFile::Create` copies the caller's buffer; the copying
/// constructor here is [`MemorySource::from_slice`].
pub struct MemorySource {
    data: Vec<u8>,
}

impl MemorySource {
    /// Takes ownership of `data` without copying.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Copies `data` into a new source (C++ `MemoryFile::Create`
    /// copy semantics).
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }
}

impl DataSource for MemorySource {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.data.len() as u64;
        let available = len.saturating_sub(offset);
        let n = u64::min(available, buf.len() as u64);
        let Some(src) = try_slice(&self.data, offset, n) else {
            return Ok(0);
        };
        let Some(dst) = buf.get_mut(..src.len()) else {
            return Ok(0);
        };
        dst.copy_from_slice(src);
        Ok(src.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(7).wrapping_add(3) & 0xFF) as u8)
            .collect()
    }

    #[test]
    fn arbitrary_offsets() {
        let data = golden(1000);
        let src = MemorySource::from_slice(&data);
        assert_eq!(src.size(), 1000);

        for &(offset, len) in &[(0_u64, 10_usize), (500, 500), (999, 1), (990, 10)] {
            let mut buf = vec![0_u8; len];
            let n = src.read_at(offset, &mut buf).expect("read");
            assert_eq!(n, len);
            let start = usize::try_from(offset).expect("fits");
            assert_eq!(&buf[..n], &data[start..start.saturating_add(len)]);
        }
    }

    #[test]
    fn short_and_out_of_range_reads() {
        let data = golden(100);
        let src = MemorySource::new(data.clone());
        let mut buf = [0_u8; 64];
        assert_eq!(src.read_at(90, &mut buf).expect("read"), 10);
        assert_eq!(&buf[..10], &data[90..]);
        assert_eq!(src.read_at(100, &mut buf).expect("read"), 0);
        assert_eq!(src.read_at(u64::MAX, &mut buf).expect("read"), 0);
    }

    #[test]
    fn empty_source() {
        let src = MemorySource::new(Vec::new());
        assert_eq!(src.size(), 0);
        let mut buf = [0_u8; 4];
        assert_eq!(src.read_at(0, &mut buf).expect("read"), 0);
    }

    #[test]
    fn one_byte_source() {
        let src = MemorySource::from_slice(&[0x5A]);
        assert_eq!(src.size(), 1);
        let mut buf = [0_u8; 4];
        assert_eq!(src.read_at(0, &mut buf).expect("read"), 1);
        assert_eq!(buf[0], 0x5A);
        assert_eq!(src.read_at(1, &mut buf).expect("read"), 0);
    }

    #[test]
    fn from_slice_copies() {
        let mut original = vec![1_u8, 2, 3, 4];
        let src = MemorySource::from_slice(&original);
        original[0] = 0xFF;
        let mut buf = [0_u8; 4];
        assert_eq!(src.read_at(0, &mut buf).expect("read"), 4);
        assert_eq!(buf, [1, 2, 3, 4]);
    }
}
