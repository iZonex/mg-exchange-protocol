//! Write-Ahead Log — persistent message journal.
//!
//! Appends MGEP messages to a file for crash recovery and audit trail.
//! Uses mmap for append-only writes (no fsync per message — OS page cache
//! batches writes, fsync on interval or on demand).
//!
//! Format:
//!   [WAL Header: 64 bytes]
//!     magic: u32 = 0x4D47_574C ("MGWL")
//!     version: u32 = 1
//!     write_pos: u64 (updated atomically)
//!     _reserved: [u8; 48]
//!   [Entry 0: length(u32) + message(N bytes)]
//!   [Entry 1: ...]
//!   ...
//!
//! Recovery: scan from offset 64, reading length-prefixed entries until EOF or invalid.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

const WAL_MAGIC: u32 = 0x4D47_574C; // "MGWL"
const WAL_VERSION: u32 = 1;
const WAL_HEADER_SIZE: usize = 64;
const ENTRY_HEADER_SIZE: usize = 4; // u32 length prefix

/// Write-ahead log writer.
pub struct WalWriter {
    file: File,
    write_pos: u64,
}

/// Write-ahead log reader (for recovery).
pub struct WalReader {
    data: Vec<u8>,
    read_pos: usize,
}

impl WalWriter {
    /// Create a new WAL file or open existing one for append.
    pub fn open(path: &Path) -> io::Result<Self> {
        let exists = path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        if !exists || file.metadata()?.len() == 0 {
            // New file — write header
            file.set_len(WAL_HEADER_SIZE as u64)?;
            let mut header = [0u8; WAL_HEADER_SIZE];
            header[0..4].copy_from_slice(&WAL_MAGIC.to_le_bytes());
            header[4..8].copy_from_slice(&WAL_VERSION.to_le_bytes());
            header[8..16].copy_from_slice(&(WAL_HEADER_SIZE as u64).to_le_bytes());
            use std::io::Write;
            use std::io::Seek;
            let mut f = &file;
            f.seek(std::io::SeekFrom::Start(0))?;
            f.write_all(&header)?;
            f.flush()?;

            Ok(Self {
                file,
                write_pos: WAL_HEADER_SIZE as u64,
            })
        } else {
            // Existing file — read write_pos from header
            use std::io::Read;
            use std::io::Seek;
            let mut f = &file;
            let mut header = [0u8; WAL_HEADER_SIZE];
            f.seek(std::io::SeekFrom::Start(0))?;
            f.read_exact(&mut header)?;

            let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
            if magic != WAL_MAGIC {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid WAL magic"));
            }

            let write_pos = u64::from_le_bytes(header[8..16].try_into().unwrap());

            Ok(Self { file, write_pos })
        }
    }

    /// Append a message to the WAL. Returns the offset where it was written.
    pub fn append(&mut self, msg: &[u8]) -> io::Result<u64> {
        use std::io::Write;
        use std::io::Seek;

        let offset = self.write_pos;
        let entry_size = ENTRY_HEADER_SIZE + msg.len();

        let mut f = &self.file;
        f.seek(std::io::SeekFrom::Start(offset))?;

        // Write length prefix
        f.write_all(&(msg.len() as u32).to_le_bytes())?;
        // Write message
        f.write_all(msg)?;

        self.write_pos += entry_size as u64;

        // Update write_pos in header
        f.seek(std::io::SeekFrom::Start(8))?;
        f.write_all(&self.write_pos.to_le_bytes())?;

        Ok(offset)
    }

    /// Sync to disk (fsync).
    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Current write position (total file size used).
    pub fn position(&self) -> u64 {
        self.write_pos
    }

    /// Number of bytes written (excluding header).
    pub fn data_size(&self) -> u64 {
        self.write_pos - WAL_HEADER_SIZE as u64
    }
}

impl WalReader {
    /// Open a WAL file for reading (recovery).
    pub fn open(path: &Path) -> io::Result<Self> {
        let data = std::fs::read(path)?;

        if data.len() < WAL_HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "WAL too short"));
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != WAL_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid WAL magic"));
        }

        Ok(Self {
            data,
            read_pos: WAL_HEADER_SIZE,
        })
    }

    /// Total number of entries (scan to count).
    pub fn count_entries(&self) -> usize {
        let mut pos = WAL_HEADER_SIZE;
        let mut count = 0;
        while pos + ENTRY_HEADER_SIZE <= self.data.len() {
            let len = u32::from_le_bytes(
                self.data[pos..pos + 4].try_into().unwrap()
            ) as usize;
            if len == 0 || pos + ENTRY_HEADER_SIZE + len > self.data.len() {
                break;
            }
            count += 1;
            pos += ENTRY_HEADER_SIZE + len;
        }
        count
    }
}

impl Iterator for WalReader {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.read_pos + ENTRY_HEADER_SIZE > self.data.len() {
            return None;
        }

        let len = u32::from_le_bytes(
            self.data[self.read_pos..self.read_pos + 4].try_into().ok()?
        ) as usize;

        if len == 0 || self.read_pos + ENTRY_HEADER_SIZE + len > self.data.len() {
            return None;
        }

        let start = self.read_pos + ENTRY_HEADER_SIZE;
        let msg = self.data[start..start + len].to_vec();
        self.read_pos = start + len;
        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("mgep_wal_test_{}", name))
    }

    #[test]
    fn wal_write_read_roundtrip() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        // Write
        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append(b"message one").unwrap();
            wal.append(b"message two").unwrap();
            wal.append(b"message three").unwrap();
            wal.sync().unwrap();
        }

        // Read
        let reader = WalReader::open(&path).unwrap();
        assert_eq!(reader.count_entries(), 3);

        let reader = WalReader::open(&path).unwrap();
        let messages: Vec<Vec<u8>> = reader.collect();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0], b"message one");
        assert_eq!(messages[1], b"message two");
        assert_eq!(messages[2], b"message three");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wal_append_resume() {
        let path = temp_path("resume");
        let _ = std::fs::remove_file(&path);

        // Write 2 messages
        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append(b"first").unwrap();
            wal.append(b"second").unwrap();
            wal.sync().unwrap();
        }

        // Reopen and append more
        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append(b"third").unwrap();
            wal.sync().unwrap();
        }

        // Read all
        let reader = WalReader::open(&path).unwrap();
        let messages: Vec<Vec<u8>> = reader.collect();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[2], b"third");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wal_mgep_messages() {
        let path = temp_path("mgep_msgs");
        let _ = std::fs::remove_file(&path);

        let mut wal = WalWriter::open(&path).unwrap();

        // Write real MGEP messages
        let order = crate::messages::NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 1, price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };
        let mut enc = crate::codec::MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);

        for _i in 0..100 {
            wal.append(enc.as_slice()).unwrap();
        }
        wal.sync().unwrap();

        // Recover and decode
        let reader = WalReader::open(&path).unwrap();
        let mut count = 0;
        for msg in reader {
            let decoded = crate::codec::MessageBuffer::decode_new_order(&msg);
            assert_eq!(decoded.order_id, 42);
            count += 1;
        }
        assert_eq!(count, 100);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wal_empty_file() {
        let path = temp_path("empty");
        let _ = std::fs::remove_file(&path);

        let wal = WalWriter::open(&path).unwrap();
        assert_eq!(wal.data_size(), 0);

        let reader = WalReader::open(&path).unwrap();
        assert_eq!(reader.count_entries(), 0);

        std::fs::remove_file(&path).ok();
    }
}
