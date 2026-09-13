//! Guard emergency file: preallocated 1 MiB per active run, two 512 KiB
//! slots, alternating pwrite+fdatasync after denial/kill is initiated
//! (spec §7.2).
//!
//! Slot layout: magic `TRLEMG01` (8) || generation u64be (8) ||
//! json_len u32be (4) || crc32-IEEE of generation||length||json (4) ||
//! canonical Emergency JSON || zero padding to slot length.
//! A torn write preserves the previous valid slot; neither valid means
//! evidence unknown — never an assumed success.

use crate::json::Value;
use crc32fast::Hasher;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::Path;

pub const SLOT_LEN: usize = 524_288;
pub const SLOTS: usize = 2;
pub const FILE_LEN: usize = SLOT_LEN * SLOTS;
pub const MAGIC: &[u8; 8] = b"TRLEMG01";
pub const JSON_MAX: usize = 4096;

fn slot_crc(gen: u64, len: u32, json: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(&gen.to_be_bytes());
    h.update(&len.to_be_bytes());
    h.update(json);
    h.finalize()
}

fn encode_slot(gen: u64, json: &[u8]) -> Option<[u8; SLOT_LEN]> {
    if json.is_empty() || json.len() > JSON_MAX {
        return None;
    }
    let mut s = [0u8; SLOT_LEN];
    s[..8].copy_from_slice(MAGIC);
    s[8..16].copy_from_slice(&gen.to_be_bytes());
    s[16..20].copy_from_slice(&(json.len() as u32).to_be_bytes());
    s[20..24].copy_from_slice(&slot_crc(gen, json.len() as u32, json).to_be_bytes());
    s[24..24 + json.len()].copy_from_slice(json);
    Some(s)
}

fn decode_slot(s: &[u8]) -> Option<(u64, Value)> {
    if s.len() != SLOT_LEN || &s[..8] != MAGIC {
        return None;
    }
    let gen = u64::from_be_bytes(s[8..16].try_into().unwrap());
    let len = u32::from_be_bytes(s[16..20].try_into().unwrap()) as usize;
    if gen == 0 || len == 0 || len > JSON_MAX || 24 + len > SLOT_LEN {
        return None;
    }
    let json = &s[24..24 + len];
    let crc = u32::from_be_bytes(s[20..24].try_into().unwrap());
    if slot_crc(gen, len as u32, json) != crc {
        return None;
    }
    // padding must be zero
    if s[24 + len..].iter().any(|&b| b != 0) {
        return None;
    }
    let v = crate::json::parse(json).ok()?;
    crate::schema::emergency(&v).ok()?;
    Some((gen, v))
}

/// Create the preallocated emergency file (root-owned, exactly 1 MiB).
pub fn create(path: &Path) -> std::io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    f.set_len(FILE_LEN as u64)?;
    f.sync_all()?;
    Ok(f)
}

/// Guard-side writer: alternates slots, pwrite + fdatasync.
pub struct EmergencyWriter {
    file: File,
    next_slot: usize,
    generation: u64,
}

impl EmergencyWriter {
    pub fn new(file: File) -> Self {
        EmergencyWriter {
            file,
            next_slot: 0,
            generation: 0,
        }
    }
    /// Write one observation; generation increments without wrapping.
    pub fn write(&mut self, body: &Value) -> std::io::Result<u64> {
        self.generation = self.generation.saturating_add(1);
        let json = body.canonical();
        let slot = encode_slot(self.generation, &json).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "emergency json too large")
        })?;
        self.file
            .write_all_at(&slot, (self.next_slot * SLOT_LEN) as u64)?;
        self.file.sync_data()?;
        self.next_slot = 1 - self.next_slot;
        Ok(self.generation)
    }
}

/// Recovery read: highest generation with valid magic/length/CRC/padding/
/// schema. None means evidence unknown.
pub fn read_best(path: &Path) -> Option<(u64, Value)> {
    let mut f = File::open(path).ok()?;
    let mut best: Option<(u64, Value)> = None;
    for i in 0..SLOTS {
        let mut buf = vec![0u8; SLOT_LEN];
        f.seek(SeekFrom::Start((i * SLOT_LEN) as u64)).ok()?;
        if f.read_exact(&mut buf).is_err() {
            continue;
        }
        if let Some((gen, v)) = decode_slot(&buf) {
            if best.as_ref().map(|(g, _)| gen > *g).unwrap_or(true) {
                best = Some((gen, v));
            }
        }
    }
    best
}
