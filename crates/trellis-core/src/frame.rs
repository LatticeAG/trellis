//! Wire framing (spec §5.1): 4-byte unsigned big-endian length + UTF-8 JSON.
//! Length is checked before allocation: requests <= 65536, responses <= 1 MiB.

use crate::json::Value;
use crate::types::{ApiErr, Code};
use std::io::{Read, Write};

pub const REQ_MAX: usize = 65_536;
pub const RESP_MAX: usize = 1_048_576;

/// Read one frame. `None` on clean EOF at a frame boundary.
/// Overlength or malformed frames fail closed (INVALID_INPUT); the caller
/// closes the connection with no reflected text.
pub fn read_frame(r: &mut impl Read, max: usize) -> Result<Option<Value>, ApiErr> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(ApiErr::new(Code::InvalidInput)),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > max {
        return Err(ApiErr::new(Code::InvalidInput)); // close before allocation
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|_| ApiErr::new(Code::InvalidInput))?;
    let v = crate::json::parse(&buf).map_err(|_| ApiErr::new(Code::InvalidInput))?;
    Ok(Some(v))
}

/// Write one frame; refuses payloads over `max`.
pub fn write_frame(w: &mut impl Write, v: &Value, max: usize) -> Result<(), ApiErr> {
    let body = v.canonical();
    if body.len() > max {
        return Err(ApiErr::new(Code::OutputLimit));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| w.write_all(&body))
        .map_err(|_| ApiErr::new(Code::AuditFault))
}
