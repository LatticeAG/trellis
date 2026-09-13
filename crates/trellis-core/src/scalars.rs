//! Exact scalar validators (spec §2.1) and ID generation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// U: `^(0|[1-9][0-9]{0,18})$`, value <= 9223372036854775807.
pub fn is_u(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 19 {
        return false;
    }
    if b[0] == b'0' {
        return b.len() == 1;
    }
    if !b.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    match s.parse::<u64>() {
        Ok(v) => v <= i64::MAX as u64,
        Err(_) => false,
    }
}

pub fn parse_u(s: &str) -> Option<u64> {
    if is_u(s) {
        s.parse().ok()
    } else {
        None
    }
}

/// Hash: `^[0-9a-f]{64}$`.
pub fn is_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Strict canonical unpadded base64url decoder. Rejects padding, foreign
/// alphabets, and non-canonical trailing bits.
pub fn b64url_decode(s: &str, want_len: usize) -> Option<Vec<u8>> {
    if s.is_empty()
        || s.bytes()
            .any(|c| !matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
    {
        return None;
    }
    // canonical length: no padding allowed; encoded len for n bytes is
    // ceil(n*4/3) minus padding -> n*8/6 rounded up.
    let expect_chars = (want_len * 8).div_ceil(6);
    if s.len() != expect_chars {
        return None;
    }
    // Check canonical trailing bits: last char's unused low bits must be zero.
    let rem_bits = (want_len * 8) % 6;
    if rem_bits != 0 {
        let used = rem_bits; // significant bits in final char
        let last = s.as_bytes()[s.len() - 1];
        let idx = b64_index(last)?;
        if idx & ((1u8 << (6 - used)) - 1) != 0 {
            return None;
        }
    }
    URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .filter(|v| v.len() == want_len)
}

fn b64_index(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

pub fn b64url_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Sig: canonical unpadded base64url of exactly 64 bytes.
pub fn is_sig(s: &str) -> bool {
    b64url_decode(s, 64).is_some()
}
/// Pub / Nonce: canonical unpadded base64url of exactly 32 bytes.
pub fn is_pub(s: &str) -> bool {
    b64url_decode(s, 32).is_some()
}
pub fn is_nonce(s: &str) -> bool {
    is_pub(s)
}

/// Text: Unicode scalars, no NUL, at most 256 UTF-8 bytes.
pub fn is_text(s: &str) -> bool {
    s.len() <= 256 && !s.contains('\0')
}

/// Path: absolute UTF-8 path, no NUL, at most 4096 bytes.
pub fn is_path(s: &str) -> bool {
    s.len() <= 4096 && s.starts_with('/') && !s.contains('\0')
}

/// UTC: `YYYY-MM-DDTHH:mm:ss.sssZ`, valid Gregorian instant.
pub fn is_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 24
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
    {
        return false;
    }
    let dig = |i: usize| b[i].is_ascii_digit();
    if !(0..24)
        .filter(|&i| ![4, 7, 10, 13, 16, 19, 23].contains(&i))
        .all(dig)
    {
        return false;
    }
    let num = |a: usize, c: usize| -> u32 { s[a..a + c].parse().unwrap_or(99999) };
    let (y, mo, d, h, mi, sec) = (
        num(0, 4),
        num(5, 2),
        num(8, 2),
        num(11, 2),
        num(14, 2),
        num(17, 2),
    );
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || sec > 60 || y == 0 {
        return false;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][(mo - 1) as usize];
    (1..=dim).contains(&d)
}

/// UUID: lowercase canonical UUID text.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 || b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| {
        if [8, 13, 18, 23].contains(&i) {
            true
        } else {
            c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
        }
    })
}

pub const ID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub const ID_SUFFIX_LEN: usize = 21;

/// ID<P>: `P_` + exactly 21 chars from the nanoid alphabet.
pub fn is_id(s: &str, prefix: &str) -> bool {
    let want = format!("{}_", prefix);
    if !s.starts_with(&want) {
        return false;
    }
    let suf = &s[want.len()..];
    suf.len() == ID_SUFFIX_LEN && suf.bytes().all(|c| ID_ALPHABET.contains(&c))
}

pub fn is_any_id(s: &str) -> bool {
    [
        "trh", "tra", "trr", "trb", "trq", "tre", "trk", "trp", "trc", "trn",
    ]
    .iter()
    .any(|p| is_id(s, p))
}

/// Cryptographic nanoid suffix (21 chars, rejection-sampled).
pub fn nanoid_suffix() -> String {
    let mut out = String::with_capacity(ID_SUFFIX_LEN);
    let mut buf = [0u8; 64];
    while out.len() < ID_SUFFIX_LEN {
        getrandom::getrandom(&mut buf).expect("csprng");
        for &b in buf.iter() {
            // rejection sampling: accept b < 256 - (256 % 64) = all (256%64==0)
            out.push(ID_ALPHABET[(b & 63) as usize] as char);
            if out.len() == ID_SUFFIX_LEN {
                break;
            }
        }
    }
    out
}

pub fn nanoid(prefix: &str) -> String {
    format!("{}_{}", prefix, nanoid_suffix())
}

/// CSPRNG bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("csprng");
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u_values() {
        assert!(!is_u("00"));
        assert!(!is_u("9223372036854775808"));
        assert!(is_u("0"));
        assert!(is_u("9223372036854775807"));
        assert!(!is_u("01"));
        assert!(!is_u("1e3"));
    }

    #[test]
    fn ids() {
        assert!(is_id("trr_000000000000000000001", "trr"));
        assert!(!is_id("trr_00000000000000000001", "trr")); // 20 suffix chars
        assert!(!is_id("trx_000000000000000000001", "trr"));
    }

    #[test]
    fn b64_canonical() {
        // 32-byte all-zero nonce
        let n = b64url_encode(&[0u8; 32]);
        assert!(is_pub(&n));
        // non-canonical trailing bits rejected
        let mut bad = n.clone();
        bad.replace_range(n.len() - 1.., "B"); // last char low bits nonzero for 32B
        assert!(!is_pub(&bad));
        // padded rejected
        assert!(!is_pub(&format!("{}=", n)));
    }

    #[test]
    fn utc_valid() {
        assert!(is_utc("2026-09-12T00:00:00.000Z"));
        assert!(!is_utc("2026-02-30T00:00:00.000Z"));
        assert!(!is_utc("2026-09-12T00:00:00Z"));
    }
}
