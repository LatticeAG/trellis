//! Strict JSON parser and RFC 8785 (JCS) canonical serializer.
//!
//! Wire rules (spec §2.1): UTF-8 without BOM, no duplicate object members,
//! no trailing bytes. Numbers are safe nonnegative integers only: floats,
//! exponent tokens, negative zero and unsafe integers are rejected by the
//! protocol parser. Per-object limits: depth <= 16, <= 128 properties,
//! arrays <= 256 elements.

use std::collections::BTreeMap;
use std::fmt;

/// Largest integer the wire parser accepts (JS safe integer bound).
pub const MAX_SAFE_INT: u64 = 9_007_199_254_740_991;
pub const MAX_DEPTH: usize = 16;
pub const MAX_PROPS: usize = 128;
pub const MAX_ARRAY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Nonnegative safe integer (the only numeric form allowed on the wire).
    Int(u64),
    Str(String),
    Arr(Vec<Value>),
    Obj(BTreeMap<String, Value>),
}

impl Value {
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }
    pub fn int(n: u64) -> Value {
        Value::Int(n)
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Obj(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<u64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    /// Canonical bytes J(x) per RFC 8785.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_jcs(self, &mut out);
        out
    }
    pub fn canonical_string(&self) -> String {
        String::from_utf8(self.canonical()).expect("jcs is utf8")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    TrailingBytes,
    UnexpectedEof,
    UnexpectedToken(u8),
    InvalidUtf8,
    InvalidEscape,
    InvalidSurrogate,
    DuplicateKey(String),
    NonSafeNumber,
    DepthExceeded,
    TooManyProperties,
    ArrayTooLarge,
    TrailingComma,
    BadLiteral,
    EmptyInput,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonError::TrailingBytes => write!(f, "trailing bytes"),
            JsonError::UnexpectedEof => write!(f, "unexpected end of input"),
            JsonError::UnexpectedToken(b) => write!(f, "unexpected byte {:#x}", b),
            JsonError::InvalidUtf8 => write!(f, "invalid utf-8"),
            JsonError::InvalidEscape => write!(f, "invalid escape"),
            JsonError::InvalidSurrogate => write!(f, "unpaired surrogate"),
            JsonError::DuplicateKey(k) => write!(f, "duplicate key {:?}", k),
            JsonError::NonSafeNumber => write!(f, "number is not a safe nonnegative integer"),
            JsonError::DepthExceeded => write!(f, "depth exceeds 16"),
            JsonError::TooManyProperties => write!(f, "object exceeds 128 properties"),
            JsonError::ArrayTooLarge => write!(f, "array exceeds 256 elements"),
            JsonError::TrailingComma => write!(f, "trailing comma"),
            JsonError::BadLiteral => write!(f, "bad literal"),
            JsonError::EmptyInput => write!(f, "empty input"),
        }
    }
}

impl std::error::Error for JsonError {}

/// Parse a complete JSON document under the wire rules.
pub fn parse(bytes: &[u8]) -> Result<Value, JsonError> {
    if bytes.first() == Some(&0xEF) {
        return Err(JsonError::UnexpectedToken(0xEF));
    }
    let mut p = Parser { b: bytes, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(JsonError::TrailingBytes);
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Result<u8, JsonError> {
        self.b.get(self.i).copied().ok_or(JsonError::UnexpectedEof)
    }
    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::DepthExceeded);
        }
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Value::Str(self.string()?)),
            b't' => self.lit(b"true", Value::Bool(true)),
            b'f' => self.lit(b"false", Value::Bool(false)),
            b'n' => self.lit(b"null", Value::Null),
            c => self.number(c),
        }
    }
    fn lit(&mut self, s: &[u8], v: Value) -> Result<Value, JsonError> {
        if self.b.len() - self.i >= s.len() && &self.b[self.i..self.i + s.len()] == s {
            self.i += s.len();
            Ok(v)
        } else {
            Err(JsonError::BadLiteral)
        }
    }
    fn number(&mut self, first: u8) -> Result<Value, JsonError> {
        // Wire profile: only safe nonnegative integers. Reject -, ., e, E.
        if first == b'-' {
            return Err(JsonError::NonSafeNumber);
        }
        if !first.is_ascii_digit() {
            return Err(JsonError::UnexpectedToken(first));
        }
        let start = self.i;
        self.i += 1;
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            self.i += 1;
        }
        // Any non-digit numeric continuation is a wire violation.
        if self.i < self.b.len() && matches!(self.b[self.i], b'.' | b'e' | b'E' | b'-' | b'+') {
            return Err(JsonError::NonSafeNumber);
        }
        let tok = &self.b[start..self.i];
        if tok.len() > 1 && tok[0] == b'0' {
            return Err(JsonError::NonSafeNumber); // leading zero
        }
        let s = std::str::from_utf8(tok).map_err(|_| JsonError::InvalidUtf8)?;
        let n: u64 = s.parse().map_err(|_| JsonError::NonSafeNumber)?;
        if n > MAX_SAFE_INT {
            return Err(JsonError::NonSafeNumber);
        }
        Ok(Value::Int(n))
    }
    fn string(&mut self) -> Result<String, JsonError> {
        debug_assert_eq!(self.peek()?, b'"');
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&cp) {
                                // high surrogate: require \uDC00..\uDFFF next
                                if self.peek()? != b'\\' {
                                    return Err(JsonError::InvalidSurrogate);
                                }
                                self.i += 1;
                                if self.peek()? != b'u' {
                                    return Err(JsonError::InvalidSurrogate);
                                }
                                self.i += 1;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(JsonError::InvalidSurrogate);
                                }
                                0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&cp) {
                                return Err(JsonError::InvalidSurrogate);
                            } else {
                                cp
                            };
                            let ch = char::from_u32(ch).ok_or(JsonError::InvalidSurrogate)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(JsonError::InvalidEscape),
                    }
                }
                0x00..=0x1F => return Err(JsonError::UnexpectedToken(c)),
                _ => {
                    // raw multibyte utf-8 collected then validated wholesale
                    out.push(c);
                    if c >= 0x80 {
                        let extra = if c >= 0xF0 {
                            3
                        } else if c >= 0xE0 {
                            2
                        } else {
                            1
                        };
                        for _ in 0..extra {
                            out.push(self.peek()?);
                            self.i += 1;
                        }
                    }
                }
            }
        }
        String::from_utf8(out).map_err(|_| JsonError::InvalidUtf8)
    }
    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.i + 4 > self.b.len() {
            return Err(JsonError::UnexpectedEof);
        }
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.b[self.i];
            self.i += 1;
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(JsonError::InvalidEscape),
            };
            v = v * 16 + d as u32;
        }
        Ok(v)
    }
    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.i += 1; // '{'
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek()? == b'}' {
            self.i += 1;
            return Ok(Value::Obj(m));
        }
        loop {
            self.ws();
            if self.peek()? != b'"' {
                return Err(JsonError::UnexpectedToken(self.peek()?));
            }
            let k = self.string()?;
            if m.contains_key(&k) {
                return Err(JsonError::DuplicateKey(k));
            }
            self.ws();
            if self.peek()? != b':' {
                return Err(JsonError::UnexpectedToken(self.peek()?));
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            m.insert(k, v);
            if m.len() > MAX_PROPS {
                return Err(JsonError::TooManyProperties);
            }
            self.ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                    self.ws();
                    if self.peek()? == b'}' {
                        return Err(JsonError::TrailingComma);
                    }
                }
                b'}' => {
                    self.i += 1;
                    return Ok(Value::Obj(m));
                }
                c => return Err(JsonError::UnexpectedToken(c)),
            }
        }
    }
    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.i += 1; // '['
        let mut a = Vec::new();
        self.ws();
        if self.peek()? == b']' {
            self.i += 1;
            return Ok(Value::Arr(a));
        }
        loop {
            let v = self.value(depth + 1)?;
            a.push(v);
            if a.len() > MAX_ARRAY {
                return Err(JsonError::ArrayTooLarge);
            }
            self.ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                    self.ws();
                    if self.peek()? == b']' {
                        return Err(JsonError::TrailingComma);
                    }
                }
                b']' => {
                    self.i += 1;
                    return Ok(Value::Arr(a));
                }
                c => return Err(JsonError::UnexpectedToken(c)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JCS serialization (RFC 8785). Wire values hold only safe integers, so the
// number branch is the integer case of the ECMAScript serialization.
// ---------------------------------------------------------------------------

fn write_jcs(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::Str(s) => write_jcs_string(s, out),
        Value::Arr(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_jcs(x, out);
            }
            out.push(b']');
        }
        Value::Obj(m) => {
            // Sort by UTF-16 code units (RFC 8785 ordering).
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by_key(|a| utf16_key(a));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_jcs_string(k, out);
                out.push(b':');
                write_jcs(&m[*k], out);
            }
            out.push(b'}');
        }
    }
}

fn utf16_key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn write_jcs_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0A}' => out.extend_from_slice(b"\\n"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\u{0D}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Serialize any `serde_json`-free structure built as `Value` into canonical
/// bytes. Convenience for callers holding raw JSON text produced by the
/// canonical path.
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, JsonError> {
    Ok(parse(bytes)?.canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dup_keys_rejected() {
        assert_eq!(
            parse(b"{\"v\":1,\"v\":1}"),
            Err(JsonError::DuplicateKey("v".into()))
        );
    }

    #[test]
    fn negative_zero_rejected() {
        assert_eq!(parse(b"{\"v\":1,\"x\":-0}"), Err(JsonError::NonSafeNumber));
    }

    #[test]
    fn exponent_and_float_rejected() {
        assert!(matches!(parse(b"1e3"), Err(JsonError::NonSafeNumber)));
        assert!(matches!(parse(b"1.5"), Err(JsonError::NonSafeNumber)));
        assert!(matches!(parse(b"-1"), Err(JsonError::NonSafeNumber)));
    }

    #[test]
    fn jcs_sorts_and_compacts() {
        let v = parse(br#"{"b":2,"a":"1"}"#).unwrap();
        assert_eq!(v.canonical(), br#"{"a":"1","b":2}"#.to_vec());
    }

    #[test]
    fn jcs_utf16_order() {
        // U+FFFF (utf16 FFFF) sorts after U+10000 surrogate pair start? No:
        // '\u{10000}' encodes as D800 DC00 -> first unit D800 < FFFF.
        let v = parse("{\"\\uffff\":1,\"𐀀\":2}".as_bytes()).unwrap();
        let keys: Vec<String> = v.as_obj().unwrap().keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort_by_key(|a| utf16_key(a));
        assert_eq!(sorted[0], "𐀀");
    }

    #[test]
    fn no_unicode_normalization() {
        let a = parse("{\"x\":\"é\"}".as_bytes()).unwrap();
        let b = parse("{\"x\":\"é\"}".as_bytes()).unwrap();
        assert_ne!(a.canonical(), b.canonical());
    }

    #[test]
    fn depth_limit() {
        let mut s = String::new();
        for _ in 0..17 {
            s.push('[');
        }
        s.push('0');
        for _ in 0..17 {
            s.push(']');
        }
        assert_eq!(parse(s.as_bytes()), Err(JsonError::DepthExceeded));
    }

    #[test]
    fn unsafe_int_rejected() {
        assert_eq!(parse(b"9007199254740992"), Err(JsonError::NonSafeNumber));
        assert!(parse(b"9007199254740991").is_ok());
    }
}
