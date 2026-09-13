//! Hash domains and Ed25519 (spec §2.4).
//!
//! `D(label,x) = hex(SHA256(UTF8(label) || 0x00 || J(x)))`.
//! Signature input is `UTF8(label-SIGN) || 0x00 || raw32(hash)` — raw digest
//! bytes, never printed hexadecimal. Ordinary Ed25519, not Ed25519ph.

use crate::json::Value;
use crate::scalars::b64url_decode;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const D_POLICY: &str = "TRELLIS-POLICY/1";
pub const D_POLICY_SIGN: &str = "TRELLIS-POLICY-SIGN/1";
pub const D_EXEC: &str = "TRELLIS-EXEC/1";
pub const D_REQUEST: &str = "TRELLIS-REQUEST/1";
pub const D_EVENT: &str = "TRELLIS-EVENT/1";
pub const D_EVENT_SIGN: &str = "TRELLIS-EVENT-SIGN/1";
pub const D_CHECKPOINT: &str = "TRELLIS-CHECKPOINT/1";
pub const D_CHECKPOINT_SIGN: &str = "TRELLIS-CHECKPOINT-SIGN/1";
pub const D_KILL: &str = "TRELLIS-KILL/1";
pub const D_KILL_SIGN: &str = "TRELLIS-KILL-SIGN/1";
pub const D_HOST_CONFIG: &str = "TRELLIS-HOST-CONFIG/1";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// D(label, x): hex SHA-256 over label || NUL || canonical(x).
pub fn domain_hash(label: &str, x: &Value) -> String {
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.update([0u8]);
    h.update(x.canonical());
    hex::encode(h.finalize())
}

/// Signature payload: label || NUL || raw 32-byte digest.
fn sign_payload(label: &str, hash_hex: &str) -> Option<Vec<u8>> {
    let raw = hex::decode(hash_hex).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut m = Vec::with_capacity(label.len() + 1 + 32);
    m.extend_from_slice(label.as_bytes());
    m.push(0);
    m.extend_from_slice(&raw);
    Some(m)
}

#[derive(Clone)]
pub struct Keypair {
    pub key: SigningKey,
}

impl Keypair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Keypair {
            key: SigningKey::from_bytes(seed),
        }
    }
    pub fn generate() -> Self {
        let mut s = [0u8; 32];
        getrandom::getrandom(&mut s).expect("csprng");
        Self::from_seed(&s)
    }
    pub fn public_raw(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    pub fn public_b64(&self) -> String {
        crate::scalars::b64url_encode(&self.public_raw())
    }
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
    /// Sign raw digest bytes under the given sign domain; returns base64url sig.
    pub fn sign_domain(&self, sign_label: &str, hash_hex: &str) -> Option<String> {
        let payload = sign_payload(sign_label, hash_hex)?;
        let sig: Signature = self.key.sign(&payload);
        Some(crate::scalars::b64url_encode(&sig.to_bytes()))
    }
}

/// Verify a domain signature. Strict verification: rejects noncanonical S,
/// weak/small-order keys and points (dalek verify_strict).
pub fn verify_domain(sign_label: &str, hash_hex: &str, public_b64: &str, sig_b64: &str) -> bool {
    let Some(payload) = sign_payload(sign_label, hash_hex) else {
        return false;
    };
    let Some(pk_raw) = b64url_decode(public_b64, 32) else {
        return false;
    };
    let Some(sig_raw) = b64url_decode(sig_b64, 64) else {
        return false;
    };
    let Ok(pk) = VerifyingKey::from_bytes(&pk_raw.try_into().unwrap()) else {
        return false;
    };
    let sig = Signature::from_slice(&sig_raw).unwrap_or_else(|_| Signature::from_bytes(&[0u8; 64]));
    pk.verify_strict(&payload, &sig).is_ok()
}
