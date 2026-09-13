//! trellis-core: the safety owner. Strict protocol parsing, canonical JSON,
//! domain-separated hashing/signing, the single-writer reducer, SQLite
//! persistence, the guard automaton, and OS-boundary models.
//!
//! TypeScript and Python are clients only — every safety decision lives here.

pub mod chan;
pub mod clock;
pub mod crypto;
pub mod daemon;
pub mod emergency;
pub mod engine;
pub mod export;
pub mod fixtures;
pub mod frame;
pub mod gate;
pub mod guard;
pub mod harness;
pub mod json;
pub mod os;
pub mod scalars;
pub mod schema;
pub mod seccomp;
pub mod store;
pub mod types;
pub mod verify;
pub mod wire;
