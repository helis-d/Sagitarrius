//! Sagitarrius library: vault, crypto, storage and broker modules shared by
//! both binaries.
//!
//! - `sagitarrius` (main CLI) is network-free by construction: it builds
//!   without the `broker-http` feature, so `ureq`/`url` never enter its
//!   dependency tree (verify: `cargo tree -e normal --bin sagitarrius`).
//! - `sagitarrius-broker` (credential broker) requires `broker-http` and is
//!   the only binary allowed to open sockets.

pub mod archive;
pub mod banner;
pub mod cli;
pub mod commands;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod files;
pub mod input;
pub mod platform;
pub mod state;
pub mod storage;
pub mod vault;
pub mod vault_v3;

pub mod broker;
