//! Credential broker modules.
//!
//! `policy`, `request`, `respond` and `audit` are pure and always compiled.
//! `http` (outbound sockets) exists only with the `broker-http` feature,
//! which only the `sagitarrius-broker` binary enables.

pub mod audit;
#[cfg(feature = "broker-http")]
pub mod http;
pub mod policy;
pub mod request;
pub mod respond;
