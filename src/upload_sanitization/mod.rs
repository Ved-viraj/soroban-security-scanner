//! Upload sanitization pipeline for WASM binaries.
//!
//! This module validates uploaded WASM binaries through multiple stages:
//! - Magic byte verification (magic.rs)
//! - Malware signature scanning (malware.rs)
//! - Content type checks (content_type.rs)
//! - Deep inspection (deep_inspection.rs) that validates WASM structure
//!   and function signatures against the Stellar Environment Interface (SEI)

pub mod content_type;
pub mod deep_inspection;
pub mod magic;
pub mod malware;
pub mod sanitize;
pub mod wasm;

pub use self::sanitize::SanitizationPipeline;
pub use self::deep_inspection::{SorobanContractInterface, SignatureValidationResult};
