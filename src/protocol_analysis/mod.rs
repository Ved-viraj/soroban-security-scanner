//! Protocol-Level Invariant Verification for Multi-Contract Soroban Systems.
//!
//! This module implements a comprehensive protocol-level invariant verification
//! system described in Issue #449. Real Soroban protocols involve 5–20 contracts
//! working together (tokens, pools, factories, fee distributors, governance, oracles).
//! This module verifies invariants that span **multiple contracts** — something the
//! single-contract invariant engine cannot do.
//!
//! # Architecture
//!
//! ```text
//! ProtocolManifest (YAML/JSON)
//!         │
//!         ▼
//! ┌──────────────────────────────┐
//! │  Phase 1: Manifest Parser    │
//! └──────────┬───────────────────┘
//!            ▼
//! ┌──────────────────────────────┐
//! │  Phase 2: Auto-Inference     │
//! │  detects AMM / Lending /     │
//! │  Bridge / Governance patterns│
//! └──────────┬───────────────────┘
//!            ▼
//! ┌──────────────────────────────┐
//! │  Phase 3: Static Analysis    │
//! │  (modular verification, SMT) │
//! └──────────┬───────────────────┘
//!            ▼
//! ┌──────────────────────────────┐
//! │  Phase 4: Dynamic Simulation │
//! │  (100k random operations)    │
//! └──────────┬───────────────────┘
//!            ▼
//! ┌──────────────────────────────┐
//! │  Phase 5: Call Graph         │
//! │  (protocol-level control flow│
//! │   + invariant-critical secs) │
//! └──────────┬───────────────────┘
//!            ▼
//! ┌──────────────────────────────┐
//! │  Phase 6: Adversarial        │
//! │  (multi-contract exploit     │
//! │   exploration + profit)      │
//! └──────────┬───────────────────┘
//!            ▼
//! ┌──────────────────────────────┐
//! │  Phase 7: Health Dashboard   │
//! │  (status, coverage, history) │
//! └──────────┬───────────────────┘
//!            ▼
//! ┌──────────────────────────────┐
//! │  Phase 8: CLI + CI           │
//! │  (stellar-scanner protocol-  │
//! │   verify) + docs             │
//! └──────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust
//! use soroban_security_scanner::protocol_analysis::*;
//!
//! // Parse a protocol manifest
//! let manifest = ProtocolManifest::from_yaml(r#"
//!   name: "MyDex"
//!   version: "1.0.0"
//!   contracts:
//!     - name: pool_a
//!       role: amm_pool
//!   "#).unwrap();
//!
//! // Verify all protocol invariants
//! let engine = ProtocolVerificationEngine::new();
//! let report = engine.verify(&manifest, VerificationConfig::default()).unwrap();
//! ```

pub mod manifest;
pub mod inference;
pub mod static_analysis;
pub mod simulator;
pub mod call_graph;
pub mod adversarial;
pub mod health;
pub mod report;

#[cfg(test)]
mod tests;

// ── Re-exports ──────────────────────────────────────────────────────────────
pub use manifest::{
    ContractRole, ContractSpec, Expression, InvariantSpec, ProtocolManifest, ProtocolParser,
};
pub use inference::{
    InferredInvariant, PatternDetector, ProtocolPattern, PatternConfidence,
};
pub use static_analysis::{StaticAnalyzer, StaticVerificationResult, VerificationStatus};
pub use simulator::{
    OperationSequence, ProtocolSimulator, SimulationConfig, SimulationReport,
};
pub use call_graph::{
    CallEdgeType, CallGraphEdge, CallGraphNode, ControlFlowPhase, InvariantCriticalSection,
    ProtocolCallGraph, ProtocolCallGraphBuilder,
};
pub use adversarial::{AdversarialAgent, AdversarialExploit, AdversarialReport, ExplorationConfig, ExploitDifficulty};
pub use health::{
    HealthCoverage, InvariantStatus, ProtocolHealth, ProtocolHealthDashboard,
};
pub use report::{ProtocolVerifyCommand, ProtocolVerifyReport, VerificationConfig};
