//! Phase 1 – Protocol Specification Format
//!
//! Defines `ProtocolManifest` – a YAML/JSON format that describes a multi-contract
//! protocol: contracts, their interactions, and protocol-level invariants.
//!
//! ```yaml
//! name: SimpleDEX
//! description: A constant-product automated market maker
//! contracts:
//!   - name: token_a
//!     address: C...
//!     wasm_path: ./token_a.wasm
//!     role: Token
//!   - name: pool
//!     address: C...
//!     wasm_path: ./pool.wasm
//!     role: AMMPool
//! interactions:
//!   - from_contract: token_a
//!     from_function: transfer
//!     to_contract: pool
//!     to_function: swap
//! invariants:
//!   - name: constant_product
//!     description: Reserve product before and after non-swap ops must be constant
//!     expression: "reserve_x * reserve_y == k_constant"
//!     kind: Economic
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::path::PathBuf;

use super::{InvariantKind, ProtocolInvariant, VerificationStatus};

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolManifest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub contracts: Vec<ContractSpec>,
    #[serde(default)]
    pub interactions: Vec<InteractionSpec>,
    #[serde(default)]
    pub invariants: Vec<ProtocolInvariant>,
}

// ---------------------------------------------------------------------------
// Contract specification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSpec {
    pub name: String,
    pub address: String,
    pub wasm_path: PathBuf,
    pub role: ContractRole,
}

/// Semantic role of a contract in the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractRole {
    Token,
    AMMPool,
    LendingPool,
    Factory,
    FeeDistributor,
    Governance,
    Oracle,
    Vault,
    Bridge,
    StakingPool,
    Other(String),
}

impl std::fmt::Display for ContractRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractRole::Other(s) => write!(f, "{}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

// ---------------------------------------------------------------------------
// Interaction specification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionSpec {
    pub from_contract: String,
    pub from_function: String,
    pub to_contract: String,
    pub to_function: String,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

pub fn load_manifest(path: &PathBuf) -> Result<ProtocolManifest> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("failed to read {:?}", path))?;

    let manifest: ProtocolManifest = if path
        .extension()
        .map(|e| e == "json")
        .unwrap_or(false)
    {
        serde_json::from_str(&content)?
    } else {
        serde_yaml::from_str(&content).unwrap_or_else(|_| {
            serde_json::from_str(&content).expect("manifest must be valid YAML or JSON")
        })
    };

    // Default invariants to Unknown status on first load.
    let invariants = manifest
        .invariants
        .into_iter()
        .map(|mut inv| {
            inv.status = VerificationStatus::Unknown;
            inv
        })
        .collect();

    Ok(ProtocolManifest {
        invariants,
        ..manifest
    })
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl ProtocolManifest {
    /// Validate cross-references: every interaction must reference contracts
    /// that are declared in the manifest.
    pub fn validate(&self) -> Result<()> {
        let contract_names: Vec<&str> = self.contracts.iter().map(|c| c.name.as_str()).collect();

        for (i, ix) in self.interactions.iter().enumerate() {
            if !contract_names.contains(&ix.from_contract.as_str()) {
                anyhow::bail!(
                    "interaction[{}]: from_contract '{}' not in contracts list",
                    i,
                    ix.from_contract
                );
            }
            if !contract_names.contains(&ix.to_contract.as_str()) {
                anyhow::bail!(
                    "interaction[{}]: to_contract '{}' not in contracts list",
                    i,
                    ix.to_contract
                );
            }
        }

        for inv in &self.invariants {
            for c in &inv.spans_contracts {
                if !contract_names.contains(&c.as_str()) {
                    anyhow::bail!(
                        "invariant '{}': spans_contract '{}' not in contracts list",
                        inv.name,
                        c
                    );
                }
            }
        }

        Ok(())
    }
}
