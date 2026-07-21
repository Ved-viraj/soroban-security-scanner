//! Phase 6 – Adversarial Protocol Exploration
//!
//! Extends the economic exploit framework to target protocol-level invariants.
//! An attacker agent attempts to find sequences of operations across multiple
//! contracts that violate a protocol-level invariant and produce profit.
//!
//! The agent can interact with any contract in the protocol, not just a single
//! vulnerable contract. Protocol-level exploits are reported separately from
//! single-contract exploits.

use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::manifest::ProtocolManifest;
use super::ProtocolInvariant;

// ---------------------------------------------------------------------------
// Adversarial Agent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialAgent {
    /// Number of attack sequences to generate.
    pub attack_rounds: u64,
    /// Maximum operations per attack sequence.
    pub max_operations_per_round: usize,
    /// The agent's initial balance (for profit calculation).
    pub initial_balance: f64,
}

impl Default for AdversarialAgent {
    fn default() -> Self {
        Self {
            attack_rounds: 1_000,
            max_operations_per_round: 20,
            initial_balance: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialReport {
    pub total_rounds: u64,
    pub exploits_found: Vec<ProtocolExploit>,
    pub profit_by_exploit: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolExploit {
    pub target_invariant: String,
    pub operation_sequence: Vec<ExploitStep>,
    pub estimated_profit: f64,
    pub contracts_affected: Vec<String>,
    pub severity: crate::Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitStep {
    pub contract: String,
    pub function: String,
    pub args: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Exploration engine
// ---------------------------------------------------------------------------

pub fn run_adversarial_exploration(
    protocol: &ProtocolManifest,
    agent: &AdversarialAgent,
) -> Result<AdversarialReport> {
    let mut rng = rand::thread_rng();
    let mut exploits = Vec::new();
    let mut profit_by_exploit = HashMap::new();

    let operations = build_operation_pool(protocol);

    for round in 0..agent.attack_rounds {
        let op_count = rng.gen_range(3..agent.max_operations_per_round);
        let mut sequence = Vec::new();

        for _ in 0..op_count {
            let op_idx = rng.gen_range(0..operations.len());
            let (contract, function) = &operations[op_idx];
            sequence.push(ExploitStep {
                contract: contract.clone(),
                function: function.clone(),
                args: serde_json::json!({"attack_round": round}),
            });
        }

        // Check if this sequence violates any protocol invariant
        for inv in &protocol.invariants {
            if does_sequence_violate_invariant(&sequence, inv, protocol) {
                let profit = estimate_profit(&sequence, inv);
                let exploit = ProtocolExploit {
                    target_invariant: inv.name.clone(),
                    operation_sequence: sequence.clone(),
                    estimated_profit: profit,
                    contracts_affected: inv.spans_contracts.clone(),
                    severity: if profit > 0.0 {
                        crate::Severity::Critical
                    } else {
                        crate::Severity::High
                    },
                    description: format!(
                        "Adversarial sequence violating invariant '{}': {} steps across {} contracts",
                        inv.name,
                        sequence.len(),
                        inv.spans_contracts.len()
                    ),
                };
                exploits.push(exploit);
                *profit_by_exploit.entry(inv.name.clone()).or_insert(0.0) += profit;
                break; // one exploit per round
            }
        }
    }

    Ok(AdversarialReport {
        total_rounds: agent.attack_rounds,
        exploits_found: exploits,
        profit_by_exploit,
    })
}

fn build_operation_pool(protocol: &ProtocolManifest) -> Vec<(String, String)> {
    let mut pool = Vec::new();
    for contract in &protocol.contracts {
        let funcs = match &contract.role {
            super::manifest::ContractRole::Token => vec!["transfer", "mint", "burn", "approve"],
            super::manifest::ContractRole::AMMPool => vec!["swap", "add_liquidity", "remove_liquidity"],
            super::manifest::ContractRole::LendingPool => vec!["deposit", "borrow", "repay", "liquidate"],
            super::manifest::ContractRole::Vault => vec!["deposit_collateral", "withdraw_collateral", "mint_stable"],
            super::manifest::ContractRole::StakingPool => vec!["stake", "unstake", "claim_rewards"],
            super::manifest::ContractRole::Bridge => vec!["lock", "unlock", "mint_wrapped"],
            super::manifest::ContractRole::Governance => vec!["propose", "vote", "execute"],
            super::manifest::ContractRole::Oracle => vec!["update_price", "get_price"],
            _ => vec!["call", "execute", "invoke"],
        };
        for func in funcs {
            pool.push((contract.name.clone(), func.to_string()));
        }
    }
    pool
}

fn does_sequence_violate_invariant(
    sequence: &[ExploitStep],
    inv: &ProtocolInvariant,
    protocol: &ProtocolManifest,
) -> bool {
    // Check if operations in the sequence span the contracts the invariant depends on
    let affected_contracts: std::collections::HashSet<&str> = sequence
        .iter()
        .map(|s| s.contract.as_str())
        .collect();

    let spans_all = inv
        .spans_contracts
        .iter()
        .all(|c| affected_contracts.contains(c.as_str()));

    if !spans_all {
        return false;
    }

    // Heuristic: sequences that contain operations modifying state on
    // contracts involved in the invariant are more likely to violate it.
    let has_modifying_ops = sequence.iter().any(|s| {
        let func = s.function.as_str();
        func.contains("swap")
            || func.contains("mint")
            || func.contains("burn")
            || func.contains("borrow")
            || func.contains("liquidate")
            || func.contains("stake")
            || func.contains("unstake")
    });

    // Sequences that end with a state-modifying operation on a spanned contract
    // are more likely to leave the invariant broken.
    if let Some(last) = sequence.last() {
        if inv.spans_contracts.contains(&last.contract) {
            let last_func = last.function.as_str();
            if last_func.contains("swap")
                || last_func.contains("transfer")
                || last_func.contains("mint")
            {
                return has_modifying_ops;
            }
        }
    }

    false
}

fn estimate_profit(sequence: &[ExploitStep], _inv: &ProtocolInvariant) -> f64 {
    // Simplified profit estimation: attacks that involve mint/burn/swap
    // on multiple contracts are potentially profitable.
    let mut score = 0.0;
    for step in sequence {
        match step.function.as_str() {
            "mint" | "mint_stable" | "mint_wrapped" => score += 1000.0,
            "swap" | "borrow" => score += 500.0,
            "stake" | "claim_rewards" => score += 100.0,
            _ => {}
        }
    }
    // Multi-contract attacks have higher profit potential
    let unique_contracts: std::collections::HashSet<&str> =
        sequence.iter().map(|s| s.contract.as_str()).collect();
    score * (unique_contracts.len() as f64).max(1.0)
}
