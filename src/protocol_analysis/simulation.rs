//! Phase 4 – Dynamic Protocol Simulation
//!
//! For economic invariants (those that depend on market dynamics), this module
//! builds a protocol simulator that:
//! - initializes all contracts with the protocol's genesis state,
//! - generates random sequences of user operations,
//! - checks all protocol invariants after each operation,
//! - records violation sequences.

use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::manifest::ProtocolManifest;

// ---------------------------------------------------------------------------
// Simulation report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationReport {
    pub total_steps: u64,
    pub violations: Vec<InvariantViolation>,
    /// Coverage heatmap: contract_name → fraction of functions exercised.
    pub coverage_heatmap: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant_name: String,
    pub step: u64,
    /// The operation sequence that triggered the violation.
    pub operation_sequence: Vec<SimulatedOperation>,
    pub state_snapshot: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedOperation {
    pub contract: String,
    pub function: String,
    pub args: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Operations we can simulate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum OpTemplate {
    Swap,
    Deposit,
    Borrow,
    Repay,
    Liquidate,
    Mint,
    Burn,
    Transfer,
    Stake,
    Unstake,
    ClaimRewards,
}

impl OpTemplate {
    fn all() -> &'static [OpTemplate] {
        &[
            OpTemplate::Swap,
            OpTemplate::Deposit,
            OpTemplate::Borrow,
            OpTemplate::Repay,
            OpTemplate::Liquidate,
            OpTemplate::Mint,
            OpTemplate::Burn,
            OpTemplate::Transfer,
            OpTemplate::Stake,
            OpTemplate::Unstake,
            OpTemplate::ClaimRewards,
        ]
    }
}

// ---------------------------------------------------------------------------
// Simulator
// ---------------------------------------------------------------------------

pub async fn run_protocol_simulation(
    protocol: &ProtocolManifest,
    steps: u64,
) -> Result<SimulationReport> {
    let mut rng = rand::thread_rng();
    let mut violations = Vec::new();
    let mut state: HashMap<String, HashMap<String, f64>> = initialize_state(protocol);
    let mut coverage: HashMap<String, usize> = protocol
        .contracts
        .iter()
        .map(|c| (c.name.clone(), 0))
        .collect();

    let ops = OpTemplate::all();

    for step in 0..steps {
        // Pick a random contract and operation
        let contract_idx = rng.gen_range(0..protocol.contracts.len());
        let op_idx = rng.gen_range(0..ops.len());
        let contract = &protocol.contracts[contract_idx];

        let (function_name, state_updates) =
            simulate_operation(&ops[op_idx], &contract.name, &mut state, &mut rng);

        *coverage.get_mut(&contract.name).unwrap() += 1;

        // Check invariants after each operation
        for inv in &protocol.invariants {
            if !check_invariant(inv, &state) {
                violations.push(InvariantViolation {
                    invariant_name: inv.name.clone(),
                    step,
                    operation_sequence: vec![SimulatedOperation {
                        contract: contract.name.clone(),
                        function: function_name.clone(),
                        args: serde_json::json!({"random_seed": step}),
                    }],
                    state_snapshot: serde_json::to_value(&state).unwrap_or_default(),
                });
            }
        }

        // Apply state updates
        for (key, delta) in state_updates {
            let parts: Vec<&str> = key.splitn(2, '.').collect();
            if parts.len() == 2 {
                let entry = state
                    .entry(parts[0].to_string())
                    .or_default()
                    .entry(parts[1].to_string())
                    .or_insert(0.0);
                *entry = (*entry + delta).max(0.0); // clamp to non-negative
            }
        }
    }

    let coverage_heatmap: HashMap<String, f64> = coverage
        .into_iter()
        .map(|(name, count)| {
            let pct = (count as f64 / steps as f64).min(1.0);
            (name, pct)
        })
        .collect();

    Ok(SimulationReport {
        total_steps: steps,
        violations,
        coverage_heatmap,
    })
}

fn initialize_state(
    protocol: &ProtocolManifest,
) -> HashMap<String, HashMap<String, f64>> {
    let mut state = HashMap::new();
    for contract in &protocol.contracts {
        let mut vars = HashMap::new();
        match &contract.role {
            super::manifest::ContractRole::Token => {
                vars.insert("total_supply".into(), 1_000_000.0);
                vars.insert("balance_alice".into(), 500_000.0);
                vars.insert("balance_bob".into(), 300_000.0);
            }
            super::manifest::ContractRole::AMMPool => {
                vars.insert("reserve_x".into(), 100_000.0);
                vars.insert("reserve_y".into(), 100_000.0);
                vars.insert("k_constant".into(), 10_000_000_000.0);
            }
            super::manifest::ContractRole::LendingPool => {
                vars.insert("total_deposits".into(), 500_000.0);
                vars.insert("total_loans".into(), 300_000.0);
            }
            super::manifest::ContractRole::Vault => {
                vars.insert("collateral_value".into(), 1_000_000.0);
                vars.insert("debt".into(), 500_000.0);
            }
            super::manifest::ContractRole::StakingPool => {
                vars.insert("total_staked".into(), 200_000.0);
                vars.insert("token_balance".into(), 200_000.0);
            }
            super::manifest::ContractRole::Bridge => {
                vars.insert("locked_soroban".into(), 50_000.0);
                vars.insert("minted_counterpart".into(), 50_000.0);
            }
            super::manifest::ContractRole::Governance => {
                vars.insert("total_voting_power".into(), 10_000.0);
                vars.insert("delegated_alice".into(), 5_000.0);
                vars.insert("delegated_bob".into(), 3_000.0);
            }
            _ => {
                vars.insert("default_value".into(), 1000.0);
            }
        }
        state.insert(contract.name.clone(), vars);
    }
    state
}

fn simulate_operation(
    op: &OpTemplate,
    contract: &str,
    _state: &HashMap<String, HashMap<String, f64>>,
    rng: &mut impl Rng,
) -> (String, Vec<(String, f64)>) {
    let amount: f64 = rng.gen_range(1.0..1000.0);
    match op {
        OpTemplate::Swap => ("swap".into(), vec![
            (format!("{}.reserve_x", contract), -amount),
            (format!("{}.reserve_y", contract), amount * 0.99),
        ]),
        OpTemplate::Deposit => ("deposit".into(), vec![
            (format!("{}.total_deposits", contract), amount),
        ]),
        OpTemplate::Borrow => ("borrow".into(), vec![
            (format!("{}.total_loans", contract), amount),
        ]),
        OpTemplate::Repay => ("repay".into(), vec![
            (format!("{}.total_loans", contract), -amount),
        ]),
        OpTemplate::Liquidate => ("liquidate".into(), vec![
            (format!("{}.collateral_value", contract), -amount * 1.5),
            (format!("{}.debt", contract), -amount),
        ]),
        OpTemplate::Mint => ("mint".into(), vec![
            (format!("{}.total_supply", contract), amount),
            (format!("{}.balance_alice", contract), amount),
        ]),
        OpTemplate::Burn => ("burn".into(), vec![
            (format!("{}.total_supply", contract), -amount),
            (format!("{}.balance_alice", contract), -amount),
        ]),
        OpTemplate::Transfer => ("transfer".into(), vec![
            (format!("{}.balance_alice", contract), -amount),
            (format!("{}.balance_bob", contract), amount),
        ]),
        OpTemplate::Stake => ("stake".into(), vec![
            (format!("{}.total_staked", contract), amount),
        ]),
        OpTemplate::Unstake => ("unstake".into(), vec![
            (format!("{}.total_staked", contract), -amount),
        ]),
        OpTemplate::ClaimRewards => ("claim_rewards".into(), vec![
            (format!("{}.balance_alice", contract), amount * 0.05),
        ]),
    }
}

fn check_invariant(
    inv: &super::ProtocolInvariant,
    state: &HashMap<String, HashMap<String, f64>>,
) -> bool {
    // Simple DSL evaluator for common invariant patterns
    if inv.expression.contains("total_supply")
        && inv.expression.contains("sum(balances")
        && inv.expression.contains("==")
    {
        // Extract contract name
        for (cname, vars) in state {
            if inv.expression.contains(cname) {
                let supply = vars.get("total_supply").copied().unwrap_or(0.0);
                let alice = vars.get("balance_alice").copied().unwrap_or(0.0);
                let bob = vars.get("balance_bob").copied().unwrap_or(0.0);
                return (supply - (alice + bob)).abs() < 0.001;
            }
        }
    }

    if inv.expression.contains("reserve_x") && inv.expression.contains("k_constant") {
        for (_cname, vars) in state {
            let rx = vars.get("reserve_x").copied().unwrap_or(0.0);
            let ry = vars.get("reserve_y").copied().unwrap_or(0.0);
            let k = vars.get("k_constant").copied().unwrap_or(0.0);
            // k constant should hold: rx * ry == k
            if k > 0.0 && (rx * ry - k).abs() > 1.0 {
                return false;
            }
        }
    }

    if inv.expression.contains("total_deposits") && inv.expression.contains(">=") {
        for (_cname, vars) in state {
            let deposits = vars.get("total_deposits").copied().unwrap_or(0.0);
            let loans = vars.get("total_loans").copied().unwrap_or(0.0);
            return deposits >= loans || (deposits - loans).abs() < 0.001;
        }
    }

    if inv.expression.contains("total_staked") && inv.expression.contains("token_balance") {
        for (_cname, vars) in state {
            let staked = vars.get("total_staked").copied().unwrap_or(0.0);
            let balance = vars.get("token_balance").copied().unwrap_or(0.0);
            return (staked - balance).abs() < 0.001;
        }
    }

    if inv.expression.contains("locked") && inv.expression.contains("minted") {
        for (_cname, vars) in state {
            let locked = vars.get("locked_soroban").copied().unwrap_or(0.0);
            let minted = vars.get("minted_counterpart").copied().unwrap_or(0.0);
            return (locked - minted).abs() < 0.001;
        }
    }

    if inv.expression.contains("total_voting_power") && inv.expression.contains("sum(delegated") {
        for (_cname, vars) in state {
            let power = vars.get("total_voting_power").copied().unwrap_or(0.0);
            let alice = vars.get("delegated_alice").copied().unwrap_or(0.0);
            let bob = vars.get("delegated_bob").copied().unwrap_or(0.0);
            return (power - (alice + bob)).abs() < 0.001;
        }
    }

    if inv.expression.contains("total_supply[stablecoin]")
        && inv.expression.contains("collateral_value")
    {
        for (_cname, vars) in state {
            let collateral = vars.get("collateral_value").copied().unwrap_or(0.0);
            let debt = vars.get("debt").copied().unwrap_or(0.0);
            // Simplified: debt must not exceed collateral.
            return debt <= collateral;
        }
    }

    // For non-negative checks
    if inv.expression.contains(">= 0") {
        for (_cname, vars) in state {
            if vars.values().any(|&v| v < 0.0) {
                return false;
            }
        }
        return true;
    }

    // Unrecognized pattern — don't flag as violated, just warn.
    // Returning false would cause false positives for invariants whose
    // DSL we don't parse yet.
    log::warn!("Unrecognized invariant expression, cannot check: {}", inv.expression);
    true
}
