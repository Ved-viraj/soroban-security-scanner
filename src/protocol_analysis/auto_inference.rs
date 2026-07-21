//! Phase 2 – Protocol Invariant Auto-Inference
//!
//! For common protocol patterns, invariants are automatically inferred from
//! contract roles and interaction topology.

use anyhow::Result;

use super::manifest::{ContractRole, ProtocolManifest};
use super::{InvariantKind, ProtocolInvariant, VerificationStatus};

pub fn augment_with_auto_inferred_invariants(protocol: &mut ProtocolManifest) -> Result<()> {
    for contract in &protocol.contracts {
        infer_for_contract(protocol, contract);
    }
    Ok(())
}

fn infer_for_contract(protocol: &mut ProtocolManifest, contract: &super::manifest::ContractSpec) {
    match &contract.role {
        ContractRole::AMMPool => {
            infer_amm_pool_invariants(protocol, contract);
        }
        ContractRole::LendingPool => {
            infer_lending_pool_invariants(protocol, contract);
        }
        ContractRole::Bridge => {
            infer_bridge_invariants(protocol, contract);
        }
        ContractRole::Governance => {
            infer_governance_invariants(protocol, contract);
        }
        ContractRole::Token => {
            infer_token_invariants(protocol, contract);
        }
        ContractRole::Vault => {
            infer_vault_invariants(protocol, contract);
        }
        ContractRole::StakingPool => {
            infer_staking_pool_invariants(protocol, contract);
        }
        _ => {}
    }
}

fn add_invariant(protocol: &mut ProtocolManifest, inv: ProtocolInvariant) {
    // Avoid duplicates by name.
    if protocol.invariants.iter().any(|i| i.name == inv.name) {
        return;
    }
    protocol.invariants.push(inv);
}

// ---------------------------------------------------------------------------
// AMM Pool (constant product)
// ---------------------------------------------------------------------------

fn infer_amm_pool_invariants(
    protocol: &mut ProtocolManifest,
    contract: &super::manifest::ContractSpec,
) {
    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__constant_product", contract.name),
            description: "Reserve product must remain constant before/after any non-swap operation"
                .into(),
            expression: format!("reserve_x[{}] * reserve_y[{}] == k_constant", contract.name, contract.name),
            kind: InvariantKind::Economic,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );

    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__reserves_non_negative", contract.name),
            description: "Pool reserves must never be negative".into(),
            expression: format!("reserve_x[{}] >= 0 && reserve_y[{}] >= 0", contract.name, contract.name),
            kind: InvariantKind::Structural,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );
}

// ---------------------------------------------------------------------------
// Lending Pool
// ---------------------------------------------------------------------------

fn infer_lending_pool_invariants(
    protocol: &mut ProtocolManifest,
    contract: &super::manifest::ContractSpec,
) {
    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__deposits_gte_loans", contract.name),
            description: "Total deposits must always be >= total outstanding loans".into(),
            expression: format!("total_deposits[{}] >= total_loans[{}]", contract.name, contract.name),
            kind: InvariantKind::Economic,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

fn infer_bridge_invariants(
    protocol: &mut ProtocolManifest,
    contract: &super::manifest::ContractSpec,
) {
    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__locked_equals_minted", contract.name),
            description: "Tokens locked on chain A must equal tokens minted on chain B".into(),
            expression: format!("locked[{}_soroban] == minted[{}_counterpart]", contract.name, contract.name),
            kind: InvariantKind::Hybrid,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );
}

// ---------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------

fn infer_governance_invariants(
    protocol: &mut ProtocolManifest,
    contract: &super::manifest::ContractSpec,
) {
    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__voting_power_equals_delegated", contract.name),
            description: "Total voting power must equal sum of delegated power".into(),
            expression: format!("total_voting_power[{}] == sum(delegated_power[{}])", contract.name, contract.name),
            kind: InvariantKind::Structural,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

fn infer_token_invariants(
    protocol: &mut ProtocolManifest,
    contract: &super::manifest::ContractSpec,
) {
    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__supply_equals_balances", contract.name),
            description: "Total supply must equal the sum of all account balances".into(),
            expression: format!("total_supply[{}] == sum(balances[{}])", contract.name, contract.name),
            kind: InvariantKind::Structural,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );

    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__no_negative_balances", contract.name),
            description: "No account may hold a negative balance".into(),
            expression: format!("forall a: balance[{}][a] >= 0", contract.name),
            kind: InvariantKind::Structural,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );
}

// ---------------------------------------------------------------------------
// Vault (e.g. stablecoin collateral)
// ---------------------------------------------------------------------------

fn infer_vault_invariants(
    protocol: &mut ProtocolManifest,
    contract: &super::manifest::ContractSpec,
) {
    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__collateral_sufficient", contract.name),
            description: "Stablecoin supply must be backed by sufficient collateral at all times"
                .into(),
            expression: format!(
                "total_supply[stablecoin] * collateralization_ratio <= sum(collateral_value[{}])",
                contract.name
            ),
            kind: InvariantKind::Economic,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );
}

// ---------------------------------------------------------------------------
// Staking Pool
// ---------------------------------------------------------------------------

fn infer_staking_pool_invariants(
    protocol: &mut ProtocolManifest,
    contract: &super::manifest::ContractSpec,
) {
    add_invariant(
        protocol,
        ProtocolInvariant {
            name: format!("{}__staked_equals_balance", contract.name),
            description: "Total staked tokens must equal the pool's token balance".into(),
            expression: format!("total_staked[{}] == token_balance[{}]", contract.name, contract.name),
            kind: InvariantKind::Structural,
            spans_contracts: vec![contract.name.clone()],
            status: VerificationStatus::Unknown,
            auto_inferred: true,
        },
    );
}
