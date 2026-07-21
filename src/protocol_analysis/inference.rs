//! Phase 2 — Protocol Invariant Auto-Inference.
//!
//! For common protocol patterns, auto-infer invariants by matching contract
//! function signatures and storage layout against known templates:
//!
//! - **AMM Pool**: `reserve_x * reserve_y == k` (constant product)
//! - **Lending Pool**: `total_deposits >= total_loans`
//! - **Bridge/Wrapped Token**: `locked_on_chain_a == minted_on_chain_b`
//! - **Governance Token**: `total_voting_power == sum(delegated_power)`

use crate::protocol_analysis::manifest::{
    ContractRole, ContractSpec, Expression, InvariantSpec, ProtocolManifest,
};

/// Common protocol patterns that the inference engine recognizes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ProtocolPattern {
    /// Constant product AMM (Uniswap-like): `reserve_x * reserve_y == k`
    ConstantProductAmm,
    /// Lending pool: `total_deposits >= total_loans`
    LendingPool,
    /// Bridge / wrapped token: `locked == minted`
    BridgeToken,
    /// Governance token: `total_voting_power == sum(delegated_power)`
    GovernanceToken,
    /// Stablecoin: total_supply == collateral_value / collateralization_ratio
    Stablecoin,
}

/// An invariant that was inferred from pattern matching.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InferredInvariant {
    pub pattern: ProtocolPattern,
    pub invariant: InvariantSpec,
    pub confidence: PatternConfidence,
    pub source_contracts: Vec<String>,
    pub explanation: String,
}

/// Confidence level of an auto-inferred invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum PatternConfidence {
    /// Strong match: contract explicitly tagged with role or has all required functions.
    High,
    /// Partial match: some but not all function signatures match.
    Medium,
    /// Weak match: inferred from storage key names only.
    Low,
}

/// Engine that detects protocol patterns and auto-infers invariants.
pub struct PatternDetector;

impl PatternDetector {
    /// Auto-infer invariants for all contracts in a protocol manifest.
    pub fn infer_all(manifest: &ProtocolManifest) -> Vec<InferredInvariant> {
        let mut inferred = Vec::new();

        for contract in &manifest.contracts {
            match contract.role {
                ContractRole::AmmPool => {
                    inferred.extend(Self::infer_amm_invariants(contract));
                }
                ContractRole::LendingPool => {
                    inferred.extend(Self::infer_lending_invariants(contract));
                }
                ContractRole::Bridge => {
                    inferred.extend(Self::infer_bridge_invariants(contract));
                }
                ContractRole::Governance => {
                    inferred.extend(Self::infer_governance_invariants(contract));
                }
                _ => {
                    // Try function-signature-based detection for custom roles
                    inferred.extend(Self::detect_by_signatures(contract));
                }
            }
        }

        // Also detect multi-contract patterns
        inferred.extend(Self::detect_stablecoin_pattern(manifest));

        inferred
    }

    /// Infer constant product invariant for an AMM pool.
    fn infer_amm_invariants(contract: &ContractSpec) -> Vec<InferredInvariant> {
        let mut invariants = Vec::new();

        // Get token references from storage keys or function signatures
        let tokens: Vec<&str> = contract
            .storage_keys
            .iter()
            .filter(|k| k.starts_with("reserve_"))
            .map(|k| k.trim_start_matches("reserve_"))
            .collect();

        if tokens.len() >= 2 {
            // reserve_x * reserve_y == k
            let expr = Expression::eq(
                Expression::mul(
                    Expression::storage(&contract.name, &format!("reserve_{}", tokens[0])),
                    Expression::storage(&contract.name, &format!("reserve_{}", tokens[1])),
                ),
                Expression::storage(&contract.name, "k"),
            );

            invariants.push(InferredInvariant {
                pattern: ProtocolPattern::ConstantProductAmm,
                invariant: InvariantSpec {
                    name: format!("{}_constant_product", contract.name),
                    description: format!(
                        "AMM pool {} must maintain constant product: reserve_{} * reserve_{} == k",
                        contract.name, tokens[0], tokens[1]
                    ),
                    expression: expr,
                    severity: "critical".to_string(),
                    category: "dex".to_string(),
                    auto_inferred: true,
                },
                confidence: PatternConfidence::High,
                source_contracts: vec![contract.name.clone()],
                explanation: format!(
                    "Contract '{}' tagged as amm_pool with reserve storage keys for tokens {} and {}",
                    contract.name, tokens[0], tokens[1]
                ),
            });
        } else {
            // Infer from function names
            let has_swap = contract.functions.iter().any(|f| f.name.contains("swap"));
            let has_add_liquidity =
                contract.functions.iter().any(|f| f.name.contains("add_liquidity"));

            if has_swap && has_add_liquidity {
                let expr = Expression::eq(
                    Expression::mul(
                        Expression::storage(&contract.name, "reserve_x"),
                        Expression::storage(&contract.name, "reserve_y"),
                    ),
                    Expression::storage(&contract.name, "k"),
                );

                invariants.push(InferredInvariant {
                    pattern: ProtocolPattern::ConstantProductAmm,
                    invariant: InvariantSpec {
                        name: format!("{}_constant_product", contract.name),
                        description: format!(
                            "AMM pool {} must maintain constant product",
                            contract.name
                        ),
                        expression: expr,
                        severity: "critical".to_string(),
                        category: "dex".to_string(),
                        auto_inferred: true,
                    },
                    confidence: PatternConfidence::Medium,
                    source_contracts: vec![contract.name.clone()],
                    explanation: format!(
                        "Contract '{}' has swap() and add_liquidity() functions suggesting AMM pattern",
                        contract.name
                    ),
                });
            }
        }

        // Also add: before(swap) == after(swap) for reserves
        invariants
    }

    /// Infer lending pool invariants.
    fn infer_lending_invariants(contract: &ContractSpec) -> Vec<InferredInvariant> {
        let mut invariants = Vec::new();

        // total_deposits >= total_loans
        let expr = Expression::gte(
            Expression::storage(&contract.name, "total_deposits"),
            Expression::storage(&contract.name, "total_loans"),
        );

        invariants.push(InferredInvariant {
            pattern: ProtocolPattern::LendingPool,
            invariant: InvariantSpec {
                name: format!("{}_solvency", contract.name),
                description: format!(
                    "Lending pool {} must have total_deposits >= total_loans",
                    contract.name
                ),
                expression: expr,
                severity: "critical".to_string(),
                category: "lending".to_string(),
                auto_inferred: true,
            },
            confidence: PatternConfidence::High,
            source_contracts: vec![contract.name.clone()],
            explanation: format!(
                "Contract '{}' tagged as lending_pool: must remain solvent",
                contract.name
            ),
        });

        // total_deposits == total_loans + available_liquidity + protocol_fees
        let expr2 = Expression::eq(
            Expression::storage(&contract.name, "total_deposits"),
            Expression::add(
                Expression::add(
                    Expression::storage(&contract.name, "total_loans"),
                    Expression::storage(&contract.name, "available_liquidity"),
                ),
                Expression::storage(&contract.name, "protocol_fees"),
            ),
        );

        invariants.push(InferredInvariant {
            pattern: ProtocolPattern::LendingPool,
            invariant: InvariantSpec {
                name: format!("{}_balance_sheet", contract.name),
                description: format!(
                    "Lending pool {} balance sheet must balance",
                    contract.name
                ),
                expression: expr2,
                severity: "high".to_string(),
                category: "lending".to_string(),
                auto_inferred: true,
            },
            confidence: PatternConfidence::Medium,
            source_contracts: vec![contract.name.clone()],
            explanation: format!(
                "Contract '{}' tagged as lending_pool: balance sheet invariant",
                contract.name
            ),
        });

        invariants
    }

    /// Infer bridge/wrapped token invariants.
    fn infer_bridge_invariants(contract: &ContractSpec) -> Vec<InferredInvariant> {
        // locked_on_soroban == minted_on_counterpart
        let expr = Expression::eq(
            Expression::storage(&contract.name, "locked_soroban"),
            Expression::storage(&contract.name, "minted_counterpart"),
        );

        vec![InferredInvariant {
            pattern: ProtocolPattern::BridgeToken,
            invariant: InvariantSpec {
                name: format!("{}_bridge_parity", contract.name),
                description: format!(
                    "Bridge {} must maintain locked == minted parity",
                    contract.name
                ),
                expression: expr,
                severity: "critical".to_string(),
                category: "bridge".to_string(),
                auto_inferred: true,
            },
            confidence: PatternConfidence::High,
            source_contracts: vec![contract.name.clone()],
            explanation: format!(
                "Contract '{}' tagged as bridge: locked and minted tokens must match",
                contract.name
            ),
        }]
    }

    /// Infer governance token invariants.
    fn infer_governance_invariants(contract: &ContractSpec) -> Vec<InferredInvariant> {
        // total_voting_power == sum(delegated_power)
        let expr = Expression::eq(
            Expression::storage(&contract.name, "total_voting_power"),
            Expression::storage(&contract.name, "total_delegated_power"),
        );

        vec![InferredInvariant {
            pattern: ProtocolPattern::GovernanceToken,
            invariant: InvariantSpec {
                name: format!("{}_voting_parity", contract.name),
                description: format!(
                    "Governance {} must have total_voting_power == sum(delegated_power)",
                    contract.name
                ),
                expression: expr,
                severity: "high".to_string(),
                category: "governance".to_string(),
                auto_inferred: true,
            },
            confidence: PatternConfidence::High,
            source_contracts: vec![contract.name.clone()],
            explanation: format!(
                "Contract '{}' tagged as governance: voting power must equal delegated power",
                contract.name
            ),
        }]
    }

    /// Detect patterns by analyzing function signatures (for custom roles).
    fn detect_by_signatures(contract: &ContractSpec) -> Vec<InferredInvariant> {
        let mut inferred = Vec::new();

        let has_swap = contract.functions.iter().any(|f| f.name.contains("swap"));
        let has_add_liquidity =
            contract.functions.iter().any(|f| f.name.contains("add_liquidity"));
        let has_remove_liquidity =
            contract.functions.iter().any(|f| f.name.contains("remove_liquidity"));

        if has_swap && has_add_liquidity && has_remove_liquidity {
            let expr = Expression::eq(
                Expression::mul(
                    Expression::storage(&contract.name, "reserve_x"),
                    Expression::storage(&contract.name, "reserve_y"),
                ),
                Expression::storage(&contract.name, "k"),
            );

            inferred.push(InferredInvariant {
                pattern: ProtocolPattern::ConstantProductAmm,
                invariant: InvariantSpec {
                    name: format!("{}_constant_product", contract.name),
                    description: format!(
                        "AMM pool {} must maintain constant product (detected from function signatures)",
                        contract.name
                    ),
                    expression: expr,
                    severity: "critical".to_string(),
                    category: "dex".to_string(),
                    auto_inferred: true,
                },
                confidence: PatternConfidence::Medium,
                source_contracts: vec![contract.name.clone()],
                explanation: format!(
                    "Contract '{}' has swap/add_liquidity/remove_liquidity suggesting AMM pattern",
                    contract.name
                ),
            });
        }

        let has_deposit = contract.functions.iter().any(|f| f.name.contains("deposit"));
        let has_borrow = contract.functions.iter().any(|f| f.name.contains("borrow"));
        let has_repay = contract.functions.iter().any(|f| f.name.contains("repay"));

        if has_deposit && has_borrow && has_repay {
            let expr = Expression::gte(
                Expression::storage(&contract.name, "total_deposits"),
                Expression::storage(&contract.name, "total_loans"),
            );

            inferred.push(InferredInvariant {
                pattern: ProtocolPattern::LendingPool,
                invariant: InvariantSpec {
                    name: format!("{}_solvency", contract.name),
                    description: format!(
                        "Lending pool {} must have deposits >= loans (detected from function signatures)",
                        contract.name
                    ),
                    expression: expr,
                    severity: "critical".to_string(),
                    category: "lending".to_string(),
                    auto_inferred: true,
                },
                confidence: PatternConfidence::Medium,
                source_contracts: vec![contract.name.clone()],
                explanation: format!(
                    "Contract '{}' has deposit/borrow/repay functions suggesting lending pattern",
                    contract.name
                ),
            });
        }

        inferred
    }

    /// Detect stablecoin pattern across multiple contracts.
    fn detect_stablecoin_pattern(manifest: &ProtocolManifest) -> Vec<InferredInvariant> {
        // A stablecoin invariant: total_supply(token) == collateral_value(vaults) / collateralization_ratio
        let tokens: Vec<&ContractSpec> = manifest
            .contracts
            .iter()
            .filter(|c| c.role == ContractRole::Token)
            .collect();
        let vaults: Vec<&ContractSpec> = manifest
            .contracts
            .iter()
            .filter(|c| {
                c.role == ContractRole::Treasury
                    || c.functions.iter().any(|f| f.name.contains("vault"))
            })
            .collect();

        if tokens.len() >= 1 && vaults.len() >= 1 {
            let token = &tokens[0];
            let mut invariants = Vec::new();

            // total_supply == sum(collateral_value_i) / collateralization_ratio
            let expr = Expression::eq(
                Expression::TotalSupply {
                    token: Box::new(token.name.clone()),
                },
                Expression::storage(&vaults[0].name, "total_collateral_value_usd"),
            );

            invariants.push(InferredInvariant {
                pattern: ProtocolPattern::Stablecoin,
                invariant: InvariantSpec {
                    name: format!("{}_collateral_backing", token.name),
                    description: format!(
                        "Stablecoin {} must be fully backed by collateral",
                        token.name
                    ),
                    expression: expr,
                    severity: "critical".to_string(),
                    category: "stablecoin".to_string(),
                    auto_inferred: true,
                },
                confidence: PatternConfidence::Low,
                source_contracts: vec![token.name.clone(), vaults[0].name.clone()],
                explanation: format!(
                    "Token '{}' and treasury '{}' suggest stablecoin pattern",
                    token.name, vaults[0].name
                ),
            });

            return invariants;
        }

        Vec::new()
    }
}

impl std::fmt::Display for ProtocolPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolPattern::ConstantProductAmm => write!(f, "Constant Product AMM"),
            ProtocolPattern::LendingPool => write!(f, "Lending Pool"),
            ProtocolPattern::BridgeToken => write!(f, "Bridge Token"),
            ProtocolPattern::GovernanceToken => write!(f, "Governance Token"),
            ProtocolPattern::Stablecoin => write!(f, "Stablecoin"),
        }
    }
}

impl std::fmt::Display for PatternConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternConfidence::High => write!(f, "HIGH"),
            PatternConfidence::Medium => write!(f, "MEDIUM"),
            PatternConfidence::Low => write!(f, "LOW"),
        }
    }
}
