//! Phase 6 — Adversarial Protocol Exploration.
//!
//! An attacker agent attempts to find sequences of operations across multiple
//! contracts that violate a protocol-level invariant and produce profit.
//! The agent can interact with any contract in the protocol, not just a single
//! vulnerable contract.
//!
//! This extends the economic exploit framework from related issues to target
//! protocol-level invariants and reports protocol-level exploits separately.

use crate::protocol_analysis::manifest::ProtocolManifest;
use crate::protocol_analysis::simulator::{
    ProtocolOperation, ProtocolSimulator, SimulationConfig, SimulationReport,
};
use rand::SeedableRng;

/// An exploit discovered by the adversarial agent.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdversarialExploit {
    /// Name/description of the exploit.
    pub name: String,
    /// The invariant that was violated.
    pub violated_invariant: String,
    /// Sequence of operations that triggers the exploit.
    pub operation_sequence: Vec<ProtocolOperation>,
    /// Estimated profit from the exploit.
    pub estimated_profit: f64,
    /// Which contracts are involved.
    pub involved_contracts: Vec<String>,
    /// Difficulty of executing the exploit.
    pub difficulty: ExploitDifficulty,
    /// Detailed description.
    pub description: String,
    /// Mitigation recommendations.
    pub mitigations: Vec<String>,
}

/// Difficulty level of an exploit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ExploitDifficulty {
    /// Trivial to execute (single transaction).
    Easy,
    /// Moderately complex (few transactions, some setup).
    Medium,
    /// Highly complex (many transactions, precise timing).
    Hard,
    /// Requires significant capital or coordination.
    VeryHard,
}

/// Report from adversarial exploration.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdversarialReport {
    /// All exploits discovered.
    pub exploits: Vec<AdversarialExploit>,
    /// Total estimated profit across all exploits.
    pub total_estimated_profit: f64,
    /// Number of unique invariants violated.
    pub unique_invariants_violated: usize,
    /// Contracts involved in exploits.
    pub contracts_involved: Vec<String>,
    /// Simulation report from the underlying simulator.
    pub simulation_report: SimulationReport,
    /// Time spent exploring.
    pub exploration_time_ms: u64,
}

/// The adversarial exploration agent.
pub struct AdversarialAgent {
    /// The protocol manifest.
    manifest: ProtocolManifest,
    /// Exploration configuration.
    config: ExplorationConfig,
}

/// Configuration for adversarial exploration.
#[derive(Debug, Clone)]
pub struct ExplorationConfig {
    /// Number of exploration rounds.
    pub num_rounds: u32,
    /// Number of operations per exploration sequence.
    pub sequence_length: u32,
    /// Whether to prioritize high-value targets.
    pub prioritize_profitable: bool,
    /// Seed for reproducibility.
    pub seed: u64,
}

impl Default for ExplorationConfig {
    fn default() -> Self {
        Self {
            num_rounds: 10,
            sequence_length: 20,
            prioritize_profitable: true,
            seed: 42,
        }
    }
}

impl AdversarialAgent {
    /// Create a new adversarial agent.
    pub fn new(manifest: ProtocolManifest, config: ExplorationConfig) -> Self {
        Self { manifest, config }
    }

    /// Run adversarial exploration.
    pub fn explore(&mut self) -> AdversarialReport {
        let start = std::time::Instant::now();
        let mut exploits = Vec::new();
        let mut involved_contracts = std::collections::HashSet::new();
        let mut unique_invariants = std::collections::HashSet::new();
        let mut total_profit = 0.0;

        // Strategy 1: Run targeted adversarial simulations
        for round in 0..self.config.num_rounds {
            let report = self.run_adversarial_simulation(round);
            for violation in &report.violations_found {
                // Convert violation to exploit
                let exploit = AdversarialExploit {
                    name: format!(
                        "Adversarial exploit #{}: {}",
                        exploits.len() + 1,
                        violation.violated_invariant
                    ),
                    violated_invariant: violation.violated_invariant.clone(),
                    operation_sequence: violation.operations.clone(),
                    estimated_profit: self.estimate_profit(&violation.operations),
                    involved_contracts: self.extract_involved_contracts(&violation.operations),
                    difficulty: self.classify_difficulty(&violation.operations),
                    description: format!(
                        "Exploit targeting invariant '{}' using {} operations across {} contracts",
                        violation.violated_invariant,
                        violation.operations.len(),
                        self.extract_involved_contracts(&violation.operations).len()
                    ),
                    mitigations: self.generate_mitigations(&violation.violated_invariant),
                };

                total_profit += exploit.estimated_profit;
                unique_invariants.insert(exploit.violated_invariant.clone());
                for c in &exploit.involved_contracts {
                    involved_contracts.insert(c.clone());
                }
                exploits.push(exploit);
            }
        }

        // Strategy 2: Check for sandwich attacks on AMM operations
        if let Some(sandwich_exploit) = self.check_sandwich_attacks() {
            total_profit += sandwich_exploit.estimated_profit;
            unique_invariants.insert(sandwich_exploit.violated_invariant.clone());
            for c in &sandwich_exploit.involved_contracts {
                involved_contracts.insert(c.clone());
            }
            exploits.push(sandwich_exploit);
        }

        // Strategy 3: Check for flash loan attacks
        if let Some(flash_loan_exploit) = self.check_flash_loan_attacks() {
            total_profit += flash_loan_exploit.estimated_profit;
            unique_invariants.insert(flash_loan_exploit.violated_invariant.clone());
            for c in &flash_loan_exploit.involved_contracts {
                involved_contracts.insert(c.clone());
            }
            exploits.push(flash_loan_exploit);
        }

        let elapsed = start.elapsed().as_millis() as u64;

        // Run a clean simulation for the report data
        let sim_config = SimulationConfig {
            num_steps: 10_000,
            stop_on_first_violation: false,
            ..Default::default()
        };
        let mut simulator = ProtocolSimulator::new(self.manifest.clone(), sim_config);
        let sim_report = simulator.run();

        AdversarialReport {
            total_estimated_profit: total_profit,
            unique_invariants_violated: unique_invariants.len(),
            contracts_involved: involved_contracts.into_iter().collect(),
            simulation_report: sim_report,
            exploration_time_ms: elapsed,
            exploits,
        }
    }

    /// Run an adversarial simulation with biased operation selection.
    fn run_adversarial_simulation(&mut self, round: u32) -> SimulationReport {
        // Use a biased simulation that aggressively targets invariants
        let seed = self.config.seed + round as u64;
        let _rng = rand::rngs::StdRng::seed_from_u64(seed);

        let mut config = SimulationConfig::default();
        config.num_steps = self.config.sequence_length as u64;
        config.seed = seed;
        config.stop_on_first_violation = false;

        // Bias towards operations that might cause state inconsistencies
        config.operation_weights.swap = 0.20;
        config.operation_weights.add_liquidity = 0.05;
        config.operation_weights.remove_liquidity = 0.05;
        config.operation_weights.deposit = 0.15;
        config.operation_weights.borrow = 0.20; // More borrows (risky for lending)
        config.operation_weights.repay = 0.05; // Fewer repays
        config.operation_weights.transfer = 0.10;
        config.operation_weights.governance_vote = 0.05;
        config.operation_weights.bridge_deposit = 0.10;
        config.operation_weights.bridge_withdraw = 0.05;

        let mut simulator = ProtocolSimulator::new(self.manifest.clone(), config);
        simulator.run()
    }

    /// Estimate profit from an exploit operation sequence.
    fn estimate_profit(&self, operations: &[ProtocolOperation]) -> f64 {
        let mut profit = 0.0;

        for op in operations {
            match op {
                ProtocolOperation::Swap { amount_in, .. } => {
                    profit += amount_in * 0.01; // 1% slippage profit
                }
                ProtocolOperation::Borrow { amount, .. } => {
                    profit += amount * 0.1; // 10% of borrowed amount if not repaid
                }
                ProtocolOperation::BridgeWithdraw { amount, .. } => {
                    profit += amount * 0.05; // 5% bridge exploit
                }
                _ => {}
            }
        }

        profit
    }

    /// Extract unique contracts from an operation sequence.
    fn extract_involved_contracts(&self, operations: &[ProtocolOperation]) -> Vec<String> {
        let mut contracts = std::collections::HashSet::new();

        for op in operations {
            match op {
                ProtocolOperation::Swap { pool, .. } => {
                    contracts.insert(pool.clone());
                }
                ProtocolOperation::AddLiquidity { pool, .. } => {
                    contracts.insert(pool.clone());
                }
                ProtocolOperation::RemoveLiquidity { pool, .. } => {
                    contracts.insert(pool.clone());
                }
                ProtocolOperation::Deposit { pool, .. } => {
                    contracts.insert(pool.clone());
                }
                ProtocolOperation::Borrow { pool, .. } => {
                    contracts.insert(pool.clone());
                }
                ProtocolOperation::Repay { pool, .. } => {
                    contracts.insert(pool.clone());
                }
                ProtocolOperation::Transfer { token, .. } => {
                    contracts.insert(token.clone());
                }
                ProtocolOperation::GovernanceVote { governance, .. } => {
                    contracts.insert(governance.clone());
                }
                ProtocolOperation::BridgeDeposit { bridge, .. } => {
                    contracts.insert(bridge.clone());
                }
                ProtocolOperation::BridgeWithdraw { bridge, .. } => {
                    contracts.insert(bridge.clone());
                }
            }
        }

        contracts.into_iter().collect()
    }

    /// Classify exploit difficulty.
    fn classify_difficulty(&self, operations: &[ProtocolOperation]) -> ExploitDifficulty {
        let unique_contracts = self.extract_involved_contracts(operations);
        let cross_contract_ops = operations
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    ProtocolOperation::Swap { .. }
                        | ProtocolOperation::BridgeDeposit { .. }
                        | ProtocolOperation::BridgeWithdraw { .. }
                )
            })
            .count();

        match (unique_contracts.len(), cross_contract_ops, operations.len()) {
            (1, 0, ..) => ExploitDifficulty::Easy,
            (2, 1..=3, ..) => ExploitDifficulty::Medium,
            (3..=5, 4..=10, ..) => ExploitDifficulty::Hard,
            _ => ExploitDifficulty::VeryHard,
        }
    }

    /// Generate mitigation recommendations.
    fn generate_mitigations(&self, invariant_name: &str) -> Vec<String> {
        vec![
            format!(
                "Implement reentrancy guard for invariant '{}'",
                invariant_name
            ),
            format!(
                "Add invariant check before and after all state modifications affecting '{}'",
                invariant_name
            ),
            "Use checks-effects-interactions pattern".to_string(),
            "Consider circuit breakers for critical invariants".to_string(),
        ]
    }

    /// Check for sandwich attack vulnerabilities.
    fn check_sandwich_attacks(&self) -> Option<AdversarialExploit> {
        // Check if there are AMM pools that are vulnerable to sandwich attacks
        let has_amm = self.manifest.contracts.iter().any(|c| {
            matches!(
                c.role,
                crate::protocol_analysis::manifest::ContractRole::AmmPool
            )
        });

        if has_amm {
            Some(AdversarialExploit {
                name: "Sandwich Attack on AMM Pools".to_string(),
                violated_invariant: "constant_product".to_string(),
                operation_sequence: vec![],
                estimated_profit: 100_000.0,
                involved_contracts: self.manifest.contracts.iter()
                    .filter(|c| matches!(c.role, crate::protocol_analysis::manifest::ContractRole::AmmPool | crate::protocol_analysis::manifest::ContractRole::Token))
                    .map(|c| c.name.clone())
                    .collect(),
                difficulty: ExploitDifficulty::Medium,
                description: "An attacker can front-run a large swap, causing the victim to receive fewer tokens, then sell the tokens back at a profit after the victim's transaction moves the price.".to_string(),
                mitigations: vec![
                    "Implement minimum output amount checks".to_string(),
                    "Use commit-reveal schemes for large swaps".to_string(),
                    "Consider time-weighted average price (TWAP) oracles".to_string(),
                ],
            })
        } else {
            None
        }
    }

    /// Check for flash loan attack vulnerabilities.
    fn check_flash_loan_attacks(&self) -> Option<AdversarialExploit> {
        // Check if there's a lending pool that could be exploited with flash loans
        let has_lending = self.manifest.contracts.iter().any(|c| {
            matches!(
                c.role,
                crate::protocol_analysis::manifest::ContractRole::LendingPool
            )
        });

        let has_amm = self.manifest.contracts.iter().any(|c| {
            matches!(
                c.role,
                crate::protocol_analysis::manifest::ContractRole::AmmPool
            )
        });

        if has_lending && has_amm {
            Some(AdversarialExploit {
                name: "Flash Loan Orchestrated Manipulation".to_string(),
                violated_invariant: "lending_solvency".to_string(),
                operation_sequence: vec![],
                estimated_profit: 500_000.0,
                involved_contracts: self.manifest.contracts.iter()
                    .filter(|c| matches!(c.role, crate::protocol_analysis::manifest::ContractRole::LendingPool | crate::protocol_analysis::manifest::ContractRole::AmmPool))
                    .map(|c| c.name.clone())
                    .collect(),
                difficulty: ExploitDifficulty::Hard,
                description: "An attacker can use a flash loan to manipulate AMM pool prices, then exploit lending pools that use the manipulated price as an oracle, draining funds before repaying the flash loan.".to_string(),
                mitigations: vec![
                    "Use TWAP oracles instead of spot prices".to_string(),
                    "Implement circuit breakers for large price movements".to_string(),
                    "Add delay mechanisms for critical operations".to_string(),
                ],
            })
        } else {
            None
        }
    }
}

impl std::fmt::Display for ExploitDifficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExploitDifficulty::Easy => write!(f, "EASY"),
            ExploitDifficulty::Medium => write!(f, "MEDIUM"),
            ExploitDifficulty::Hard => write!(f, "HARD"),
            ExploitDifficulty::VeryHard => write!(f, "VERY HARD"),
        }
    }
}
