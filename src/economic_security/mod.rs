//! Economic Exploit Simulation Framework (#444)
//!
//! Models Soroban DeFi protocols as systems of interacting agents with
//! economic incentives, then searches for sequences of transactions that
//! produce profitable attacks: flash loans, oracle manipulation, and MEV.
//!
//! This is the first economic-security analyzer built specifically for
//! the Stellar/Soroban ecosystem, accounting for fixed low fees, the
//! absence of a public mempool, and 3–5 second ledger close windows.

pub mod attack_agent;
pub mod defi_primitives;
pub mod flash_loan;
pub mod mev_detection;
pub mod oracle_detection;
pub mod profitability;
pub mod report;
pub mod search_engine;

#[cfg(test)]
mod tests;

pub use attack_agent::{AttackAgent, AttackCapability, AgentObjective};
pub use defi_primitives::{
    ConstantProductAmm, DeFiPrimitive, DeFiPrimitiveType, LendingPool, LiquidityPool, Oracle,
    OracleType, StateChange, StakingRewards, TwapOracle,
};
pub use flash_loan::{FlashLoanAttack, FlashLoanScenario, FlashLoanSimulator};
pub use mev_detection::{MevDetector, MevOpportunity, MevType, SandwichAttack, TransactionOrder};
pub use oracle_detection::{OracleManipulationDetector, OracleManipulationScenario, PriceDeviation};
pub use profitability::{
    ExploitDifficulty, ExploitProfitability, ProfitabilityAnalyzer, ProfitabilityScore,
};
pub use report::{
    AttackSequence, EconomicExploitReport, EconomicExploitSummary, EconomicFinding,
};
pub use search_engine::{
    BeamSearch, GeneticAlgorithm, MonteCarloTreeSearch, SearchAlgorithm, SearchConfig,
    SearchResult, TransactionSequence,
};
