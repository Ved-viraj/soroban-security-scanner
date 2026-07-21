//! Attack Agent Model (#444 — Phase 2)
//!
//! Defines the attacker agent with flash loan execution, trade submission,
//! oracle manipulation, transaction reordering, and temporary contract
//! deployment capabilities. The agent's objective is profit maximization.

use serde::{Deserialize, Serialize};

/// Capabilities available to the attack agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackCapability {
    /// Take a flash loan from any lending pool.
    FlashLoan,
    /// Submit swap/trade transactions to AMM pools.
    Swap,
    /// Manipulate oracle prices via trades within TWAP window.
    OracleManipulation,
    /// Reorder transactions within a ledger close.
    TransactionReordering,
    /// Deploy temporary contracts for complex multi-step attacks.
    TemporaryContractDeployment,
    /// Provide liquidity to manipulate pool ratios.
    LiquidityProvision,
    /// Borrow from lending pools.
    Borrow,
    /// Repay loans.
    Repay,
}

impl AttackCapability {
    pub fn description(&self) -> &'static str {
        match self {
            Self::FlashLoan => "Execute flash loans (borrow + repay within same transaction)",
            Self::Swap => "Submit swap/trade transactions to AMM pools",
            Self::OracleManipulation => "Manipulate oracle prices through trades",
            Self::TransactionReordering => "Reorder transactions within a ledger close (MEV)",
            Self::TemporaryContractDeployment => "Deploy temporary contracts for complex attack logic",
            Self::LiquidityProvision => "Provide/remove liquidity to manipulate pool ratios",
            Self::Borrow => "Borrow assets from lending pools",
            Self::Repay => "Repay borrowed assets",
        }
    }

    /// Stellar-specific gas cost estimate for this capability (in stroops).
    pub fn gas_cost_estimate(&self) -> u64 {
        match self {
            Self::FlashLoan => 500_000,
            Self::Swap => 200_000,
            Self::OracleManipulation => 300_000,
            Self::TransactionReordering => 0, // No direct gas cost
            Self::TemporaryContractDeployment => 1_000_000,
            Self::LiquidityProvision => 400_000,
            Self::Borrow => 300_000,
            Self::Repay => 150_000,
        }
    }
}

/// The objective function for the attack agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentObjective {
    /// Target profit in the base asset.
    pub target_profit: u128,
    /// Maximum gas budget in stroops.
    pub max_gas_budget: u64,
    /// Maximum number of transactions in the attack sequence.
    pub max_transactions: usize,
    /// Time window in seconds (for Stellar: 3-5 second ledger close).
    pub time_window_seconds: u64,
}

impl Default for AgentObjective {
    fn default() -> Self {
        Self {
            target_profit: 0,       // Find any profitable attack
            max_gas_budget: 10_000_000,
            max_transactions: 10,
            time_window_seconds: 5, // Stellar ledger close window
        }
    }
}

/// The attack agent that searches for profitable exploits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackAgent {
    pub capabilities: Vec<AttackCapability>,
    pub initial_balance: u128,
    pub objective: AgentObjective,
    pub current_balance: u128,
    pub total_gas_spent: u64,
    pub executed_actions: Vec<AgentAction>,
}

/// An action taken by the agent during an attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    pub capability: AttackCapability,
    pub target: String,        // Pool/Oracle/Contract ID
    pub amount: u128,
    pub token: String,
    pub timestamp: u64,
}

impl AttackAgent {
    pub fn new(
        capabilities: Vec<AttackCapability>,
        initial_balance: u128,
    ) -> Self {
        Self {
            capabilities,
            initial_balance,
            objective: AgentObjective::default(),
            current_balance: initial_balance,
            total_gas_spent: 0,
            executed_actions: Vec::new(),
        }
    }

    /// Compute the agent's profit (after gas costs).
    pub fn net_profit(&self, gas_cost_stroops: u64, xlm_per_stroop: f64) -> f64 {
        let gross = self.current_balance as f64 - self.initial_balance as f64;
        let gas_cost_xlm = gas_cost_stroops as f64 * xlm_per_stroop;
        gross - gas_cost_xlm
    }

    /// Check if an action is within gas budget.
    pub fn within_gas_budget(&self, action: &AgentAction) -> bool {
        let action_cost = action.capability.gas_cost_estimate();
        self.total_gas_spent + action_cost <= self.objective.max_gas_budget
    }

    /// Record an executed action.
    pub fn record_action(&mut self, action: AgentAction) {
        let gas = action.capability.gas_cost_estimate();
        self.total_gas_spent += gas;
        self.executed_actions.push(action);
    }

    /// Check if the attack is complete (objective met or budget exhausted).
    pub fn is_complete(&self) -> bool {
        let profit = self.current_balance as i128 - self.initial_balance as i128;
        profit >= self.objective.target_profit as i128
            || self.total_gas_spent >= self.objective.max_gas_budget
            || self.executed_actions.len() >= self.objective.max_transactions
    }

    /// Reset the agent for a new attack attempt.
    pub fn reset(&mut self) {
        self.current_balance = self.initial_balance;
        self.total_gas_spent = 0;
        self.executed_actions.clear();
    }
}
