//! Phase 4 — Dynamic Protocol Simulation.
//!
//! For economic invariants (those that depend on market dynamics), build a
//! protocol simulator that:
//! 1. Initializes all contracts with the protocol's genesis state
//! 2. Generates random sequences of user operations (swaps, deposits, borrows, etc.)
//! 3. After each operation, checks all protocol invariants
//! 4. If an invariant is violated, records the operation sequence that triggered it
//!
//! Runs for N steps (default 100,000) and reports any invariant violations.

use crate::protocol_analysis::manifest::{Expression, InvariantSpec, ProtocolManifest};
use rand::Rng;
use std::collections::HashMap;

/// Configuration for dynamic simulation.
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Number of random operations to simulate (default 100,000).
    pub num_steps: u64,
    /// Number of user agents to simulate.
    pub num_users: u32,
    /// Probability of each operation type.
    pub operation_weights: OperationWeights,
    /// Whether to stop on first violation.
    pub stop_on_first_violation: bool,
    /// Seed for reproducibility.
    pub seed: u64,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            num_steps: 100_000,
            num_users: 10,
            operation_weights: OperationWeights::default(),
            stop_on_first_violation: true,
            seed: 42,
        }
    }
}

/// Weights for random operation generation.
#[derive(Debug, Clone)]
pub struct OperationWeights {
    pub swap: f64,
    pub add_liquidity: f64,
    pub remove_liquidity: f64,
    pub deposit: f64,
    pub borrow: f64,
    pub repay: f64,
    pub transfer: f64,
    pub governance_vote: f64,
    pub bridge_deposit: f64,
    pub bridge_withdraw: f64,
}

impl Default for OperationWeights {
    fn default() -> Self {
        Self {
            swap: 0.25,
            add_liquidity: 0.10,
            remove_liquidity: 0.05,
            deposit: 0.15,
            borrow: 0.10,
            repay: 0.10,
            transfer: 0.15,
            governance_vote: 0.05,
            bridge_deposit: 0.025,
            bridge_withdraw: 0.025,
        }
    }
}

/// A simulated operation within the protocol.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ProtocolOperation {
    Swap {
        pool: String,
        user: u32,
        amount_in: f64,
        token_in: String,
        token_out: String,
    },
    AddLiquidity {
        pool: String,
        user: u32,
        amount_x: f64,
        amount_y: f64,
    },
    RemoveLiquidity {
        pool: String,
        user: u32,
        shares: f64,
    },
    Deposit {
        pool: String,
        user: u32,
        amount: f64,
    },
    Borrow {
        pool: String,
        user: u32,
        amount: f64,
    },
    Repay {
        pool: String,
        user: u32,
        amount: f64,
    },
    Transfer {
        token: String,
        from: u32,
        to: u32,
        amount: f64,
    },
    GovernanceVote {
        governance: String,
        user: u32,
        power: f64,
    },
    BridgeDeposit {
        bridge: String,
        user: u32,
        amount: f64,
    },
    BridgeWithdraw {
        bridge: String,
        user: u32,
        amount: f64,
    },
}

/// A sequence of operations that led to an invariant violation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OperationSequence {
    pub operations: Vec<ProtocolOperation>,
    pub violated_invariant: String,
    pub state_before: HashMap<String, f64>,
    pub state_after: HashMap<String, f64>,
}

/// Report from a simulation run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SimulationReport {
    pub total_steps: u64,
    pub violations_found: Vec<OperationSequence>,
    pub contracts_simulated: Vec<String>,
    pub invariants_checked: Vec<String>,
    pub coverage: SimulationCoverage,
    pub execution_time_ms: u64,
}

/// Coverage statistics about the simulation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SimulationCoverage {
    pub operations_executed: HashMap<String, u64>,
    pub unique_users_active: u32,
    pub contracts_interacted: Vec<String>,
    pub invariants_covered: Vec<String>,
    pub invariants_violated: Vec<String>,
}

/// A mutable protocol state for simulation.
#[derive(Debug, Clone)]
pub struct ProtocolState {
    /// Contract storage: contract_name -> key -> value
    pub storage: HashMap<String, HashMap<String, f64>>,
    /// Token balances: token_contract -> user -> balance
    pub balances: HashMap<String, HashMap<u32, f64>>,
    /// AMM reserves: pool -> (reserve_x, reserve_y, k)
    pub amm_pools: HashMap<String, AmmPoolState>,
    /// Lending state: pool -> {deposits, loans, liquidity, fees}
    pub lending_pools: HashMap<String, LendingPoolState>,
}

#[derive(Debug, Clone)]
pub struct AmmPoolState {
    pub reserve_x: f64,
    pub reserve_y: f64,
    pub k: f64,
    pub total_shares: f64,
    pub user_shares: HashMap<u32, f64>,
}

#[derive(Debug, Clone)]
pub struct LendingPoolState {
    pub total_deposits: f64,
    pub total_loans: f64,
    pub available_liquidity: f64,
    pub protocol_fees: f64,
    pub user_deposits: HashMap<u32, f64>,
    pub user_loans: HashMap<u32, f64>,
    pub interest_rate: f64,
}

/// The protocol simulator.
pub struct ProtocolSimulator {
    state: ProtocolState,
    config: SimulationConfig,
    manifest: ProtocolManifest,
    rng: rand::rngs::StdRng,
    operation_history: Vec<ProtocolOperation>,
    violations: Vec<OperationSequence>,
}

impl ProtocolSimulator {
    /// Create a new simulator for the given protocol.
    pub fn new(manifest: ProtocolManifest, config: SimulationConfig) -> Self {
        use rand::SeedableRng;

        let state = Self::initialize_state(&manifest);
        let rng = rand::rngs::StdRng::seed_from_u64(config.seed);

        Self {
            state,
            config,
            manifest,
            rng,
            operation_history: Vec::new(),
            violations: Vec::new(),
        }
    }

    /// Initialize protocol state from the manifest.
    fn initialize_state(manifest: &ProtocolManifest) -> ProtocolState {
        let mut storage = HashMap::new();
        let balances = HashMap::new();
        let mut amm_pools = HashMap::new();
        let mut lending_pools = HashMap::new();

        for contract in &manifest.contracts {
            let mut contract_storage = HashMap::new();

            match contract.role {
                crate::protocol_analysis::manifest::ContractRole::AmmPool => {
                    let initial_reserve_x = 1_000_000.0;
                    let initial_reserve_y = 1_000_000.0;
                    let k = initial_reserve_x * initial_reserve_y;

                    contract_storage.insert("reserve_x".to_string(), initial_reserve_x);
                    contract_storage.insert("reserve_y".to_string(), initial_reserve_y);
                    contract_storage.insert("k".to_string(), k);
                    contract_storage.insert("total_shares".to_string(), 1_000.0);

                    amm_pools.insert(
                        contract.name.clone(),
                        AmmPoolState {
                            reserve_x: initial_reserve_x,
                            reserve_y: initial_reserve_y,
                            k,
                            total_shares: 1_000.0,
                            user_shares: HashMap::new(),
                        },
                    );
                }
                crate::protocol_analysis::manifest::ContractRole::LendingPool => {
                    let initial_deposits = 5_000_000.0;
                    contract_storage.insert("total_deposits".to_string(), initial_deposits);
                    contract_storage.insert("total_loans".to_string(), 0.0);
                    contract_storage.insert("available_liquidity".to_string(), initial_deposits);
                    contract_storage.insert("protocol_fees".to_string(), 0.0);

                    lending_pools.insert(
                        contract.name.clone(),
                        LendingPoolState {
                            total_deposits: initial_deposits,
                            total_loans: 0.0,
                            available_liquidity: initial_deposits,
                            protocol_fees: 0.0,
                            user_deposits: HashMap::new(),
                            user_loans: HashMap::new(),
                            interest_rate: 0.05,
                        },
                    );
                }
                crate::protocol_analysis::manifest::ContractRole::Bridge => {
                    contract_storage.insert("locked_soroban".to_string(), 0.0);
                    contract_storage.insert("minted_counterpart".to_string(), 0.0);
                }
                crate::protocol_analysis::manifest::ContractRole::Governance => {
                    contract_storage.insert("total_voting_power".to_string(), 1_000_000.0);
                    contract_storage.insert("total_delegated_power".to_string(), 1_000_000.0);
                }
                _ => {}
            }

            storage.insert(contract.name.clone(), contract_storage);
        }

        ProtocolState {
            storage,
            balances,
            amm_pools,
            lending_pools,
        }
    }

    /// Run the simulation.
    pub fn run(&mut self) -> SimulationReport {
        let start = std::time::Instant::now();

        let invariants: Vec<InvariantSpec> = self.manifest.invariants.clone();
        let invariant_names: Vec<String> = invariants.iter().map(|i| i.name.clone()).collect();

        let mut operations_count: HashMap<String, u64> = HashMap::new();
        let mut active_users = std::collections::HashSet::new();

        for step in 0..self.config.num_steps {
            if self.config.stop_on_first_violation && !self.violations.is_empty() {
                break;
            }

            let operation = self.generate_random_operation();

            // Count by type
            let type_name = match &operation {
                ProtocolOperation::Swap { .. } => "swap",
                ProtocolOperation::AddLiquidity { .. } => "add_liquidity",
                ProtocolOperation::RemoveLiquidity { .. } => "remove_liquidity",
                ProtocolOperation::Deposit { .. } => "deposit",
                ProtocolOperation::Borrow { .. } => "borrow",
                ProtocolOperation::Repay { .. } => "repay",
                ProtocolOperation::Transfer { .. } => "transfer",
                ProtocolOperation::GovernanceVote { .. } => "governance_vote",
                ProtocolOperation::BridgeDeposit { .. } => "bridge_deposit",
                ProtocolOperation::BridgeWithdraw { .. } => "bridge_withdraw",
            };
            *operations_count.entry(type_name.to_string()).or_insert(0) += 1;

            // Track user
            match &operation {
                ProtocolOperation::Swap { user, .. }
                | ProtocolOperation::AddLiquidity { user, .. }
                | ProtocolOperation::RemoveLiquidity { user, .. }
                | ProtocolOperation::Deposit { user, .. }
                | ProtocolOperation::Borrow { user, .. }
                | ProtocolOperation::Repay { user, .. }
                | ProtocolOperation::Transfer { from: user, .. }
                | ProtocolOperation::GovernanceVote { user, .. }
                | ProtocolOperation::BridgeDeposit { user, .. }
                | ProtocolOperation::BridgeWithdraw { user, .. } => {
                    active_users.insert(*user);
                }
            }

            // Take snapshot of state before operation
            let state_before = self.capture_state_snapshot(&invariant_names);

            // Execute the operation
            self.execute_operation(&operation);

            // Check invariants
            for invariant in &invariants {
                if !self.check_invariant(invariant) {
                    let state_after = self.capture_state_snapshot(&invariant_names);

                    self.violations.push(OperationSequence {
                        operations: self.operation_history.clone(),
                        violated_invariant: invariant.name.clone(),
                        state_before: state_before.clone(),
                        state_after,
                    });

                    if self.config.stop_on_first_violation {
                        break;
                    }
                }
            }

            self.operation_history.push(operation);

            if step % 1000 == 0 && step > 0 {
                // Periodically print progress (in real implementation, use logging)
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;

        // Build coverage report
        let contracts_interacted: Vec<String> = self
            .state
            .amm_pools
            .keys()
            .chain(self.state.lending_pools.keys())
            .cloned()
            .collect();

        SimulationReport {
            total_steps: self.config.num_steps,
            violations_found: self.violations.clone(),
            contracts_simulated: contracts_interacted.clone(),
            invariants_checked: invariant_names.clone(),
            coverage: SimulationCoverage {
                operations_executed: operations_count,
                unique_users_active: active_users.len() as u32,
                contracts_interacted,
                invariants_covered: invariant_names
                    .iter()
                    .filter(|name| {
                        !self
                            .violations
                            .iter()
                            .any(|v| &v.violated_invariant == *name)
                    })
                    .cloned()
                    .collect(),
                invariants_violated: self
                    .violations
                    .iter()
                    .map(|v| v.violated_invariant.clone())
                    .collect(),
            },
            execution_time_ms: elapsed,
        }
    }

    /// Generate a random operation based on configured weights.
    fn generate_random_operation(&mut self) -> ProtocolOperation {
        let roll: f64 = self.rng.gen();
        let weights = &self.config.operation_weights;
        let user = self.rng.gen_range(0..self.config.num_users);
        let amount = self.rng.gen_range(1.0..10_000.0);

        // Pick a random pool or contract
        let pools: Vec<String> = self.state.amm_pools.keys().cloned().collect();
        let lending_pools: Vec<String> = self.state.lending_pools.keys().cloned().collect();
        let bridges: Vec<String> = self
            .manifest
            .contracts
            .iter()
            .filter(|c| {
                matches!(
                    c.role,
                    crate::protocol_analysis::manifest::ContractRole::Bridge
                )
            })
            .map(|c| c.name.clone())
            .collect();

        let mut cumulative = 0.0;

        cumulative += weights.swap;
        if roll < cumulative && !pools.is_empty() {
            let pool = pools[self.rng.gen_range(0..pools.len())].clone();
            return ProtocolOperation::Swap {
                pool,
                user,
                amount_in: amount,
                token_in: "token_x".to_string(),
                token_out: "token_y".to_string(),
            };
        }

        cumulative += weights.add_liquidity;
        if roll < cumulative && !pools.is_empty() {
            let pool = pools[self.rng.gen_range(0..pools.len())].clone();
            return ProtocolOperation::AddLiquidity {
                pool,
                user,
                amount_x: amount,
                amount_y: amount,
            };
        }

        cumulative += weights.remove_liquidity;
        if roll < cumulative && !pools.is_empty() {
            let pool = pools[self.rng.gen_range(0..pools.len())].clone();
            return ProtocolOperation::RemoveLiquidity {
                pool,
                user,
                shares: amount / 100.0,
            };
        }

        cumulative += weights.deposit;
        if roll < cumulative && !lending_pools.is_empty() {
            let pool = lending_pools[self.rng.gen_range(0..lending_pools.len())].clone();
            return ProtocolOperation::Deposit { pool, user, amount };
        }

        cumulative += weights.borrow;
        if roll < cumulative && !lending_pools.is_empty() {
            let pool = lending_pools[self.rng.gen_range(0..lending_pools.len())].clone();
            return ProtocolOperation::Borrow {
                pool,
                user,
                amount: amount.min(1000.0),
            };
        }

        cumulative += weights.repay;
        if roll < cumulative && !lending_pools.is_empty() {
            let pool = lending_pools[self.rng.gen_range(0..lending_pools.len())].clone();
            return ProtocolOperation::Repay { pool, user, amount };
        }

        cumulative += weights.transfer;
        if roll < cumulative {
            let to_user = self.rng.gen_range(0..self.config.num_users);
            return ProtocolOperation::Transfer {
                token: "token".to_string(),
                from: user,
                to: to_user,
                amount,
            };
        }

        cumulative += weights.governance_vote;
        if roll < cumulative {
            return ProtocolOperation::GovernanceVote {
                governance: "governance".to_string(),
                user,
                power: amount,
            };
        }

        cumulative += weights.bridge_deposit;
        if roll < cumulative && !bridges.is_empty() {
            let bridge = bridges[0].clone();
            return ProtocolOperation::BridgeDeposit {
                bridge,
                user,
                amount,
            };
        }

        // Default: swap
        if !pools.is_empty() {
            let pool = pools[self.rng.gen_range(0..pools.len())].clone();
            ProtocolOperation::Swap {
                pool,
                user,
                amount_in: amount,
                token_in: "token_x".to_string(),
                token_out: "token_y".to_string(),
            }
        } else {
            ProtocolOperation::Transfer {
                token: "token".to_string(),
                from: user,
                to: (user + 1) % self.config.num_users,
                amount,
            }
        }
    }

    /// Execute a single operation, updating protocol state.
    fn execute_operation(&mut self, op: &ProtocolOperation) {
        match op {
            ProtocolOperation::Swap {
                pool, amount_in, ..
            } => {
                if let Some(pool_state) = self.state.amm_pools.get_mut(pool) {
                    // Simple constant product swap: x * y = k
                    let fee = amount_in * 0.003; // 0.3% fee
                    let amount_in_after_fee = amount_in - fee;
                    let new_reserve_x = pool_state.reserve_x + amount_in_after_fee;
                    let new_reserve_y = pool_state.k / new_reserve_x;
                    let _amount_out = pool_state.reserve_y - new_reserve_y;

                    pool_state.reserve_x = new_reserve_x;
                    pool_state.reserve_y = new_reserve_y;
                    pool_state.k = new_reserve_x * new_reserve_y; // slight drift due to rounding
                }
            }
            ProtocolOperation::AddLiquidity {
                pool,
                amount_x,
                amount_y,
                ..
            } => {
                if let Some(pool_state) = self.state.amm_pools.get_mut(pool) {
                    let shares = (amount_x / pool_state.reserve_x)
                        .min(amount_y / pool_state.reserve_y)
                        * pool_state.total_shares;
                    pool_state.reserve_x += amount_x;
                    pool_state.reserve_y += amount_y;
                    pool_state.k = pool_state.reserve_x * pool_state.reserve_y;
                    pool_state.total_shares += shares;
                }
            }
            ProtocolOperation::RemoveLiquidity { pool, shares, .. } => {
                if let Some(pool_state) = self.state.amm_pools.get_mut(pool) {
                    let ratio = *shares / pool_state.total_shares;
                    let amount_x = pool_state.reserve_x * ratio;
                    let amount_y = pool_state.reserve_y * ratio;
                    pool_state.reserve_x -= amount_x;
                    pool_state.reserve_y -= amount_y;
                    pool_state.k = pool_state.reserve_x * pool_state.reserve_y;
                    pool_state.total_shares -= shares;
                }
            }
            ProtocolOperation::Deposit { pool, user, amount } => {
                if let Some(lending_state) = self.state.lending_pools.get_mut(pool) {
                    lending_state.total_deposits += amount;
                    lending_state.available_liquidity += amount;
                    *lending_state.user_deposits.entry(*user).or_insert(0.0) += amount;
                    if let Some(storage) = self.state.storage.get_mut(pool) {
                        storage.insert("total_deposits".to_string(), lending_state.total_deposits);
                        storage.insert(
                            "available_liquidity".to_string(),
                            lending_state.available_liquidity,
                        );
                    }
                }
            }
            ProtocolOperation::Borrow { pool, user, amount } => {
                if let Some(lending_state) = self.state.lending_pools.get_mut(pool) {
                    let max_borrow = lending_state.available_liquidity * 0.8; // 80% LTV
                    let borrow_amount = (*amount).min(max_borrow);

                    lending_state.total_loans += borrow_amount;
                    lending_state.available_liquidity -= borrow_amount;
                    *lending_state.user_loans.entry(*user).or_insert(0.0) += borrow_amount;
                    if let Some(storage) = self.state.storage.get_mut(pool) {
                        storage.insert("total_loans".to_string(), lending_state.total_loans);
                        storage.insert(
                            "available_liquidity".to_string(),
                            lending_state.available_liquidity,
                        );
                    }
                }
            }
            ProtocolOperation::Repay { pool, user, amount } => {
                if let Some(lending_state) = self.state.lending_pools.get_mut(pool) {
                    let user_loan = lending_state.user_loans.get(user).copied().unwrap_or(0.0);
                    let repay_amount = (*amount).min(user_loan);

                    lending_state.total_loans -= repay_amount;
                    lending_state.available_liquidity += repay_amount;
                    if let Some(user_loan_val) = lending_state.user_loans.get_mut(user) {
                        *user_loan_val -= repay_amount;
                    }
                    if let Some(storage) = self.state.storage.get_mut(pool) {
                        storage.insert("total_loans".to_string(), lending_state.total_loans);
                        storage.insert(
                            "available_liquidity".to_string(),
                            lending_state.available_liquidity,
                        );
                    }
                }
            }
            ProtocolOperation::BridgeDeposit { bridge, amount, .. } => {
                if let Some(storage) = self.state.storage.get_mut(bridge) {
                    let locked = storage.get("locked_soroban").copied().unwrap_or(0.0) + amount;
                    storage.insert("locked_soroban".to_string(), locked);
                }
            }
            ProtocolOperation::BridgeWithdraw { bridge, amount, .. } => {
                if let Some(storage) = self.state.storage.get_mut(bridge) {
                    let locked = storage.get("locked_soroban").copied().unwrap_or(0.0);
                    let withdraw_amount = (*amount).min(locked);
                    let new_locked = locked - withdraw_amount;
                    storage.insert("locked_soroban".to_string(), new_locked);

                    // Bridge minting on counterpart chain
                    let minted = storage.get("minted_counterpart").copied().unwrap_or(0.0);
                    storage.insert("minted_counterpart".to_string(), minted + withdraw_amount);
                }
            }
            ProtocolOperation::GovernanceVote { governance, .. } => {
                if let Some(storage) = self.state.storage.get_mut(governance) {
                    // Delegated power changes with votes
                    let total_power = storage.get("total_voting_power").copied().unwrap_or(0.0);
                    storage.insert("total_delegated_power".to_string(), total_power);
                }
            }
            ProtocolOperation::Transfer {
                token,
                from,
                to,
                amount,
            } => {
                // Simple balance transfer
                let balance_key_from = format!("balance_{}", from);
                let balance_key_to = format!("balance_{}", to);
                if let Some(storage) = self.state.storage.get_mut(token) {
                    let bal_from = storage.get(&balance_key_from).copied().unwrap_or(100_000.0);
                    let bal_to = storage.get(&balance_key_to).copied().unwrap_or(100_000.0);
                    let transfer_amount = (*amount).min(bal_from);
                    storage.insert(balance_key_from, bal_from - transfer_amount);
                    storage.insert(balance_key_to, bal_to + transfer_amount);
                }
            }
        }
    }

    /// Check if an invariant holds in the current state.
    fn check_invariant(&self, invariant: &InvariantSpec) -> bool {
        self.evaluate_expression(&invariant.expression)
    }

    /// Evaluate an expression and return whether it's true.
    fn evaluate_expression(&self, expr: &Expression) -> bool {
        match expr {
            Expression::Eq { left, right } => {
                let l = self.evaluate_numeric(left);
                let r = self.evaluate_numeric(right);
                (l - r).abs() < 0.001 // Allow small rounding errors
            }
            Expression::Neq { left, right } => {
                let l = self.evaluate_numeric(left);
                let r = self.evaluate_numeric(right);
                (l - r).abs() >= 0.001
            }
            Expression::Gte { left, right } => {
                let l = self.evaluate_numeric(left);
                let r = self.evaluate_numeric(right);
                l >= r - 0.001
            }
            Expression::Lte { left, right } => {
                let l = self.evaluate_numeric(left);
                let r = self.evaluate_numeric(right);
                l <= r + 0.001
            }
            Expression::Gt { left, right } => {
                let l = self.evaluate_numeric(left);
                let r = self.evaluate_numeric(right);
                l > r + 0.001
            }
            Expression::Lt { left, right } => {
                let l = self.evaluate_numeric(left);
                let r = self.evaluate_numeric(right);
                l < r - 0.001
            }
            Expression::And { left, right } => {
                self.evaluate_expression(left) && self.evaluate_expression(right)
            }
            Expression::Or { left, right } => {
                self.evaluate_expression(left) || self.evaluate_expression(right)
            }
            Expression::Not(inner) => !self.evaluate_expression(inner),
            Expression::Bool(val) => *val,
            _ => true, // Complex expressions default to true
        }
    }

    /// Evaluate a numeric expression.
    fn evaluate_numeric(&self, expr: &Expression) -> f64 {
        match expr {
            Expression::Literal(val) => *val,
            Expression::Storage { contract, key } => self
                .state
                .storage
                .get(contract.as_str())
                .and_then(|s| s.get(key.as_str()))
                .copied()
                .unwrap_or(0.0),
            Expression::Add { left, right } => {
                self.evaluate_numeric(left) + self.evaluate_numeric(right)
            }
            Expression::Sub { left, right } => {
                self.evaluate_numeric(left) - self.evaluate_numeric(right)
            }
            Expression::Mul { left, right } => {
                self.evaluate_numeric(left) * self.evaluate_numeric(right)
            }
            Expression::Div { left, right } => {
                let r = self.evaluate_numeric(right);
                if r == 0.0 {
                    0.0
                } else {
                    self.evaluate_numeric(left) / r
                }
            }
            Expression::Sum(items) => items.iter().map(|item| self.evaluate_numeric(item)).sum(),
            Expression::Reserve { pool, token } => {
                if let Some(amm) = self.state.amm_pools.get(pool.as_str()) {
                    if token.as_str().contains("x") {
                        amm.reserve_x
                    } else {
                        amm.reserve_y
                    }
                } else {
                    self.state
                        .storage
                        .get(pool.as_str())
                        .and_then(|s| s.get(format!("reserve_{}", token).as_str()))
                        .copied()
                        .unwrap_or(0.0)
                }
            }
            Expression::ConstantK { pool } => self
                .state
                .amm_pools
                .get(pool.as_str())
                .map(|a| a.k)
                .or_else(|| {
                    self.state
                        .storage
                        .get(pool.as_str())
                        .and_then(|s| s.get("k"))
                        .copied()
                })
                .unwrap_or(0.0),
            Expression::TotalSupply { token } => self
                .state
                .storage
                .get(token.as_str())
                .and_then(|s| s.get("total_supply"))
                .copied()
                .unwrap_or(1_000_000.0),
            Expression::TotalDeposits { pool } => self
                .state
                .lending_pools
                .get(pool.as_str())
                .map(|l| l.total_deposits)
                .or_else(|| {
                    self.state
                        .storage
                        .get(pool.as_str())
                        .and_then(|s| s.get("total_deposits"))
                        .copied()
                })
                .unwrap_or(0.0),
            Expression::TotalLoans { pool } => self
                .state
                .lending_pools
                .get(pool.as_str())
                .map(|l| l.total_loans)
                .or_else(|| {
                    self.state
                        .storage
                        .get(pool.as_str())
                        .and_then(|s| s.get("total_loans"))
                        .copied()
                })
                .unwrap_or(0.0),
            Expression::LockedSoroban { bridge } => self
                .state
                .storage
                .get(bridge.as_str())
                .and_then(|s| s.get("locked_soroban"))
                .copied()
                .unwrap_or(0.0),
            Expression::MintedCounterpart { bridge } => self
                .state
                .storage
                .get(bridge.as_str())
                .and_then(|s| s.get("minted_counterpart"))
                .copied()
                .unwrap_or(0.0),
            _ => 0.0,
        }
    }

    /// Capture a snapshot of current state values for invariant tracking.
    fn capture_state_snapshot(&self, invariant_names: &[String]) -> HashMap<String, f64> {
        let mut snapshot = HashMap::new();

        for name in invariant_names {
            if let Some(invariant) = self.manifest.invariants.iter().find(|i| &i.name == name) {
                let value = self.evaluate_numeric(&invariant.expression);
                snapshot.insert(name.clone(), value);
            }
        }

        // Also capture key storage values
        for (contract, storage) in &self.state.storage {
            for (key, value) in storage {
                snapshot.insert(format!("{}::{}", contract, key), *value);
            }
        }

        snapshot
    }
}
