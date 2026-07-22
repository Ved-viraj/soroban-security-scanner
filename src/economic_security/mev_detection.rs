//! MEV Sandwich Detection (#444 — Phase 5)
//!
//! Models a ledger close as a sequence of transactions and detects
//! sandwich attack opportunities. Accounts for Stellar's fixed fee
//! model (no priority gas auctions) and 3-5 second ledger close windows.

use serde::{Deserialize, Serialize};

/// Types of MEV opportunities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MevType {
    /// Front-run + User trade + Back-run
    SandwichAttack,
    /// Front-run only (same-direction trade)
    FrontRunning,
    /// Back-run only (opposite-direction after large trade)
    BackRunning,
    /// Arbitrage between pools
    CrossPoolArbitrage,
    /// Liquidations
    Liquidation,
}

/// Ordering of transactions relative to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionOrder {
    Before, // Front-run
    After,  // Back-run
}

/// A sandwich attack detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandwichAttack {
    pub target_tx_hash: String,
    pub pool_id: String,
    pub front_run_amount: u128,
    pub user_amount: u128,
    pub back_run_amount: u128,
    pub attacker_profit: f64,
    pub user_loss: f64,
    pub gas_cost: u64,
    pub is_profitable: bool,
}

/// A detected MEV opportunity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevOpportunity {
    pub mev_type: MevType,
    pub pool_id: String,
    pub asset: String,
    pub estimated_profit: f64,
    pub gas_cost: u64,
    pub ledger_close_window_ms: u64,
    pub is_exploitable: bool,
    pub sandwich: Option<SandwichAttack>,
}

/// Detects MEV opportunities in transaction sequences.
pub struct MevDetector {
    /// Minimum profit in XLM to report.
    min_profit_threshold: f64,
    /// Fixed transaction fee on Stellar (100 stroops = 0.00001 XLM).
    base_fee: u64,
}

impl MevDetector {
    pub fn new(min_profit_threshold: f64) -> Self {
        Self {
            min_profit_threshold,
            base_fee: 100, // Stellar base fee
        }
    }

    /// Detect sandwich attack opportunities for a given user transaction.
    pub fn detect_sandwich(
        &self,
        user_trade_amount: u128,
        pool_reserve_a: u128,
        pool_reserve_b: u128,
        fee_bps: u16,
        is_buy: bool,
    ) -> Option<SandwichAttack> {
        // Model: attacker front-runs with a same-direction trade,
        // user trades at a worse price, attacker back-runs with opposite direction.
        let pool = super::defi_primitives::ConstantProductAmm {
            id: "target".into(),
            token_a: "A".into(),
            token_b: "B".into(),
            reserve_a: pool_reserve_a,
            reserve_b: pool_reserve_b,
            swap_fee_bps: fee_bps,
        };

        // Calculate optimal front-run amount (fraction of user trade)
        // Research shows optimal sandwich size ≈ 30-50% of victim trade
        let front_run_pct = 0.3;
        let front_run_amount = (user_trade_amount as f64 * front_run_pct) as u128;

        if front_run_amount == 0 {
            return None;
        }

        let token_in = if is_buy { &pool.token_a } else { &pool.token_b };

        // Simulate front-run
        let front_run_out = pool.get_amount_out(front_run_amount, token_in).ok()? as f64;
        // User trade at worse price (after front-run)
        let user_out = pool.get_amount_out(user_trade_amount, token_in).ok()? as f64;

        // Back-run (reverse the front-run direction)
        let back_run_out = pool.get_amount_out(front_run_out as u128, token_in).ok()? as f64;

        // Calculate profit
        let attacker_profit = back_run_out - front_run_amount as f64;
        let spot_price = if is_buy {
            pool.spot_price_a_in_b()
        } else {
            pool.spot_price_b_in_a()
        };
        let user_loss = (user_trade_amount as f64
            * (1.0 - user_out / (user_trade_amount as f64 * spot_price)))
            .abs();

        let gas_cost = self.base_fee * 3; // Three transactions: front-run, user, back-run
        let is_profitable = attacker_profit > self.min_profit_threshold;

        if attacker_profit > 0.0 || user_loss > 0.0 {
            Some(SandwichAttack {
                target_tx_hash: "simulated".to_string(),
                pool_id: pool.id,
                front_run_amount,
                user_amount: user_trade_amount,
                back_run_amount: back_run_out as u128,
                attacker_profit,
                user_loss,
                gas_cost,
                is_profitable,
            })
        } else {
            None
        }
    }

    /// Scan a list of simulated transactions for MEV opportunities.
    pub fn scan(
        &self,
        trades: &[(u128, u128, u128, bool)], // (user_amount, reserve_a, reserve_b, is_buy)
    ) -> Vec<MevOpportunity> {
        let mut opportunities = Vec::new();

        for (user_amount, reserve_a, reserve_b, is_buy) in trades {
            if let Some(sandwich) = self.detect_sandwich(
                *user_amount,
                *reserve_a,
                *reserve_b,
                30, // 0.3% fee
                *is_buy,
            ) {
                opportunities.push(MevOpportunity {
                    mev_type: MevType::SandwichAttack,
                    pool_id: "target_pool".into(),
                    asset: "XLM".into(),
                    estimated_profit: sandwich.attacker_profit,
                    gas_cost: sandwich.gas_cost,
                    ledger_close_window_ms: 4000, // Stellar average
                    is_exploitable: sandwich.is_profitable,
                    sandwich: Some(sandwich),
                });
            }
        }

        opportunities
    }
}
