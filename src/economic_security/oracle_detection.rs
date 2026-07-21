//! Oracle Manipulation Detection (#444 — Phase 4)
//!
//! Detects when a protocol uses a spot price from an AMM pool as an oracle
//! and tests whether an attacker can manipulate the price to extract value.

use super::defi_primitives::{ConstantProductAmm, Oracle, OracleType};
use serde::{Deserialize, Serialize};

/// Price deviation measured during a manipulation scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceDeviation {
    pub asset_pair: String,
    pub price_before: f64,
    pub price_after: f64,
    pub deviation_bps: u16,
    pub is_significant: bool,
}

/// A complete oracle manipulation scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleManipulationScenario {
    pub oracle_id: String,
    pub pool_id: String,
    pub manipulated_asset: String,
    pub swap_amount: u128,
    pub price_deviation: PriceDeviation,
    pub required_capital: u128,
    pub estimated_profit: f64,
    pub is_exploitable: bool,
}

/// Detects oracle manipulation vulnerabilities.
pub struct OracleManipulationDetector {
    threshold_bps: u16,
}

impl OracleManipulationDetector {
    pub fn new(threshold_bps: u16) -> Self {
        Self { threshold_bps }
    }

    /// Detect if oracle manipulation is possible for a given pool-oracle pair.
    pub fn detect(
        &self,
        pool: &ConstantProductAmm,
        oracle: &Oracle,
    ) -> Vec<OracleManipulationScenario> {
        let mut scenarios = Vec::new();

        // Skip non-spot oracles (TWAP, Chainlink are harder to manipulate)
        if oracle.oracle_type != OracleType::Spot {
            return scenarios;
        }

        // Calculate the swap amount needed to move the price beyond threshold
        let swap_amount = self.required_swap_for_deviation(pool, self.threshold_bps);

        // Check manipulation from both directions
        for token in [&pool.token_a, &pool.token_b] {
            let (price_before, price_after) = self.simulate_price_impact(pool, swap_amount, token);

            let deviation_bps = if price_before > 0.0 {
                ((price_before - price_after).abs() / price_before * 10000.0) as u16
            } else {
                0
            };

            let is_significant = deviation_bps >= self.threshold_bps;

            if is_significant {
                let scenario = OracleManipulationScenario {
                    oracle_id: oracle.id.clone(),
                    pool_id: pool.id.clone(),
                    manipulated_asset: token.clone(),
                    swap_amount,
                    price_deviation: PriceDeviation {
                        asset_pair: oracle.asset_pair.clone(),
                        price_before,
                        price_after,
                        deviation_bps,
                        is_significant: true,
                    },
                    required_capital: swap_amount,
                    estimated_profit: self.estimate_manipulation_profit(
                        pool,
                        oracle,
                        swap_amount,
                        token,
                    ),
                    is_exploitable: true,
                };
                scenarios.push(scenario);
            }
        }

        scenarios
    }

    /// Calculate the swap amount needed to move price by threshold_bps.
    fn required_swap_for_deviation(
        &self,
        pool: &ConstantProductAmm,
        target_bps: u16,
    ) -> u128 {
        // Binary search for swap amount
        let mut low: u128 = 0;
        let mut high: u128 = pool.reserve_a.max(pool.reserve_b);

        for _ in 0..60 {
            let mid = (low + high) / 2;
            if mid == 0 {
                break;
            }
            match pool.price_impact_bps(mid, &pool.token_a) {
                Ok(impact) if impact >= target_bps => high = mid,
                _ => low = mid,
            }
        }
        high
    }

    fn simulate_price_impact(
        &self,
        pool: &ConstantProductAmm,
        amount: u128,
        token: &str,
    ) -> (f64, f64) {
        let price_before = if token == pool.token_a {
            pool.spot_price_a_in_b()
        } else {
            pool.spot_price_b_in_a()
        };

        let amount_out = pool.get_amount_out(amount, token).unwrap_or(0);

        let (new_reserve_a, new_reserve_b) = if token == pool.token_a {
            (pool.reserve_a + amount, pool.reserve_b - amount_out)
        } else {
            (pool.reserve_a - amount_out, pool.reserve_b + amount)
        };

        let price_after = if token == pool.token_a {
            if new_reserve_a == 0 {
                0.0
            } else {
                new_reserve_b as f64 / new_reserve_a as f64
            }
        } else {
            if new_reserve_b == 0 {
                0.0
            } else {
                new_reserve_a as f64 / new_reserve_b as f64
            }
        };

        (price_before, price_after)
    }

    /// Estimate profit from manipulation (simplified model).
    fn estimate_manipulation_profit(
        &self,
        pool: &ConstantProductAmm,
        _oracle: &Oracle,
        amount: u128,
        token: &str,
    ) -> f64 {
        // In a real exploit, profit comes from:
        // 1. Swap to move price
        // 2. Trigger protocol operation using manipulated price
        // 3. Reverse swap
        // Simplified: profit ≈ arbitrage opportunity created by the deviation

        let amount_out_initial = pool.get_amount_out(amount, token).unwrap_or(0) as f64;

        // Simulate the reverse swap
        let fee_loss = amount as f64 * pool.swap_fee_bps as f64 / 10000.0;
        let estimated_profit = amount_out_initial - amount as f64 - fee_loss;

        estimated_profit
    }
}
