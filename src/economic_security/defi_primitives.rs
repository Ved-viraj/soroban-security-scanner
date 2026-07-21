//! DeFi Primitives Library (#444 — Phase 1)
//!
//! Configurable models of DeFi building blocks: AMM pools, lending pools,
//! oracles, staking rewards, and governance tokens. Each primitive exposes
//! a `simulate(operation) -> StateChange` interface for the exploit search engine.

use serde::{Deserialize, Serialize};

// ── DeFi Primitive Types ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeFiPrimitiveType {
    ConstantProductAmm,
    StableswapPool,
    LendingPool,
    TwapOracle,
    SpotOracle,
    StakingRewards,
    GovernanceToken,
}

/// Represents a change in a primitive's state after an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub primitive_id: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Common trait for all DeFi primitives.
pub trait DeFiPrimitive {
    fn primitive_type(&self) -> DeFiPrimitiveType;
    fn id(&self) -> &str;
    fn simulate_swap(
        &self,
        token_in: &str,
        amount_in: u128,
    ) -> Result<u128, String>;
}

// ── Constant Product AMM (x*y=k) ─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantProductAmm {
    pub id: String,
    pub token_a: String,
    pub token_b: String,
    pub reserve_a: u128,
    pub reserve_b: u128,
    pub swap_fee_bps: u16, // Basis points (e.g. 30 = 0.3%)
}

impl ConstantProductAmm {
    pub fn new(
        id: &str,
        token_a: &str,
        token_b: &str,
        reserve_a: u128,
        reserve_b: u128,
    ) -> Self {
        Self {
            id: id.to_string(),
            token_a: token_a.to_string(),
            token_b: token_b.to_string(),
            reserve_a,
            reserve_b,
            swap_fee_bps: 30,
        }
    }

    /// The invariant k = reserve_a * reserve_b
    pub fn k(&self) -> u128 {
        self.reserve_a.checked_mul(self.reserve_b).unwrap_or(0)
    }

    /// Spot price of token_a in terms of token_b.
    pub fn spot_price_a_in_b(&self) -> f64 {
        if self.reserve_a == 0 {
            return 0.0;
        }
        self.reserve_b as f64 / self.reserve_a as f64
    }

    /// Spot price of token_b in terms of token_a.
    pub fn spot_price_b_in_a(&self) -> f64 {
        if self.reserve_b == 0 {
            return 0.0;
        }
        self.reserve_a as f64 / self.reserve_b as f64
    }

    /// Calculate output amount for a swap (with fee).
    pub fn get_amount_out(&self, amount_in: u128, token_in: &str) -> Result<u128, String> {
        let (reserve_in, reserve_out) = if token_in == self.token_a {
            (self.reserve_a, self.reserve_b)
        } else if token_in == self.token_b {
            (self.reserve_b, self.reserve_a)
        } else {
            return Err(format!("Unknown token: {}", token_in));
        };

        let amount_in_with_fee = amount_in
            .checked_mul((10000 - self.swap_fee_bps as u128))
            .and_then(|v| v.checked_div(10000))
            .ok_or("Fee calculation overflow")?;

        let numerator = amount_in_with_fee.checked_mul(reserve_out).ok_or("Overflow")?;
        let denominator = reserve_in.checked_add(amount_in_with_fee).ok_or("Overflow")?;

        if denominator == 0 {
            return Err("Division by zero".to_string());
        }

        Ok(numerator / denominator)
    }

    /// Calculate the price impact of a swap in basis points.
    pub fn price_impact_bps(&self, amount_in: u128, token_in: &str) -> Result<u16, String> {
        let spot_before = if token_in == self.token_a {
            self.spot_price_a_in_b()
        } else {
            self.spot_price_b_in_a()
        };

        let amount_out = self.get_amount_out(amount_in, token_in)?;

        // Simulated state
        let (new_reserve_a, new_reserve_b) = if token_in == self.token_a {
            (
                self.reserve_a + amount_in,
                self.reserve_b - amount_out,
            )
        } else {
            (
                self.reserve_a - amount_out,
                self.reserve_b + amount_in,
            )
        };

        let spot_after = if new_reserve_a == 0 {
            0.0
        } else if token_in == self.token_a {
            new_reserve_b as f64 / new_reserve_a as f64
        } else {
            new_reserve_a as f64 / new_reserve_b as f64
        };

        if spot_before == 0.0 {
            return Ok(10000); // Max impact
        }

        let deviation = ((spot_before - spot_after).abs() / spot_before) * 10000.0;
        Ok(deviation as u16)
    }
}

impl DeFiPrimitive for ConstantProductAmm {
    fn primitive_type(&self) -> DeFiPrimitiveType {
        DeFiPrimitiveType::ConstantProductAmm
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn simulate_swap(&self, token_in: &str, amount_in: u128) -> Result<u128, String> {
        self.get_amount_out(amount_in, token_in)
    }
}

// ── Liquidity Pool (alias) ───────────────────────────────────────

pub type LiquidityPool = ConstantProductAmm;

// ── Lending Pool ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LendingPool {
    pub id: String,
    pub collateral_asset: String,
    pub borrow_asset: String,
    pub total_liquidity: u128,
    pub total_borrowed: u128,
    pub collateralization_ratio_bps: u16, // e.g. 15000 = 150%
    pub liquidation_threshold_bps: u16,   // e.g. 12000 = 120%
    pub borrow_rate_bps: u16,             // Annual borrow rate in bps
}

impl LendingPool {
    pub fn new(
        id: &str,
        collateral_asset: &str,
        borrow_asset: &str,
        liquidity: u128,
    ) -> Self {
        Self {
            id: id.to_string(),
            collateral_asset: collateral_asset.to_string(),
            borrow_asset: borrow_asset.to_string(),
            total_liquidity: liquidity,
            total_borrowed: 0,
            collateralization_ratio_bps: 15000,
            liquidation_threshold_bps: 12000,
            borrow_rate_bps: 500,
        }
    }

    /// Maximum borrowable amount given collateral.
    pub fn max_borrow(&self, collateral_amount: u128, collateral_price: f64, borrow_price: f64) -> u128 {
        if borrow_price <= 0.0 {
            return 0;
        }
        let collateral_value = (collateral_amount as f64) * collateral_price;
        let max_borrow_value =
            collateral_value * 10000.0 / self.collateralization_ratio_bps as f64;
        (max_borrow_value / borrow_price) as u128
    }

    /// Check if a position is liquidatable.
    pub fn is_liquidatable(
        &self,
        collateral_amount: u128,
        borrow_amount: u128,
        collateral_price: f64,
        borrow_price: f64,
    ) -> bool {
        if borrow_amount == 0 || collateral_amount == 0 {
            return false;
        }
        let collateral_value = (collateral_amount as f64) * collateral_price;
        let borrow_value = (borrow_amount as f64) * borrow_price;
        let ratio_bps = (collateral_value / borrow_value) * 10000.0;
        ratio_bps < self.liquidation_threshold_bps as f64
    }
}

impl DeFiPrimitive for LendingPool {
    fn primitive_type(&self) -> DeFiPrimitiveType {
        DeFiPrimitiveType::LendingPool
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn simulate_swap(&self, _token_in: &str, _amount_in: u128) -> Result<u128, String> {
        Err("LendingPool does not support swap".to_string())
    }
}

// ── Oracle ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleType {
    Spot,
    TWAP,
    Chainlink,
    BandProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Oracle {
    pub id: String,
    pub oracle_type: OracleType,
    pub asset_pair: String,
    pub current_price: f64,
    pub twap_window_seconds: u64,
    pub historical_prices: Vec<(u64, f64)>, // (timestamp, price)
}

impl Oracle {
    pub fn new(id: &str, asset_pair: &str, initial_price: f64) -> Self {
        Self {
            id: id.to_string(),
            oracle_type: OracleType::Spot,
            asset_pair: asset_pair.to_string(),
            current_price: initial_price,
            twap_window_seconds: 3600,
            historical_prices: Vec::new(),
        }
    }

    /// Calculate TWAP over the window.
    pub fn twap(&self) -> f64 {
        if self.historical_prices.is_empty() {
            return self.current_price;
        }
        let sum: f64 = self.historical_prices.iter().map(|(_, p)| p).sum();
        sum / self.historical_prices.len() as f64
    }

    /// How much a trade must move the spot price to deviate TWAP by `threshold_bps`.
    pub fn required_trade_for_deviation(
        &self,
        threshold_bps: u16,
        pool: &ConstantProductAmm,
    ) -> u128 {
        let target_price = self.current_price
            * (1.0 + threshold_bps as f64 / 10000.0);

        // Binary search for the trade size
        let mut low: u128 = 0;
        let mut high: u128 = pool.reserve_a / 10; // Start with 10% of reserves

        for _ in 0..50 {
            let mid = (low + high) / 2;
            if mid == 0 {
                break;
            }
            let impact = pool.price_impact_bps(mid, &pool.token_a).unwrap_or(0);
            if impact as u16 >= threshold_bps {
                high = mid;
            } else {
                low = mid;
            }
        }
        high
    }
}

impl DeFiPrimitive for Oracle {
    fn primitive_type(&self) -> DeFiPrimitiveType {
        DeFiPrimitiveType::SpotOracle
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn simulate_swap(&self, _token_in: &str, _amount_in: u128) -> Result<u128, String> {
        Err("Oracle does not support swap".to_string())
    }
}

/// TWAP Oracle — convenience alias.
pub type TwapOracle = Oracle;

// ── Staking Rewards ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingRewards {
    pub id: String,
    pub staking_token: String,
    pub reward_token: String,
    pub total_staked: u128,
    pub reward_rate_per_second: u128,
    pub lock_period_seconds: u64,
}

impl StakingRewards {
    pub fn new(id: &str, staking_token: &str, reward_token: &str, reward_rate: u128) -> Self {
        Self {
            id: id.to_string(),
            staking_token: staking_token.to_string(),
            reward_token: reward_token.to_string(),
            total_staked: 0,
            reward_rate_per_second: reward_rate,
            lock_period_seconds: 0,
        }
    }
}

impl DeFiPrimitive for StakingRewards {
    fn primitive_type(&self) -> DeFiPrimitiveType {
        DeFiPrimitiveType::StakingRewards
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn simulate_swap(&self, _token_in: &str, _amount_in: u128) -> Result<u128, String> {
        Err("StakingRewards does not support swap".to_string())
    }
}
