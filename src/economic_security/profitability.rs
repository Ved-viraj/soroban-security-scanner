//! Profitability Quantification (#444 — Phase 7)
//!
//! Quantifies exploit profitability: required capital, gross/net profit,
//! risk of revert, and exploit difficulty score. Only reports exploits
//! with net profit > 0 and difficulty < 0.8.

use serde::{Deserialize, Serialize};

/// Profitability breakdown for an exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitProfitability {
    pub required_capital: u128,
    pub gross_profit: f64,
    pub net_profit: f64,
    pub total_fees: f64,
    pub total_gas: u64,
    pub risk_of_revert: f64,
    pub exploit_difficulty: ExploitDifficulty,
    pub is_exploitable: bool,
}

/// Difficulty assessment for executing an exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitDifficulty {
    /// Number of transactions required.
    pub transaction_count: usize,
    /// Timing requirements (seconds — Stellar: 3-5s ledger close).
    pub timing_window_seconds: u64,
    /// Capital required as a fraction of pool liquidity.
    pub capital_to_liquidity_ratio: f64,
    /// Overall difficulty score 0.0 (trivial) to 1.0 (impossible).
    pub score: f64,
}

impl ExploitDifficulty {
    /// Calculate the difficulty score.
    pub fn calculate(
        transaction_count: usize,
        timing_window_seconds: u64,
        required_capital: u128,
        pool_liquidity: u128,
    ) -> Self {
        let capital_ratio = if pool_liquidity > 0 {
            required_capital as f64 / pool_liquidity as f64
        } else {
            1.0
        };

        // Score formula: weighted combination of factors
        let tx_factor = (transaction_count as f64 / 10.0).min(1.0) * 0.3;
        let timing_factor = (timing_window_seconds as f64 / 5.0).min(1.0) * 0.3;
        let capital_factor = capital_ratio.min(1.0) * 0.4;

        let score = (tx_factor + timing_factor + capital_factor).min(1.0);

        Self {
            transaction_count,
            timing_window_seconds,
            capital_to_liquidity_ratio: capital_ratio,
            score,
        }
    }
}

/// Scoring result for profit analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfitabilityScore {
    pub profit_score: f64,  // 0.0 - 1.0, higher = more profitable
    pub risk_score: f64,    // 0.0 - 1.0, higher = more risky
    pub overall_score: f64, // Composite score
    pub recommendation: ProfitabilityRecommendation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfitabilityRecommendation {
    /// Definitely exploitable — report as critical.
    Exploitable,
    /// Possibly exploitable — report as warning.
    PossiblyExploitable,
    /// Not exploitable under current conditions.
    NotExploitable,
    /// Theoretical only — requires unrealistic conditions.
    Theoretical,
}

/// Analyzes exploit profitability.
pub struct ProfitabilityAnalyzer {
    min_net_profit_threshold: f64,
    max_difficulty_threshold: f64,
    max_risk_of_revert: f64,
}

impl ProfitabilityAnalyzer {
    pub fn new() -> Self {
        Self {
            min_net_profit_threshold: 0.0,
            max_difficulty_threshold: 0.8,
            max_risk_of_revert: 0.5,
        }
    }

    /// Analyze profitability of a potential exploit.
    pub fn analyze(
        &self,
        required_capital: u128,
        gross_profit: f64,
        fees: f64,
        gas_stroops: u64,
        transaction_count: usize,
        timing_window_seconds: u64,
        pool_liquidity: u128,
        risk_of_revert: f64,
    ) -> ExploitProfitability {
        // Stellar: 1 XLM = 10,000,000 stroops, base fee = 100 stroops
        let gas_cost_xlm = (gas_stroops as f64) / 10_000_000.0;
        let total_fees = fees + gas_cost_xlm;
        let net_profit = gross_profit - total_fees;

        let difficulty = ExploitDifficulty::calculate(
            transaction_count,
            timing_window_seconds,
            required_capital,
            pool_liquidity,
        );

        let is_exploitable = net_profit > self.min_net_profit_threshold
            && difficulty.score < self.max_difficulty_threshold
            && risk_of_revert < self.max_risk_of_revert;

        ExploitProfitability {
            required_capital,
            gross_profit,
            net_profit,
            total_fees,
            total_gas: gas_stroops,
            risk_of_revert,
            exploit_difficulty: difficulty,
            is_exploitable,
        }
    }

    /// Score the profitability on a 0-1 scale.
    pub fn score(&self, profitability: &ExploitProfitability) -> ProfitabilityScore {
        let profit_score = if profitability.gross_profit > 0.0 {
            (profitability.net_profit / (profitability.required_capital as f64).max(1.0)).min(1.0)
        } else {
            0.0
        };

        let risk_score = (profitability.risk_of_revert * 0.5
            + profitability.exploit_difficulty.score * 0.5)
            .min(1.0);

        let overall = (profit_score * 0.6 + (1.0 - risk_score) * 0.4).max(0.0);

        let recommendation = if overall > 0.7 {
            ProfitabilityRecommendation::Exploitable
        } else if overall > 0.4 {
            ProfitabilityRecommendation::PossiblyExploitable
        } else if overall > 0.1 {
            ProfitabilityRecommendation::NotExploitable
        } else {
            ProfitabilityRecommendation::Theoretical
        };

        ProfitabilityScore {
            profit_score,
            risk_score,
            overall_score: overall,
            recommendation,
        }
    }
}

impl Default for ProfitabilityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
