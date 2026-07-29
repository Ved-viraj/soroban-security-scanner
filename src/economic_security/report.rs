//! Economic Exploit Report Generation (#444 — Phase 9)
//!
//! Generates an `EconomicExploitReport` with attack sequences, economic
//! models, profit breakdowns, and severity scores. Integrates with the
//! `VulnerabilityReport` frontend via an `Economic` tag.

use serde::{Deserialize, Serialize};

/// Severity of an economic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EconomicSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Step in an attack sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSequence {
    pub step_number: usize,
    pub action: String,
    pub target: String,
    pub amount: u128,
    pub asset: String,
    pub expected_outcome: String,
}

/// A single economic finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicFinding {
    pub id: u64,
    pub title: String,
    pub finding_type: EconomicFindingType,
    pub severity: EconomicSeverity,
    pub attack_sequence: Vec<AttackSequence>,
    pub profit_breakdown: Option<ProfitBreakdown>,
    pub required_preconditions: Vec<String>,
    pub description: String,
    pub recommendation: String,
}

/// Types of economic findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EconomicFindingType {
    FlashLoanAttack,
    OracleManipulation,
    MevSandwich,
    CollateralExploitation,
    LiquidationCascade,
    GovernanceAttack,
    FeeManipulation,
}

/// Profit breakdown for an attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfitBreakdown {
    pub gross_profit: f64,
    pub fees_paid: f64,
    pub gas_paid: f64,
    pub net_profit: f64,
    pub required_capital: u128,
    pub roi_percent: f64,
    pub is_profitable: bool,
}

/// Full economic exploit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicExploitReport {
    pub report_title: String,
    pub protocol_name: String,
    pub analysis_timestamp: String,
    pub findings: Vec<EconomicFinding>,
    pub summary: EconomicExploitSummary,
}

/// Summary of the report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EconomicExploitSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total_profitable_attacks: usize,
    pub total_estimated_loss_xlm: f64,
    pub most_vulnerable_primitive: String,
    pub protocol_security_score: f64, // 0-100
}

impl EconomicExploitReport {
    pub fn new(title: impl Into<String>, protocol_name: impl Into<String>) -> Self {
        Self {
            report_title: title.into(),
            protocol_name: protocol_name.into(),
            analysis_timestamp: String::new(),
            findings: Vec::new(),
            summary: EconomicExploitSummary::default(),
        }
    }

    /// Add a finding and update the summary.
    pub fn add_finding(&mut self, finding: EconomicFinding) {
        self.summary.total_findings += 1;
        match finding.severity {
            EconomicSeverity::Critical => self.summary.critical += 1,
            EconomicSeverity::High => self.summary.high += 1,
            EconomicSeverity::Medium => self.summary.medium += 1,
            EconomicSeverity::Low => self.summary.low += 1,
            EconomicSeverity::Info => {}
        }

        if let Some(ref pb) = finding.profit_breakdown {
            if pb.is_profitable {
                self.summary.total_profitable_attacks += 1;
                self.summary.total_estimated_loss_xlm += pb.net_profit;
            }
        }

        self.findings.push(finding);
    }

    /// Build protocol security score (0-100).
    pub fn calculate_security_score(&mut self) {
        let penalty_per_critical = 25.0;
        let penalty_per_high = 15.0;
        let penalty_per_medium = 8.0;
        let penalty_per_low = 3.0;

        let total_penalty = (self.summary.critical as f64 * penalty_per_critical)
            + (self.summary.high as f64 * penalty_per_high)
            + (self.summary.medium as f64 * penalty_per_medium)
            + (self.summary.low as f64 * penalty_per_low);

        self.summary.protocol_security_score = (100.0 - total_penalty).max(0.0);
    }

    /// Generate plain-text summary.
    pub fn to_text_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Economic Exploit Report: {}\nProtocol: {}\n",
            self.report_title, self.protocol_name
        ));
        out.push_str(&format!(
            "Security Score: {:.0}/100\n",
            self.summary.protocol_security_score
        ));
        out.push_str(&format!(
            "Findings: {} (C:{}, H:{}, M:{}, L:{})\n",
            self.summary.total_findings,
            self.summary.critical,
            self.summary.high,
            self.summary.medium,
            self.summary.low,
        ));
        out.push_str(&format!(
            "Profitable attacks: {}, Est. loss: {:.2} XLM\n",
            self.summary.total_profitable_attacks, self.summary.total_estimated_loss_xlm,
        ));

        for finding in &self.findings {
            out.push_str(&format!(
                "\n[{:?}] {} — {}",
                finding.severity, finding.title, finding.description
            ));
            if let Some(pb) = &finding.profit_breakdown {
                out.push_str(&format!(" (Net profit: {:.2} XLM)", pb.net_profit));
            }
        }
        out
    }
}
