//! Cross-Layer Report Generation (#447 — Phase 8)
//!
//! Produces a `CrossLayerReport` organized as a three-column table:
//! Rust Finding → WASM Manifestation → VM Impact. Each row is annotated
//! with severity, confidence, and whether the finding is
//! optimization-sensitive.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Finding Severities ──────────────────────────────────────────────

/// Combined severity across all layers in a single finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Confidence in a propagated finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// Propagation is certain (verifiable mapping exists).
    Certain,
    /// Propagation is likely (heuristic-based).
    Likely,
    /// Propagation is speculative (may be a false positive).
    Speculative,
}

impl fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certain => write!(f, "✓ Certain"),
            Self::Likely => write!(f, "~ Likely"),
            Self::Speculative => write!(f, "? Speculative"),
        }
    }
}

// ── Finding Components ──────────────────────────────────────────────

/// A finding discovered at the Rust source level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustFinding {
    pub kind: String,
    pub description: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub code_snippet: String,
    pub can_propagate_to_wasm: bool,
    pub severity: FindingSeverity,
}

/// How the Rust finding manifests in compiled WASM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmManifestation {
    pub wasm_opcode: String,
    pub description: String,
    pub can_trap: bool,
    pub gas_impact: Option<u64>,
    pub was_protection_optimized_away: bool,
    pub severity_change: Option<SeverityChange>,
}

/// The impact at the Soroban VM level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmImpact {
    pub description: String,
    pub exploitability: ExploitabilityLevel,
    pub state_inconsistency_risk: bool,
    pub metering_impact: Option<u64>,
    pub severity_change: Option<SeverityChange>,
}

/// Whether severity increased or decreased across layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeverityChange {
    Escalated,
    Mitigated,
    Unchanged,
}

/// How exploitable a VM-level impact is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitabilityLevel {
    None,
    Theoretical,
    Difficult,
    Practical,
    Trivial,
}

/// The impact level score for a report row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ImpactLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

// ── Report Row ──────────────────────────────────────────────────────

/// A single row in the three-column Cross-Layer Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLayerReportRow {
    /// Unique row id.
    pub id: u64,
    /// Finding at the Rust source level.
    pub rust_finding: RustFinding,
    /// How it manifests in WASM.
    pub wasm_manifestation: WasmManifestation,
    /// Impact at the VM level.
    pub vm_impact: VmImpact,
    /// Worst severity across all layers.
    pub worst_severity: FindingSeverity,
    /// Confidence in the propagation.
    pub confidence: ConfidenceLevel,
    /// Whether the finding only appears at certain optimization levels.
    pub is_optimization_sensitive: bool,
    /// Optimization levels where this finding was observed.
    pub optimization_levels: Vec<String>,
    /// Overall impact level score.
    pub impact_level: ImpactLevel,
}

// ── Full Report ─────────────────────────────────────────────────────

/// The complete Cross-Layer Analysis Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLayerReport {
    pub report_title: String,
    pub contract_name: String,
    pub rustc_version: String,
    pub soroban_sdk_version: String,
    pub analysis_timestamp: String,
    pub rows: Vec<CrossLayerReportRow>,
    pub summary: CrossLayerReportSummary,
    pub optimization_sensitivity: Option<OptimizationSensitivitySummary>,
}

/// Summary statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossLayerReportSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub optimization_sensitive: usize,
    pub certain_count: usize,
    pub likely_count: usize,
    pub speculative_count: usize,
}

/// Summary of optimization-sensitive findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptimizationSensitivitySummary {
    pub findings_only_at_o0: usize,
    pub findings_only_at_o1: usize,
    pub findings_only_at_o2: usize,
    pub findings_only_at_os: usize,
    pub findings_only_at_oz: usize,
    pub findings_across_multiple_levels: usize,
}

impl CrossLayerReport {
    pub fn new(
        title: impl Into<String>,
        contract_name: impl Into<String>,
    ) -> Self {
        Self {
            report_title: title.into(),
            contract_name: contract_name.into(),
            rustc_version: String::new(),
            soroban_sdk_version: String::new(),
            analysis_timestamp: String::new(),
            rows: Vec::new(),
            summary: CrossLayerReportSummary::default(),
            optimization_sensitivity: None,
        }
    }

    /// Add a row and update summary counters.
    pub fn add_row(&mut self, row: CrossLayerReportRow) {
        self.summary.total_findings += 1;
        match row.worst_severity {
            FindingSeverity::Critical => self.summary.critical += 1,
            FindingSeverity::High => self.summary.high += 1,
            FindingSeverity::Medium => self.summary.medium += 1,
            FindingSeverity::Low => self.summary.low += 1,
            FindingSeverity::Info => self.summary.info += 1,
        }
        if row.is_optimization_sensitive {
            self.summary.optimization_sensitive += 1;
        }
        match row.confidence {
            ConfidenceLevel::Certain => self.summary.certain_count += 1,
            ConfidenceLevel::Likely => self.summary.likely_count += 1,
            ConfidenceLevel::Speculative => self.summary.speculative_count += 1,
        }
        self.rows.push(row);
    }

    /// Return findings sorted by severity (worst first).
    pub fn sorted_by_severity(&self) -> Vec<&CrossLayerReportRow> {
        let mut sorted: Vec<&CrossLayerReportRow> = self.rows.iter().collect();
        sorted.sort_by_key(|r| std::cmp::Reverse(r.worst_severity));
        sorted
    }

    /// Dump the report as a plain-text table.
    pub fn to_text_table(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Cross-Layer Analysis Report: {}\n",
            self.report_title
        ));
        out.push_str(&format!(
            "Contract: {} | rustc: {} | SDK: {}\n",
            self.contract_name, self.rustc_version, self.soroban_sdk_version
        ));
        out.push_str(&format!(
            "Total findings: {} (C:{}, H:{}, M:{}, L:{}, I:{})\n",
            self.summary.total_findings,
            self.summary.critical,
            self.summary.high,
            self.summary.medium,
            self.summary.low,
            self.summary.info,
        ));
        out.push_str(&"-".repeat(80));
        out.push('\n');

        for row in &self.rows {
            out.push_str(&format!(
                "\n[{:?}] {} (confidence: {})\n",
                row.worst_severity, row.rust_finding.kind, row.confidence,
            ));
            out.push_str(&format!(
                "  Rust: {}:{} — {}\n",
                row.rust_finding.file, row.rust_finding.line, row.rust_finding.description,
            ));
            out.push_str(&format!(
                "  WASM: {} — {}\n",
                row.wasm_manifestation.wasm_opcode, row.wasm_manifestation.description,
            ));
            out.push_str(&format!(
                "  VM:   {} (exploitability: {:?})\n",
                row.vm_impact.description, row.vm_impact.exploitability,
            ));
            if row.is_optimization_sensitive {
                out.push_str(&format!(
                    "  ⚠ Optimization-sensitive: {}\n",
                    row.optimization_levels.join(", ")
                ));
            }
        }
        out
    }
}
