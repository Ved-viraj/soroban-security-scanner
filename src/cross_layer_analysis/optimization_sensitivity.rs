//! Optimization Sensitivity Analysis (#447 — Phase 6)
//!
//! Recompiles with different optimization levels and detects findings
//! that only appear at certain levels. These "optimization-sensitive
//! vulnerabilities" can appear or disappear depending on compiler flags.

use serde::{Deserialize, Serialize};

/// Supported optimization levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OptimizationLevel {
    /// No optimization.
    O0,
    /// Basic optimization.
    O1,
    /// Standard optimization.
    O2,
    /// Optimize for size.
    Os,
    /// Aggressive size optimization.
    Oz,
}

impl OptimizationLevel {
    pub fn as_flag(&self) -> &'static str {
        match self {
            Self::O0 => "-O0",
            Self::O1 => "-O1",
            Self::O2 => "-O2",
            Self::Os => "-Os",
            Self::Oz => "-Oz",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::O0 => "No optimization — all checks preserved",
            Self::O1 => "Basic optimization — some dead-code eliminated",
            Self::O2 => "Standard optimization — LLVM can prove and eliminate checks",
            Self::Os => "Size optimization — aggressive dead-code and check elimination",
            Self::Oz => "Aggressive size — maximum code elimination, highest risk of check removal",
        }
    }

    /// All optimization levels.
    pub fn all() -> Vec<Self> {
        vec![Self::O0, Self::O1, Self::O2, Self::Os, Self::Oz]
    }
}

/// A finding that only appears or changes at certain optimization levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSensitiveFinding {
    /// The finding description.
    pub description: String,
    /// Optimization levels where the finding was observed.
    pub present_at: Vec<OptimizationLevel>,
    /// Optimization levels where the finding was NOT observed.
    pub absent_at: Vec<OptimizationLevel>,
    /// Whether the finding escalates in severity at certain levels.
    pub severity_escalation: bool,
    /// The worst-case severity.
    pub worst_severity: super::report::FindingSeverity,
    /// Whether the finding represents a check being removed.
    pub is_check_elimination: bool,
}

/// Analyzes findings across optimization levels.
pub struct OptimizationSensitivityAnalyzer {
    findings: Vec<OptimizationSensitiveFinding>,
}

impl OptimizationSensitivityAnalyzer {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Register a finding observed at a specific optimization level.
    pub fn observe(
        &mut self,
        description: impl Into<String>,
        level: OptimizationLevel,
        is_check_elimination: bool,
    ) {
        let desc = description.into();

        // Check if we already have this finding
        if let Some(existing) = self
            .findings
            .iter_mut()
            .find(|f| f.description == desc)
        {
            if !existing.present_at.contains(&level) {
                existing.present_at.push(level);
            }
            return;
        }

        // New finding — mark as present at this level, absent at others
        let all_levels = OptimizationLevel::all();
        let absent_at: Vec<OptimizationLevel> = all_levels
            .iter()
            .filter(|l| **l != level)
            .copied()
            .collect();

        self.findings.push(OptimizationSensitiveFinding {
            description: desc,
            present_at: vec![level],
            absent_at,
            severity_escalation: is_check_elimination,
            worst_severity: if is_check_elimination {
                super::report::FindingSeverity::High
            } else {
                super::report::FindingSeverity::Medium
            },
            is_check_elimination,
        });
    }

    /// Check if findings are optimization-sensitive.
    pub fn is_optimization_sensitive(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Get findings that only appear at specific levels (not all).
    pub fn level_specific_findings(&self) -> Vec<&OptimizationSensitiveFinding> {
        self.findings
            .iter()
            .filter(|f| f.present_at.len() < OptimizationLevel::all().len())
            .collect()
    }

    /// Get only check-elimination findings (most dangerous).
    pub fn check_elimination_findings(&self) -> Vec<&OptimizationSensitiveFinding> {
        self.findings
            .iter()
            .filter(|f| f.is_check_elimination)
            .collect()
    }

    /// Summarize findings by optimization level.
    pub fn summary_by_level(&self) -> Vec<(OptimizationLevel, usize)> {
        OptimizationLevel::all()
            .into_iter()
            .map(|level| {
                let count = self
                    .findings
                    .iter()
                    .filter(|f| f.present_at.contains(&level))
                    .count();
                (level, count)
            })
            .collect()
    }

    /// Return all findings.
    pub fn findings(&self) -> &[OptimizationSensitiveFinding] {
        &self.findings
    }
}

impl Default for OptimizationSensitivityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to build a sensitivity summary for the report.
pub fn build_sensitivity_summary(
    analyzer: &OptimizationSensitivityAnalyzer,
) -> super::report::OptimizationSensitivitySummary {
    let level_counts = analyzer.summary_by_level();
    let mut summary = super::report::OptimizationSensitivitySummary::default();

    for (level, count) in &level_counts {
        match level {
            OptimizationLevel::O0 => summary.findings_only_at_o0 = *count,
            OptimizationLevel::O1 => summary.findings_only_at_o1 = *count,
            OptimizationLevel::O2 => summary.findings_only_at_o2 = *count,
            OptimizationLevel::Os => summary.findings_only_at_os = *count,
            OptimizationLevel::Oz => summary.findings_only_at_oz = *count,
        }
    }

    summary.findings_across_multiple_levels = analyzer
        .findings()
        .iter()
        .filter(|f| f.present_at.len() > 1)
        .count();

    summary
}
