//! Rust-Level Vulnerability Analysis (#447 — Phase 3)
//!
//! Analyzes Rust source for patterns that can introduce cross-layer
//! vulnerabilities: interior mutability panics, non-deterministic iteration,
//! platform-specific branches, unsafe assumptions, and suppressed errors.

use super::report::FindingSeverity;
use serde::{Deserialize, Serialize};

/// A finding discovered at the Rust source level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustFinding {
    pub kind: RustFindingKind,
    pub description: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub can_propagate_to_wasm: bool,
    pub severity: FindingSeverity,
    pub code_context: String,
}

/// Categories of Rust-level findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RustFindingKind {
    // ── Interior Mutability ──
    RefCellPanicRisk,
    CellMisuse,
    UnsafeCellDanger,

    // ── Non-Deterministic ──
    HashMapIteration,
    HashSetIteration,
    PlatformSpecificBranch,

    // ── Unsafe Assumptions ──
    UnsafeBlockWasmMemory,
    TransmuteTypePunning,
    MaybeUninitPropagation,

    // ── Error Suppression ──
    CatchUnwindSuppression,
    UnwrapWithoutContext,
    ExpectWithoutJustification,
    SilentOverflow,

    // ── Compilation-Dependent ──
    OptimizationDependentCheck,
    DebugOnlyCheck,
    ReleaseOnlyBehavior,

    // ── Soroban-Specific ──
    MissingStorageCheck,
    UnboundedStorageGrowth,
    UncheckedCrossContractCall,
    MissingAuthCheck,
}

impl RustFindingKind {
    pub fn severity(&self) -> FindingSeverity {
        match self {
            Self::RefCellPanicRisk | Self::UnsafeBlockWasmMemory | Self::UnsafeCellDanger => {
                FindingSeverity::High
            }
            Self::HashMapIteration
            | Self::HashSetIteration
            | Self::UncheckedCrossContractCall
            | Self::MissingAuthCheck
            | Self::SilentOverflow => FindingSeverity::Medium,
            Self::CatchUnwindSuppression
            | Self::OptimizationDependentCheck
            | Self::MissingStorageCheck
            | Self::UnboundedStorageGrowth => FindingSeverity::Low,
            _ => FindingSeverity::Info,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::RefCellPanicRisk => {
                "RefCell::borrow_mut() can panic at runtime, causing a WASM trap that rolls back partial state"
            }
            Self::CellMisuse => "Cell misuse can hide mutation from the borrow checker",
            Self::UnsafeCellDanger => "UnsafeCell exposes raw pointers to interior data",
            Self::HashMapIteration => {
                "HashMap iteration is non-deterministic — different validators see different order"
            }
            Self::HashSetIteration => "HashSet iteration is non-deterministic like HashMap",
            Self::PlatformSpecificBranch => {
                "cfg(target_arch = \"wasm32\") branch differs from test/debug behavior"
            }
            Self::UnsafeBlockWasmMemory => {
                "Unsafe block assumes WASM memory layout (4GB address space — wrap-around risk)"
            }
            Self::TransmuteTypePunning => "Transmute reinterprets bits, potentially violating WASM type safety",
            Self::MaybeUninitPropagation => "MaybeUninit can propagate uninitialized data to storage",
            Self::CatchUnwindSuppression => "catch_unwind suppresses critical errors that should abort",
            Self::UnwrapWithoutContext => "unwrap() without context — panic information lost in WASM",
            Self::ExpectWithoutJustification => "expect() without meaningful message",
            Self::SilentOverflow => "Arithmetic overflow without checked operations in release",
            Self::OptimizationDependentCheck => {
                "Security check that LLVM may optimize away at higher optimization levels"
            }
            Self::DebugOnlyCheck => "Check only active in debug builds — absent in production WASM",
            Self::ReleaseOnlyBehavior => "Behavior that differs between debug and release builds",
            Self::MissingStorageCheck => "Storage access without existence check (potential missing key)",
            Self::UnboundedStorageGrowth => "Unbounded storage growth without TTL or cleanup",
            Self::UncheckedCrossContractCall => "Cross-contract call without return value check",
            Self::MissingAuthCheck => "Missing authorization check on privileged operation",
        }
    }

    pub fn propagates_to_wasm(&self) -> bool {
        match self {
            Self::RefCellPanicRisk
            | Self::HashMapIteration
            | Self::HashSetIteration
            | Self::SilentOverflow
            | Self::OptimizationDependentCheck
            | Self::DebugOnlyCheck
            | Self::UnwrapWithoutContext
            | Self::PlatformSpecificBranch
            | Self::ReleaseOnlyBehavior => true,
            _ => false,
        }
    }
}

/// The Rust-level analyzer.
pub struct RustAnalyzer {
    findings: Vec<RustFinding>,
    /// Patterns to scan for.
    enabled_checks: Vec<RustFindingKind>,
}

impl RustAnalyzer {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            enabled_checks: Self::all_checks(),
        }
    }

    fn all_checks() -> Vec<RustFindingKind> {
        vec![
            RustFindingKind::RefCellPanicRisk,
            RustFindingKind::CellMisuse,
            RustFindingKind::UnsafeCellDanger,
            RustFindingKind::HashMapIteration,
            RustFindingKind::HashSetIteration,
            RustFindingKind::PlatformSpecificBranch,
            RustFindingKind::UnsafeBlockWasmMemory,
            RustFindingKind::TransmuteTypePunning,
            RustFindingKind::MaybeUninitPropagation,
            RustFindingKind::CatchUnwindSuppression,
            RustFindingKind::UnwrapWithoutContext,
            RustFindingKind::ExpectWithoutJustification,
            RustFindingKind::SilentOverflow,
            RustFindingKind::OptimizationDependentCheck,
            RustFindingKind::DebugOnlyCheck,
            RustFindingKind::ReleaseOnlyBehavior,
            RustFindingKind::MissingStorageCheck,
            RustFindingKind::UnboundedStorageGrowth,
            RustFindingKind::UncheckedCrossContractCall,
            RustFindingKind::MissingAuthCheck,
        ]
    }

    /// Analyze Rust source code and collect findings.
    pub fn analyze_source(&mut self, source: &str, file_path: &str) {
        let lines: Vec<&str> = source.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = (line_idx + 1) as u32;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            // Check each pattern
            for check in &self.enabled_checks {
                if let Some(finding) = self.check_line(trimmed, check, file_path, line_num) {
                    self.findings.push(finding);
                }
            }
        }
    }

    fn check_line(
        &self,
        line: &str,
        kind: &RustFindingKind,
        file: &str,
        line_num: u32,
    ) -> Option<RustFinding> {
        // Simple pattern matching for demonstration.
        // A real implementation would use rustc's MIR or syn-based AST traversal.
        let matched = match kind {
            RustFindingKind::RefCellPanicRisk => {
                line.contains("RefCell") && line.contains("borrow_mut")
            }
            RustFindingKind::HashMapIteration => line.contains("HashMap") && line.contains("iter"),
            RustFindingKind::HashSetIteration => line.contains("HashSet") && line.contains("iter"),
            RustFindingKind::PlatformSpecificBranch => {
                line.contains("target_arch") && line.contains("wasm32")
            }
            RustFindingKind::UnsafeBlockWasmMemory => {
                line.contains("unsafe") && (line.contains("ptr") || line.contains("as_ptr"))
            }
            RustFindingKind::TransmuteTypePunning => line.contains("transmute"),
            RustFindingKind::UnwrapWithoutContext => {
                line.contains(".unwrap()") && !line.contains("// safe because")
            }
            RustFindingKind::SilentOverflow => {
                (line.contains('+') || line.contains('-') || line.contains('*'))
                    && !line.contains("checked_")
                    && !line.contains("wrapping_")
                    && !line.contains("saturating_")
                    && (line.contains("balance") || line.contains("supply") || line.contains("amount"))
            }
            RustFindingKind::OptimizationDependentCheck => {
                line.contains("if cfg!(debug_assertions)")
                    || line.contains("debug_assert!")
            }
            RustFindingKind::CatchUnwindSuppression => line.contains("catch_unwind"),
            RustFindingKind::MissingAuthCheck => {
                (line.contains("fn") && (line.contains("transfer") || line.contains("mint") || line.contains("burn")))
                    && !line.contains("require_auth")
            }
            RustFindingKind::UncheckedCrossContractCall => {
                line.contains("invoke_contract") && !line.contains("let _")
            }
            RustFindingKind::MissingStorageCheck => {
                line.contains("storage().get") && !line.contains(".is_some()") && !line.contains("match")
            }
            RustFindingKind::UnboundedStorageGrowth => {
                line.contains("storage().set") && !line.contains("live_until")
            }
            _ => false,
        };

        if matched {
            return Some(RustFinding {
                kind: kind.clone(),
                description: kind.description().to_string(),
                file: file.to_string(),
                line: line_num,
                column: line.find(line.trim()).unwrap_or(0) as u32,
                can_propagate_to_wasm: kind.propagates_to_wasm(),
                severity: kind.severity(),
                code_context: line.to_string(),
            });
        }

        None
    }

    /// Return all collected findings.
    pub fn findings(&self) -> &[RustFinding] {
        &self.findings
    }

    /// Return only findings that can propagate to WASM.
    pub fn propagatable_findings(&self) -> Vec<&RustFinding> {
        self.findings
            .iter()
            .filter(|f| f.can_propagate_to_wasm)
            .collect()
    }

    /// Return findings sorted by severity (worst first).
    pub fn sorted_findings(&self) -> Vec<&RustFinding> {
        let mut sorted: Vec<&RustFinding> = self.findings.iter().collect();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
        sorted
    }

    /// Get the count of findings by severity.
    pub fn severity_counts(&self) -> (usize, usize, usize, usize) {
        let (mut high, mut medium, mut low, mut info) = (0, 0, 0, 0);
        for f in &self.findings {
            match f.severity {
                FindingSeverity::Critical => high += 1,
                FindingSeverity::High => high += 1,
                FindingSeverity::Medium => medium += 1,
                FindingSeverity::Low => low += 1,
                FindingSeverity::Info => info += 1,
            }
        }
        (high, medium, low, info)
    }
}

impl Default for RustAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
