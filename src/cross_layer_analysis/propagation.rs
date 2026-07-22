//! Cross-Layer Propagation (#447 — Phase 5)
//!
//! The core propagation engine that traces findings from one layer to
//! the next through the compilation mapping, determining whether a
//! Rust-level vulnerability manifests at the WASM and VM levels.

use super::compilation_mapping::{CompilationChainModel, RustPattern};
use super::cross_layer_ir::CompilationLayer;
use super::report::{ConfidenceLevel, FindingSeverity, RustFinding, VmImpact, WasmManifestation};
use super::rust_analyzer::{RustFindingKind};
use super::vm_analyzer::VmFindingKind;
use super::wasm_analyzer::WasmFindingKind;
use serde::{Deserialize, Serialize};

/// Describes how a finding propagates from one layer to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationPath {
    pub source_layer: CompilationLayer,
    pub target_layer: CompilationLayer,
    pub source_finding_id: u64,
    pub target_finding_id: u64,
    pub confidence: ConfidenceLevel,
    pub description: String,
}

/// A finding that has been propagated through the compilation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagatedFinding {
    pub rust_finding: RustFinding,
    pub wasm_manifestation: WasmManifestation,
    pub vm_impact: VmImpact,
    pub propagation_paths: Vec<PropagationPath>,
    pub worst_severity: FindingSeverity,
}

/// The cross-layer propagation engine.
pub struct CrossLayerPropagationEngine {
    compilation_model: CompilationChainModel,
}

impl CrossLayerPropagationEngine {
    pub fn new() -> Self {
        Self {
            compilation_model: CompilationChainModel::new(),
        }
    }

    /// Propagate Rust findings to WASM and VM layers.
    pub fn propagate(
        &self,
        rust_findings: &[super::rust_analyzer::RustFinding],
    ) -> Vec<PropagatedFinding> {
        let mut results = Vec::new();

        for rf in rust_findings {
            if !rf.can_propagate_to_wasm {
                continue;
            }

            let wasm = self.propagate_to_wasm(rf);
            let vm = self.propagate_to_vm(rf, &wasm);

            let worst = Self::worst_severity(&[rf.severity, vm.severity()]);

            results.push(PropagatedFinding {
                rust_finding: RustFinding {
                    kind: rf.kind.description().to_string(),
                    description: rf.description.clone(),
                    file: rf.file.clone(),
                    line: rf.line,
                    column: rf.column,
                    code_snippet: rf.code_context.clone(),
                    can_propagate_to_wasm: true,
                    severity: rf.severity,
                },
                wasm_manifestation: wasm,
                vm_impact: vm,
                propagation_paths: Vec::new(),
                worst_severity: worst,
            });
        }

        results
    }

    fn propagate_to_wasm(
        &self,
        finding: &super::rust_analyzer::RustFinding,
    ) -> WasmManifestation {
        let rust_pattern = Self::kind_to_rust_pattern(&finding.kind);

        let (opcode, description, can_trap, was_protection_removed) = match rust_pattern {
            Some(RustPattern::RefCellBorrowMut) => (
                "i32.load / i32.store / unreachable".to_string(),
                "RefCell borrow_mut compiles to a load-check-store sequence. The panic path becomes unreachable in WASM, causing a trap that rolls back all state changes made before it.".to_string(),
                true,
                true,
            ),
            Some(RustPattern::Panic) => (
                "unreachable".to_string(),
                "Rust panic!() compiles to WASM unreachable trap. All state changes made before the panic are rolled back by the VM, potentially leaving the contract in an unexpected state if partial modifications were made.".to_string(),
                true,
                false,
            ),
            Some(RustPattern::HashMapIter) => (
                "call (SipHash-based iterator)".to_string(),
                "HashMap iteration compiles to a call into the hash-table iterator. The iteration order depends on the random hash seed, which differs between validators — non-deterministic behavior.".to_string(),
                false,
                false,
            ),
            Some(RustPattern::OrdinaryAdd) | Some(RustPattern::OrdinarySub) | Some(RustPattern::OrdinaryMul) => (
                "i128.add / i128.sub / i128.mul".to_string(),
                "Ordinary arithmetic in release mode: LLVM removes overflow checks. A silent overflow at the WASM level can produce incorrect state values without any trap or error.".to_string(),
                false,
                true,
            ),
            Some(RustPattern::Unwrap) => (
                "if / else / unreachable".to_string(),
                "unwrap() compiles to a check-and-branch. If LLVM proves the None case is unreachable, the trap is removed entirely — the unwrap becomes a no-op in WASM.".to_string(),
                true,
                true,
            ),
            Some(RustPattern::UnsafeBlock) => (
                "i32.load / i32.store".to_string(),
                "Unsafe block compiles to raw memory operations without bounds checks. The 32-bit WASM address space means pointers can wrap around at 4GB.".to_string(),
                false,
                false,
            ),
            _ => (
                "unknown".to_string(),
                format!(
                    "Rust finding '{}' propagates to WASM with unknown mapping",
                    finding.kind.description()
                ),
                false,
                false,
            ),
        };

        WasmManifestation {
            wasm_opcode: opcode,
            description,
            can_trap,
            gas_impact: None,
            was_protection_optimized_away: was_protection_removed,
            severity_change: if was_protection_removed {
                Some(super::report::SeverityChange::Escalated)
            } else {
                Some(super::report::SeverityChange::Unchanged)
            },
        }
    }

    fn propagate_to_vm(
        &self,
        finding: &super::rust_analyzer::RustFinding,
        wasm: &WasmManifestation,
    ) -> VmImpact {
        let exploitability = if wasm.can_trap {
            if wasm.was_protection_optimized_away {
                super::report::ExploitabilityLevel::Practical
            } else {
                super::report::ExploitabilityLevel::Difficult
            }
        } else {
            super::report::ExploitabilityLevel::Theoretical
        };

        let description = if wasm.can_trap {
            format!(
                "WASM trap (from {}) at VM level causes state rollback. If the trap occurs after partial state modifications, the contract enters an inconsistent state. This is exploitable if an attacker can trigger the trap condition.",
                wasm.wasm_opcode
            )
        } else {
            format!(
                "Finding manifests at VM level as non-deterministic behavior. Different validators may see different execution outcomes, potentially leading to consensus issues."
            )
        };

        VmImpact {
            description,
            exploitability,
            state_inconsistency_risk: wasm.can_trap,
            metering_impact: None,
            severity_change: if wasm.was_protection_optimized_away {
                Some(super::report::SeverityChange::Escalated)
            } else {
                Some(super::report::SeverityChange::Unchanged)
            },
        }
    }

    /// Map RustFindingKind to RustPattern for compilation lookup.
    fn kind_to_rust_pattern(kind: &RustFindingKind) -> Option<RustPattern> {
        match kind {
            RustFindingKind::RefCellPanicRisk => Some(RustPattern::RefCellBorrowMut),
            RustFindingKind::HashMapIteration => Some(RustPattern::HashMapIter),
            RustFindingKind::HashSetIteration => Some(RustPattern::HashSetIter),
            RustFindingKind::SilentOverflow => Some(RustPattern::OrdinaryAdd),
            RustFindingKind::UnwrapWithoutContext => Some(RustPattern::Unwrap),
            RustFindingKind::OptimizationDependentCheck => Some(RustPattern::OrdinaryAdd),
            RustFindingKind::CatchUnwindSuppression => Some(RustPattern::CatchUnwind),
            RustFindingKind::PlatformSpecificBranch => Some(RustPattern::CfgWasm32Branch),
            RustFindingKind::UnsafeBlockWasmMemory => Some(RustPattern::UnsafeBlock),
            RustFindingKind::TransmuteTypePunning => Some(RustPattern::Transmute),
            RustFindingKind::MissingAuthCheck => Some(RustPattern::EnvRequireAuth),
            RustFindingKind::UncheckedCrossContractCall => Some(RustPattern::EnvInvokeContract),
            RustFindingKind::MissingStorageCheck => Some(RustPattern::EnvStorageGet),
            _ => None,
        }
    }

    /// Compute the worst severity from a slice.
    fn worst_severity(severities: &[FindingSeverity]) -> FindingSeverity {
        *severities.iter().max_by_key(|s| **s).unwrap_or(&FindingSeverity::Info)
    }
}

impl Default for CrossLayerPropagationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl VmImpact {
    pub fn severity(&self) -> FindingSeverity {
        match self.exploitability {
            super::report::ExploitabilityLevel::Trivial => FindingSeverity::Critical,
            super::report::ExploitabilityLevel::Practical => FindingSeverity::High,
            super::report::ExploitabilityLevel::Difficult => FindingSeverity::Medium,
            super::report::ExploitabilityLevel::Theoretical => FindingSeverity::Low,
            super::report::ExploitabilityLevel::None => FindingSeverity::Info,
        }
    }
}
