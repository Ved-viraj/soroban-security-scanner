//! Soroban VM-Level Vulnerability Analysis (#447 — Phase 5)
//!
//! Analyzes Soroban VM host-function call traces for metering-induced
//! state inconsistencies, cross-contract call reentrancy, and
//! authorization bypass patterns.

use super::report::FindingSeverity;
use serde::{Deserialize, Serialize};

/// A finding discovered at the Soroban VM level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmFinding {
    pub kind: VmFindingKind,
    pub description: String,
    pub host_function: Option<String>,
    pub metering_impact: Option<u64>,
    pub state_inconsistency_risk: bool,
    pub severity: FindingSeverity,
}

/// Categories of VM-level findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmFindingKind {
    /// State change occurs before a metering point — can be forced into
    /// an inconsistent state by exhausting the fuel budget.
    StateBeforeMetering,
    /// Storage write without corresponding event emission.
    SilentStateMutation,
    /// Cross-contract call that modifies caller state after return.
    ReentrantStateCorruption,
    /// Host function result not checked for error.
    UncheckedHostCall,
    /// Contract modifies state after calling into untrusted code.
    StateAfterExternalCall,
    /// Ledger timestamp used for critical logic (can be manipulated by validators).
    TimestampDependentLogic,
    /// Resource limit exceeded without proper rollback.
    ResourceExhaustionNoRollback,
    /// Authorization check bypassed via host function reordering.
    AuthBypassReordering,
    /// Cross-contract call depth exceeds safe limit.
    ExcessiveCallDepth,
    /// Memory page allocation pattern vulnerable to OOM.
    OomVulnerableAllocation,
}

impl VmFindingKind {
    pub fn severity(&self) -> FindingSeverity {
        match self {
            Self::ReentrantStateCorruption
            | Self::AuthBypassReordering
            | Self::StateAfterExternalCall => FindingSeverity::Critical,
            Self::StateBeforeMetering
            | Self::ResourceExhaustionNoRollback
            | Self::OomVulnerableAllocation => FindingSeverity::High,
            Self::UncheckedHostCall
            | Self::ExcessiveCallDepth
            | Self::TimestampDependentLogic => FindingSeverity::Medium,
            Self::SilentStateMutation => FindingSeverity::Low,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::StateBeforeMetering => {
                "State mutation occurs before a metering point — contract can be forced into inconsistency if fuel runs out mid-execution"
            }
            Self::SilentStateMutation => "Storage written without emitting a corresponding event",
            Self::ReentrantStateCorruption => {
                "Cross-contract call modifies state after caller assumes it's finalized"
            }
            Self::UncheckedHostCall => "Host function return value not checked for error conditions",
            Self::StateAfterExternalCall => {
                "Contract mutates state after calling into untrusted external contract"
            }
            Self::TimestampDependentLogic => {
                "Ledger timestamp used for critical logic — validators have discretion over timestamps within bounds"
            }
            Self::ResourceExhaustionNoRollback => {
                "Resource limit exceeded without proper state rollback"
            }
            Self::AuthBypassReordering => {
                "Authorization check can be bypassed by reordering host function calls"
            }
            Self::ExcessiveCallDepth => {
                "Cross-contract call depth exceeds safe limit — risk of stack overflow trap"
            }
            Self::OomVulnerableAllocation => {
                "Memory allocation pattern that can be forced to exceed page limits"
            }
        }
    }
}

/// The Soroban VM-level analyzer.
pub struct VmAnalyzer {
    findings: Vec<VmFinding>,
    max_safe_call_depth: usize,
}

impl VmAnalyzer {
    /// Default safe cross-contract call depth.
    pub const DEFAULT_MAX_CALL_DEPTH: usize = 8;

    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            max_safe_call_depth: Self::DEFAULT_MAX_CALL_DEPTH,
        }
    }

    pub fn with_max_call_depth(max: usize) -> Self {
        Self {
            findings: Vec::new(),
            max_safe_call_depth: max,
        }
    }

    /// Analyze a VM trace (list of host function calls) for vulnerabilities.
    pub fn analyze_trace(&mut self, host_calls: &[HostFunctionCall]) {
        let mut call_depth = 0usize;
        let mut state_mutations_before_metering: Vec<&HostFunctionCall> = Vec::new();
        let mut metering_seen = false;

        for call in host_calls {
            match call.function_name.as_str() {
                "host__call" | "host__try_call" => {
                    call_depth += 1;
                    if call_depth > self.max_safe_call_depth {
                        self.findings.push(VmFinding {
                            kind: VmFindingKind::ExcessiveCallDepth,
                            description: format!(
                                "Call depth {} exceeds safe limit {}",
                                call_depth, self.max_safe_call_depth
                            ),
                            host_function: Some(call.function_name.clone()),
                            metering_impact: None,
                            state_inconsistency_risk: true,
                            severity: VmFindingKind::ExcessiveCallDepth.severity(),
                        });
                    }
                }
                "host__return" => {
                    call_depth = call_depth.saturating_sub(1);
                }
                "host__ledger_put" | "host__storage_set" => {
                    if !metering_seen {
                        state_mutations_before_metering.push(call);
                    }
                    self.check_state_after_external_call(call, call_depth);
                }
                "host__meter" | "host__charge" => {
                    metering_seen = true;
                }
                _ => {}
            }
        }

        // Report state mutations that occurred before any metering point
        for call in &state_mutations_before_metering {
            self.findings.push(VmFinding {
                kind: VmFindingKind::StateBeforeMetering,
                description: format!(
                    "State mutation via {} occurs before first metering point — exploitable via resource exhaustion",
                    call.function_name
                ),
                host_function: Some(call.function_name.clone()),
                metering_impact: Some(0),
                state_inconsistency_risk: true,
                severity: VmFindingKind::StateBeforeMetering.severity(),
            });
        }
    }

    fn check_state_after_external_call(&mut self, call: &HostFunctionCall, depth: usize) {
        // If a storage write happens while we're inside a cross-contract call,
        // the caller's state could be corrupted.
        if depth > 0 {
            self.findings.push(VmFinding {
                kind: VmFindingKind::StateAfterExternalCall,
                description: "Storage mutation during cross-contract execution — caller state may be inconsistent".to_string(),
                host_function: Some(call.function_name.clone()),
                metering_impact: None,
                state_inconsistency_risk: true,
                severity: VmFindingKind::StateAfterExternalCall.severity(),
            });
        }
    }

    /// Add a finding directly (used by the propagation engine).
    pub fn add_finding(&mut self, finding: VmFinding) {
        self.findings.push(finding);
    }

    /// Return all findings.
    pub fn findings(&self) -> &[VmFinding] {
        &self.findings
    }

    /// Return findings with state inconsistency risk.
    pub fn state_risk_findings(&self) -> Vec<&VmFinding> {
        self.findings
            .iter()
            .filter(|f| f.state_inconsistency_risk)
            .collect()
    }

    pub fn severity_counts(&self) -> (usize, usize, usize, usize) {
        let (mut crit, mut high, mut med, mut low) = (0, 0, 0, 0);
        for f in &self.findings {
            match f.severity {
                FindingSeverity::Critical => crit += 1,
                FindingSeverity::High => high += 1,
                FindingSeverity::Medium => med += 1,
                FindingSeverity::Low => low += 1,
                FindingSeverity::Info => {}
            }
        }
        (crit, high, med, low)
    }
}

impl Default for VmAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a single host function call in the VM trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostFunctionCall {
    pub function_name: String,
    pub arguments: Vec<Vec<u8>>,
    pub returns: Option<Vec<u8>>,
    pub gas_consumed: u64,
    pub depth: usize,
}

impl HostFunctionCall {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            function_name: name.into(),
            arguments: Vec::new(),
            returns: None,
            gas_consumed: 0,
            depth: 0,
        }
    }

    pub fn with_args(mut self, args: Vec<Vec<u8>>) -> Self {
        self.arguments = args;
        self
    }
}
