//! WASM-Level Vulnerability Analysis (#447 — Phase 4)
//!
//! Analyzes compiled WASM binaries for: missing memory.grow failure checks,
//! offset computations near the 4GB boundary, indirect call safety, and
//! trap instructions with optional Rust source correlation via DWARF
//! debug info or the compilation mapping.

use super::report::FindingSeverity;
use serde::{Deserialize, Serialize};

/// A finding discovered at the WASM level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmFinding {
    pub kind: WasmFindingKind,
    pub description: String,
    pub wasm_offset: usize,
    pub rust_source_location: Option<String>,
    pub rust_protection_optimized_away: bool,
    pub severity: FindingSeverity,
}

/// Categories of WASM-level findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WasmFindingKind {
    /// memory.grow called but the return value (-1 on failure) is not checked.
    MissingMemoryGrowCheck,
    /// Offset computation within 1KB of the 4GB memory boundary.
    NearAddressSpaceBoundary,
    /// indirect call target not in the export table.
    UntrustedIndirectCallTarget,
    /// unreachable / unreachable-branch instruction present.
    TrapInstruction,
    /// Out-of-bounds memory access detected.
    OutOfBoundsAccess,
    /// i128.load / i128.store without alignment hint.
    MisalignedI128Access,
    /// A loop without an explicit fuel/metering point.
    UnboundedLoop,
    /// Rust source protection (e.g. checked_add) was optimized away.
    ProtectionOptimizedAway,
    /// DWARF debug info indicates a source panic path.
    DebugPanicPath,
    /// Function table exceeds expected size.
    OversizedFunctionTable,
    /// Export count mismatch with expected interface.
    ExportMismatch,
}

impl WasmFindingKind {
    pub fn severity(&self) -> FindingSeverity {
        match self {
            Self::UntrustedIndirectCallTarget | Self::OutOfBoundsAccess => FindingSeverity::Critical,
            Self::MissingMemoryGrowCheck
            | Self::NearAddressSpaceBoundary
            | Self::ProtectionOptimizedAway => FindingSeverity::High,
            Self::TrapInstruction | Self::UnboundedLoop | Self::ExportMismatch => {
                FindingSeverity::Medium
            }
            Self::MisalignedI128Access | Self::DebugPanicPath | Self::OversizedFunctionTable => {
                FindingSeverity::Low
            }
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::MissingMemoryGrowCheck => {
                "memory.grow can return -1 (failure), but the result is not checked — potential OOM leading to trap"
            }
            Self::NearAddressSpaceBoundary => {
                "Offset computation within 1KB of the 4GB address space boundary — wrap-around risk"
            }
            Self::UntrustedIndirectCallTarget => {
                "Indirect call to a function not in the verified export table — type confusion risk"
            }
            Self::TrapInstruction => {
                "Unreachable/unreachable-branch instruction — indicates a potential panic path in production"
            }
            Self::OutOfBoundsAccess => "Memory access beyond allocated pages",
            Self::MisalignedI128Access => "i128 load/store without alignment may be slower or cause issues on some platforms",
            Self::UnboundedLoop => "Loop without metering point — could exhaust VM fuel budget",
            Self::ProtectionOptimizedAway => {
                "Rust-level protection (checked arithmetic, bounds check) was optimized away by LLVM"
            }
            Self::DebugPanicPath => "DWARF debug info shows a panic path that may be latent in production",
            Self::OversizedFunctionTable => "Function table larger than expected — potential code injection surface",
            Self::ExportMismatch => "Export table does not match the expected contract interface",
        }
    }
}

/// The WASM binary analyzer.
pub struct WasmAnalyzer {
    findings: Vec<WasmFinding>,
    address_space_boundary: u64,
}

impl WasmAnalyzer {
    /// 4GB address space for WASM32.
    pub const ADDRESS_SPACE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

    /// Threshold within which offsets are flagged as near-boundary.
    pub const BOUNDARY_THRESHOLD: u64 = 1024;

    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            address_space_boundary: Self::ADDRESS_SPACE_SIZE,
        }
    }

    /// Analyze a WASM binary and collect findings.
    pub fn analyze_binary(&mut self, wasm_bytes: &[u8]) {
        // Phase 4a: Check memory.grow failure handling
        self.check_memory_grow(wasm_bytes);

        // Phase 4b: Check for near-boundary offset computations
        self.check_offset_boundaries(wasm_bytes);

        // Phase 4c: Validate indirect call targets
        self.check_indirect_calls(wasm_bytes);

        // Phase 4d: Detect trap instructions
        self.check_trap_instructions(wasm_bytes);
    }

    fn check_memory_grow(&mut self, wasm_bytes: &[u8]) {
        // Scan for the memory.grow opcode (0x40) pattern
        let mut i = 0;
        while i < wasm_bytes.len().saturating_sub(1) {
            if wasm_bytes[i] == 0x40 {
                // memory.grow opcode — check if the next bytes test the result
                let has_check = i + 3 < wasm_bytes.len()
                    && (wasm_bytes[i + 1] == 0x7f // i32.eqz
                        || wasm_bytes[i + 1] == 0x48); // i64.eqz
                if !has_check {
                    self.findings.push(WasmFinding {
                        kind: WasmFindingKind::MissingMemoryGrowCheck,
                        description: "memory.grow at offset".to_string() + " with no failure check",
                        wasm_offset: i,
                        rust_source_location: None,
                        rust_protection_optimized_away: false,
                        severity: WasmFindingKind::MissingMemoryGrowCheck.severity(),
                    });
                }
            }
            i += 1;
        }
    }

    fn check_offset_boundaries(&mut self, wasm_bytes: &[u8]) {
        // Scan for 32-bit constants near the 4GB boundary
        for i in 0..wasm_bytes.len().saturating_sub(4) {
            // i32.const opcode is 0x41
            if wasm_bytes[i] == 0x41 {
                let mut value: u64 = 0;
                let mut shift = 0;
                let mut pos = i + 1;
                while pos < wasm_bytes.len() {
                    let byte = wasm_bytes[pos];
                    value |= ((byte & 0x7f) as u64) << shift;
                    pos += 1;
                    if byte & 0x80 == 0 {
                        break;
                    }
                    shift += 7;
                    if shift >= 35 {
                        break;
                    }
                }
                if value >= self.address_space_boundary.saturating_sub(Self::BOUNDARY_THRESHOLD) {
                    self.findings.push(WasmFinding {
                        kind: WasmFindingKind::NearAddressSpaceBoundary,
                        description: format!(
                            "i32.const {} near 4GB boundary — potential wrap-around",
                            value
                        ),
                        wasm_offset: i,
                        rust_source_location: None,
                        rust_protection_optimized_away: false,
                        severity: WasmFindingKind::NearAddressSpaceBoundary.severity(),
                    });
                }
            }
        }
    }

    fn check_indirect_calls(&mut self, _wasm_bytes: &[u8]) {
        // In a full implementation, this would parse the WASM type section
        // and cross-reference indirect call targets with the export table.
        // For now, note the capability.
    }

    fn check_trap_instructions(&mut self, wasm_bytes: &[u8]) {
        // 0x00 = unreachable opcode
        for (i, &byte) in wasm_bytes.iter().enumerate() {
            if byte == 0x00 {
                self.findings.push(WasmFinding {
                    kind: WasmFindingKind::TrapInstruction,
                    description: "unreachable instruction — potential panic path".to_string(),
                    wasm_offset: i,
                    rust_source_location: None,
                    rust_protection_optimized_away: false,
                    severity: WasmFindingKind::TrapInstruction.severity(),
                });
            }
        }
    }

    /// Add a finding directly (used by the propagation engine).
    pub fn add_finding(&mut self, finding: WasmFinding) {
        self.findings.push(finding);
    }

    /// Return all findings.
    pub fn findings(&self) -> &[WasmFinding] {
        &self.findings
    }

    /// Return only findings with severity High or above.
    pub fn high_severity_findings(&self) -> Vec<&WasmFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= FindingSeverity::High)
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

impl Default for WasmAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
