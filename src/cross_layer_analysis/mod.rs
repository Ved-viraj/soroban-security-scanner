//! Cross-Layer Vulnerability Propagation Detection (#447)
//!
//! This module implements a multi-layer analysis pipeline that traces how
//! vulnerabilities propagate across the Rust → WASM → Soroban VM compilation
//! stack. No existing tool performs this kind of cross-layer analysis —
//! vulnerabilities that are invisible at a single layer become detectable
//! when the interaction between layers is modeled.
//!
//! # Architecture
//!
//! ```text
//! Rust Source ──► Rust Analyzer ──┐
//!                                 ├──► Propagation Engine ──► CrossLayerReport
//! WASM Binary ──► WASM Analyzer ──┤
//!                                 │
//! VM Trace    ──► VM Analyzer ────┘
//! ```

pub mod compilation_mapping;
pub mod cross_layer_ir;
pub mod optimization_sensitivity;
pub mod propagation;
pub mod report;
pub mod rust_analyzer;
pub mod vm_analyzer;
pub mod wasm_analyzer;

#[cfg(test)]
mod tests;

pub use compilation_mapping::{
    CompilationChainModel, CompilationMapping, MirToWasmMapping, RustPattern, WasmPattern,
};
pub use cross_layer_ir::{
    CompilationLayer, CrossLayerIr, InstructionMapping, IrInstruction, LayerInstruction,
};
pub use optimization_sensitivity::{
    OptimizationLevel, OptimizationSensitiveFinding, OptimizationSensitivityAnalyzer,
};
pub use propagation::{CrossLayerPropagationEngine, PropagationPath, PropagatedFinding};
pub use report::{
    ConfidenceLevel, CrossLayerReport, CrossLayerReportRow, FindingSeverity, ImpactLevel,
    RustFinding, VmImpact, WasmManifestation,
};
pub use rust_analyzer::{RustAnalyzer, RustFinding as RustAnalysisFinding, RustFindingKind};
pub use vm_analyzer::{VmAnalyzer, VmFinding, VmFindingKind};
pub use wasm_analyzer::{WasmAnalyzer, WasmFinding as WasmAnalysisFinding, WasmFindingKind};
