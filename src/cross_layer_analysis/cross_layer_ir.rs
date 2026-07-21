//! Cross-Layer Intermediate Representation (#447 — Phase 1)
//!
//! Defines the unified `CrossLayerIr` that represents contract behavior at
//! three levels: Rust MIR, WASM opcodes, and Soroban VM host-function calls.
//! Each instruction maps to zero or more instructions in adjacent layers
//! via `InstructionMapping`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Layers ────────────────────────────────────────────────────────────

/// The three layers of the compilation chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompilationLayer {
    /// Rust Mid-level IR (extracted via rustc driver).
    RustMir,
    /// WASM opcodes from the compiled `.wasm` binary.
    Wasm,
    /// Soroban VM host-function call trace.
    SorobanVm,
}

impl CompilationLayer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RustMir => "Rust MIR",
            Self::Wasm => "WASM",
            Self::SorobanVm => "Soroban VM",
        }
    }
}

// ── IR Instructions ──────────────────────────────────────────────────

/// A single instruction in the Cross-Layer IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrInstruction {
    /// Unique identifier within its layer.
    pub id: u64,
    /// The layer this instruction belongs to.
    pub layer: CompilationLayer,
    /// Human-readable representation (e.g. "CheckedAdd", "i128.add", "host__ledger_get").
    pub opcode: String,
    /// Source-level location when available.
    pub location: Option<SourceLocation>,
    /// Operands (register names, immediates, host function args).
    pub operands: Vec<String>,
    /// Annotations extracted during analysis.
    pub annotations: HashMap<String, String>,
}

/// Source-code location (when debug info is available).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

// ── Instruction Mappings ─────────────────────────────────────────────

/// Links one instruction in a source layer to zero or more target-layer
/// instructions through the compilation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionMapping {
    /// Source-layer instruction id.
    pub source_id: u64,
    /// Source layer.
    pub source_layer: CompilationLayer,
    /// Target-layer instruction ids that this source compiles to.
    pub target_ids: Vec<u64>,
    /// Target layer.
    pub target_layer: CompilationLayer,
    /// Whether the mapping is deterministic (same source always → same target).
    pub is_deterministic: bool,
    /// Optimization level used when this mapping was observed.
    pub optimization_level: String,
    /// Confidence 0.0–1.0 in this mapping.
    pub confidence: f64,
}

// ── Layer Instruction Wrappers ───────────────────────────────────────

/// A Rust MIR-level instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirInstruction {
    pub inner: IrInstruction,
    /// The Rust MIR statement kind (e.g. `CheckedAdd`, `RefCell::borrow_mut`).
    pub mir_kind: String,
}

/// A WASM-level instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmInstruction {
    pub inner: IrInstruction,
    /// The WASM opcode mnemonic (e.g. `i128.add`, `memory.grow`).
    pub wasm_opcode: String,
    /// Whether this instruction can trap.
    pub can_trap: bool,
}

/// A Soroban VM-level instruction (host function call).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmInstruction {
    pub inner: IrInstruction,
    /// Host function name (e.g. `host__ledger_put`, `host__call`).
    pub host_function: String,
    /// Metered CPU cost for this instruction.
    pub cpu_cost: u64,
}

/// Unified wrapper for any layer instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LayerInstruction {
    RustMir(MirInstruction),
    Wasm(WasmInstruction),
    SorobanVm(VmInstruction),
}

impl LayerInstruction {
    pub fn layer(&self) -> CompilationLayer {
        match self {
            Self::RustMir(_) => CompilationLayer::RustMir,
            Self::Wasm(_) => CompilationLayer::Wasm,
            Self::SorobanVm(_) => CompilationLayer::SorobanVm,
        }
    }

    pub fn location(&self) -> Option<&SourceLocation> {
        match self {
            Self::RustMir(i) => i.inner.location.as_ref(),
            Self::Wasm(i) => i.inner.location.as_ref(),
            Self::SorobanVm(i) => i.inner.location.as_ref(),
        }
    }
}

// ── Cross-Layer IR ───────────────────────────────────────────────────

/// The unified Cross-Layer IR — the central data structure for the
/// multi-layer analysis pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLayerIr {
    /// All instructions across all layers, indexed by (layer, id).
    pub instructions: HashMap<(CompilationLayer, u64), LayerInstruction>,
    /// Compilation mappings between layers.
    pub mappings: Vec<InstructionMapping>,
    /// The contract's function-level call graph.
    pub call_graph: CallGraph,
    /// Metadata about the compilation pipeline.
    pub metadata: CrossLayerMetadata,
}

impl CrossLayerIr {
    pub fn new() -> Self {
        Self {
            instructions: HashMap::new(),
            mappings: Vec::new(),
            call_graph: CallGraph::default(),
            metadata: CrossLayerMetadata::default(),
        }
    }

    /// Insert a layer instruction and return its id.
    pub fn insert(&mut self, inst: LayerInstruction) -> u64 {
        let id = self.next_id(inst.layer());
        let key = (inst.layer(), id);
        self.instructions.insert(key, inst);
        id
    }

    /// Add a compilation mapping between layers.
    pub fn add_mapping(&mut self, mapping: InstructionMapping) {
        self.mappings.push(mapping);
    }

    /// Get instructions for a specific layer.
    pub fn layer_instructions(&self, layer: CompilationLayer) -> Vec<&LayerInstruction> {
        self.instructions
            .iter()
            .filter(|((l, _), _)| *l == layer)
            .map(|(_, inst)| inst)
            .collect()
    }

    /// Get mappings from one layer to another.
    pub fn layer_mappings(
        &self,
        from: CompilationLayer,
        to: CompilationLayer,
    ) -> Vec<&InstructionMapping> {
        self.mappings
            .iter()
            .filter(|m| m.source_layer == from && m.target_layer == to)
            .collect()
    }

    fn next_id(&self, layer: CompilationLayer) -> u64 {
        self.instructions
            .iter()
            .filter(|((l, _), _)| *l == layer)
            .count() as u64
            + 1
    }
}

impl Default for CrossLayerIr {
    fn default() -> Self {
        Self::new()
    }
}

// ── Call Graph ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallGraph {
    /// Function name → list of callee names.
    pub edges: HashMap<String, Vec<String>>,
    /// Function name → metadata.
    pub functions: HashMap<String, FunctionMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionMetadata {
    pub is_public: bool,
    pub contains_unsafe: bool,
    pub contains_loop: bool,
    pub estimated_gas: u64,
}

// ── Metadata ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLayerMetadata {
    pub contract_name: String,
    pub rustc_version: String,
    pub soroban_sdk_version: String,
    pub wasm_opt_level: String,
    pub analysis_timestamp: String,
    pub source_file_count: usize,
    pub total_instructions: usize,
}

impl Default for CrossLayerMetadata {
    fn default() -> Self {
        Self {
            contract_name: String::new(),
            rustc_version: String::new(),
            soroban_sdk_version: String::new(),
            wasm_opt_level: String::new(),
            analysis_timestamp: String::new(),
            source_file_count: 0,
            total_instructions: 0,
        }
    }
}
