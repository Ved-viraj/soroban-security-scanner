//! Compilation Chain Model (#447 — Phase 2)
//!
//! Defines the formal mapping from Rust MIR patterns to WASM opcodes for
//! Soroban's `wasm32-unknown-unknown` target. Documents 50+ mappings
//! covering the most common Rust patterns found in Soroban contracts.

use serde::{Deserialize, Serialize};

/// Represents a Rust pattern (MIR-level construct) that has a known
/// WASM translation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RustPattern {
    // ── Arithmetic ──
    CheckedAdd,
    CheckedSub,
    CheckedMul,
    CheckedDiv,
    SaturatingAdd,
    SaturatingSub,
    WrappingAdd,
    WrappingSub,
    OverflowingAdd,
    OrdinaryAdd,
    OrdinarySub,
    OrdinaryMul,
    OrdinaryDiv,
    UncheckedAdd,
    UncheckedSub,

    // ── Memory / Borrowing ──
    RefCellBorrow,
    RefCellBorrowMut,
    CellGet,
    CellSet,
    UnsafeCellGet,
    BoxNew,
    VecPush,
    VecPop,
    VecIndex,
    StringPush,
    StringLen,

    // ── Control Flow ──
    Panic,
    Unwrap,
    Expect,
    CatchUnwind,
    IfLet,
    MatchExhaustive,
    MatchNonExhaustive,
    LoopBreak,
    ReturnEarly,

    // ── Collections ──
    HashMapIter,
    HashSetIter,
    BTreeMapIter,
    VecIter,

    // ── Platform-Specific ──
    CfgWasm32Branch,
    TargetArchCheck,
    OsCheck,

    // ── Unsafe ──
    UnsafeBlock,
    UnsafeFn,
    Transmute,
    MaybeUninit,

    // ── Soroban Specific ──
    EnvStorageGet,
    EnvStorageSet,
    EnvStorageHas,
    EnvInvokeContract,
    EnvLedgerGet,
    EnvCurrentContractAddress,
    EnvRequireAuth,
    EnvAlloc,
}

impl RustPattern {
    /// Whether this pattern can introduce non-determinism.
    pub fn is_non_deterministic(&self) -> bool {
        matches!(
            self,
            Self::HashMapIter | Self::HashSetIter | Self::CfgWasm32Branch
        )
    }

    /// Whether this pattern can trap/panic.
    pub fn can_trap(&self) -> bool {
        matches!(
            self,
            Self::Panic
                | Self::Unwrap
                | Self::Expect
                | Self::RefCellBorrow
                | Self::RefCellBorrowMut
                | Self::VecIndex
        )
    }

    /// Whether this pattern is platform-sensitive.
    pub fn is_platform_sensitive(&self) -> bool {
        matches!(
            self,
            Self::CfgWasm32Branch | Self::TargetArchCheck | Self::OsCheck
        )
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::CheckedAdd => "Checked addition with overflow trap",
            Self::CheckedSub => "Checked subtraction with underflow trap",
            Self::CheckedMul => "Checked multiplication with overflow trap",
            Self::CheckedDiv => "Checked division with zero-division trap",
            Self::SaturatingAdd => "Saturating addition (no overflow panic)",
            Self::SaturatingSub => "Saturating subtraction (no underflow panic)",
            Self::WrappingAdd => "Wrapping addition (silent overflow)",
            Self::WrappingSub => "Wrapping subtraction (silent underflow)",
            Self::OverflowingAdd => "Overflowing addition returning overflow flag",
            Self::OrdinaryAdd => "Ordinary addition (debug overflow checks)",
            Self::OrdinarySub => "Ordinary subtraction (debug overflow checks)",
            Self::OrdinaryMul => "Ordinary multiplication (debug overflow checks)",
            Self::OrdinaryDiv => "Ordinary division (debug zero-division checks)",
            Self::UncheckedAdd => "Unchecked addition via unsafe (no checks)",
            Self::UncheckedSub => "Unchecked subtraction via unsafe (no checks)",
            Self::RefCellBorrow => "RefCell::borrow() - runtime borrow check",
            Self::RefCellBorrowMut => "RefCell::borrow_mut() - runtime exclusive borrow check",
            Self::CellGet => "Cell::get() - copy-based interior mutability",
            Self::CellSet => "Cell::set() - replace interior value",
            Self::UnsafeCellGet => "UnsafeCell::get() - raw pointer to interior",
            Self::BoxNew => "Box::new() - heap allocation",
            Self::VecPush => "Vec::push() - grow vector",
            Self::VecPop => "Vec::pop() - shrink vector",
            Self::VecIndex => "Vec indexing - bounds-checked access",
            Self::StringPush => "String::push() - append character",
            Self::StringLen => "String::len() - byte length",
            Self::Panic => "panic!() - immediate abort/trap",
            Self::Unwrap => "Option/Result::unwrap() - panic on None/Err",
            Self::Expect => "Option/Result::expect() - panic with message",
            Self::CatchUnwind => "catch_unwind - intercept panics",
            Self::IfLet => "if let pattern match",
            Self::MatchExhaustive => "Exhaustive match expression",
            Self::MatchNonExhaustive => "Non-exhaustive match (wildcard arm)",
            Self::LoopBreak => "Loop with conditional break",
            Self::ReturnEarly => "Early return from function",
            Self::HashMapIter => "HashMap iteration - non-deterministic order",
            Self::HashSetIter => "HashSet iteration - non-deterministic order",
            Self::BTreeMapIter => "BTreeMap iteration - deterministic order",
            Self::VecIter => "Vector iteration - deterministic order",
            Self::CfgWasm32Branch => "cfg(target_arch = \"wasm32\") conditional code",
            Self::TargetArchCheck => "Runtime target architecture check",
            Self::OsCheck => "Runtime OS check",
            Self::UnsafeBlock => "Unsafe block",
            Self::UnsafeFn => "Unsafe function",
            Self::Transmute => "std::mem::transmute - bit-level reinterpretation",
            Self::MaybeUninit => "MaybeUninit - uninitialized memory",
            Self::EnvStorageGet => "env.storage().get() - persistent storage read",
            Self::EnvStorageSet => "env.storage().set() - persistent storage write",
            Self::EnvStorageHas => "env.storage().has() - storage existence check",
            Self::EnvInvokeContract => "env.invoke_contract() - cross-contract call",
            Self::EnvLedgerGet => "env.ledger() - ledger metadata access",
            Self::EnvCurrentContractAddress => "env.current_contract_address()",
            Self::EnvRequireAuth => "env.require_auth() - authorization check",
            Self::EnvAlloc => "env.alloc() - VM memory allocation",
        }
    }
}

/// Represents a WASM-level pattern that a Rust construct compiles to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WasmPattern {
    // ── Arithmetic ──
    I128Add,
    I128Sub,
    I128Mul,
    I128Div,
    I64Add,
    I64Sub,
    I64Mul,
    I32Add,

    // ── Memory ──
    MemoryGrow,
    MemorySize,
    I32Load,
    I32Store,
    I64Load,
    I64Store,
    I128Load,
    I128Store,
    I32Load8U,
    I32Store8,

    // ── Control Flow ──
    Unreachable,
    Call,
    CallIndirect,
    Return,
    Br,
    BrIf,
    BrTable,
    If,
    Else,
    Loop,
    Block,
    End,

    // ── Locals ──
    LocalGet,
    LocalSet,
    LocalTee,
    GlobalGet,
    GlobalSet,

    // ── Traps ──
    TrapOnOverflow,
    TrapOnDivisionByZero,
    TrapOnOutOfBounds,

    // ── Simd (for vectorization) ──
    I8x16Add,
    I16x8Add,

    /// Placeholder for unknown/not-yet-mapped patterns.
    Unknown(String),
}

impl WasmPattern {
    pub fn can_trap(&self) -> bool {
        matches!(
            self,
            Self::Unreachable
                | Self::TrapOnOverflow
                | Self::TrapOnDivisionByZero
                | Self::TrapOnOutOfBounds
        )
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::I128Add => "128-bit integer addition",
            Self::I128Sub => "128-bit integer subtraction",
            Self::I128Mul => "128-bit integer multiplication",
            Self::I128Div => "128-bit integer division",
            Self::I64Add => "64-bit integer addition",
            Self::I64Sub => "64-bit integer subtraction",
            Self::I64Mul => "64-bit integer multiplication",
            Self::I32Add => "32-bit integer addition",
            Self::MemoryGrow => "Grow linear memory by pages",
            Self::MemorySize => "Get current memory size in pages",
            Self::I32Load => "Load 32-bit from memory",
            Self::I32Store => "Store 32-bit to memory",
            Self::I64Load => "Load 64-bit from memory",
            Self::I64Store => "Store 64-bit to memory",
            Self::I128Load => "Load 128-bit from memory",
            Self::I128Store => "Store 128-bit to memory",
            Self::I32Load8U => "Load unsigned 8-bit from memory",
            Self::I32Store8 => "Store 8-bit to memory",
            Self::Unreachable => "Unreachable (trap immediately)",
            Self::Call => "Direct function call",
            Self::CallIndirect => "Indirect function call via table",
            Self::Return => "Return from function",
            Self::Br => "Unconditional branch",
            Self::BrIf => "Conditional branch",
            Self::BrTable => "Branch table (switch)",
            Self::If => "If block start",
            Self::Else => "Else block start",
            Self::Loop => "Loop block start",
            Self::Block => "Block start",
            Self::End => "Block end",
            Self::LocalGet => "Get local variable",
            Self::LocalSet => "Set local variable",
            Self::LocalTee => "Set local and leave on stack",
            Self::GlobalGet => "Get global variable",
            Self::GlobalSet => "Set global variable",
            Self::TrapOnOverflow => "Trap on arithmetic overflow",
            Self::TrapOnDivisionByZero => "Trap on division by zero",
            Self::TrapOnOutOfBounds => "Trap on out-of-bounds access",
            Self::I8x16Add => "16x8-bit SIMD add",
            Self::I16x8Add => "8x16-bit SIMD add",
            Self::Unknown(_) => "Unknown WASM pattern",
        }
    }
}

/// A single Rust → WASM compilation mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirToWasmMapping {
    pub rust_pattern: RustPattern,
    pub wasm_patterns: Vec<WasmPattern>,
    pub is_optimization_sensitive: bool,
    /// Optimization levels where divergence occurs.
    pub divergent_at: Vec<String>,
    pub notes: String,
}

/// The full Compilation Chain Model — 50+ Rust-to-WASM mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationChainModel {
    pub mappings: Vec<MirToWasmMapping>,
    pub target: String,
    pub total_mappings: usize,
}

impl Default for CompilationChainModel {
    fn default() -> Self {
        Self::new()
    }
}

impl CompilationChainModel {
    pub fn new() -> Self {
        let mappings = Self::build_all_mappings();
        let total = mappings.len();
        Self {
            mappings,
            target: "wasm32-unknown-unknown".to_string(),
            total_mappings: total,
        }
    }

    /// Build the 50+ Rust → WASM mappings.
    fn build_all_mappings() -> Vec<MirToWasmMapping> {
        vec![
            // ── Arithmetic Mappings ──
            Self::mapping(
                RustPattern::CheckedAdd,
                vec![WasmPattern::I128Add, WasmPattern::TrapOnOverflow],
                false,
                "CheckedAdd compiles to i128.add with trap-on-overflow enabled",
            ),
            Self::mapping(
                RustPattern::CheckedSub,
                vec![WasmPattern::I128Sub, WasmPattern::TrapOnOverflow],
                false,
                "CheckedSub compiles to i128.sub with trap-on-overflow enabled",
            ),
            Self::mapping(
                RustPattern::CheckedMul,
                vec![WasmPattern::I128Mul, WasmPattern::TrapOnOverflow],
                false,
                "CheckedMul compiles to i128.mul with trap-on-overflow enabled",
            ),
            Self::mapping(
                RustPattern::OrdinaryAdd,
                vec![WasmPattern::I128Add],
                true,
                "Ordinary + in release: overflow checks removed by LLVM",
            ),
            Self::mapping(
                RustPattern::WrappingAdd,
                vec![WasmPattern::I128Add],
                false,
                "Wrapping add → plain i128.add (wrapping semantics built into WASM)",
            ),
            Self::mapping(
                RustPattern::SaturatingAdd,
                vec![WasmPattern::I128Add, WasmPattern::If, WasmPattern::Else],
                false,
                "Saturating add → compare + branch + add (multi-instruction pattern)",
            ),
            Self::mapping(
                RustPattern::UncheckedAdd,
                vec![WasmPattern::I128Add],
                false,
                "Unchecked add → bare i128.add — NO overflow protection",
            ),
            // ── Memory / Borrowing Mappings ──
            Self::mapping(
                RustPattern::RefCellBorrow,
                vec![WasmPattern::I32Load, WasmPattern::I32Store, WasmPattern::If],
                true,
                "RefCell borrow → load counter, check, store. LLVM can optimize away checks at -O2",
            ),
            Self::mapping(
                RustPattern::RefCellBorrowMut,
                vec![WasmPattern::I32Load, WasmPattern::I32Store, WasmPattern::If, WasmPattern::Unreachable],
                true,
                "RefCell borrow_mut → load counter, check=0, set -1. Panic → unreachable trap",
            ),
            Self::mapping(
                RustPattern::CellGet,
                vec![WasmPattern::I32Load],
                false,
                "Cell::get → simple memory load (Copy type)",
            ),
            Self::mapping(
                RustPattern::CellSet,
                vec![WasmPattern::I32Store],
                false,
                "Cell::set → simple memory store",
            ),
            Self::mapping(
                RustPattern::VecPush,
                vec![WasmPattern::MemoryGrow, WasmPattern::I32Store],
                false,
                "Vec::push → potentially grows memory, then stores element",
            ),
            Self::mapping(
                RustPattern::VecIndex,
                vec![WasmPattern::I32Load, WasmPattern::TrapOnOutOfBounds],
                false,
                "Vec indexing → bounds check + memory load. Out-of-bounds → WASM trap",
            ),
            // ── Control Flow Mappings ──
            Self::mapping(
                RustPattern::Panic,
                vec![WasmPattern::Unreachable],
                true,
                "panic! → unreachable. LLVM can optimize away preceding code at higher opt levels",
            ),
            Self::mapping(
                RustPattern::Unwrap,
                vec![WasmPattern::If, WasmPattern::Else, WasmPattern::Unreachable],
                true,
                "unwrap → check + branch. The unreachable trap can disappear if LLVM proves infallibility",
            ),
            Self::mapping(
                RustPattern::Expect,
                vec![WasmPattern::If, WasmPattern::Else, WasmPattern::Unreachable],
                true,
                "expect → same as unwrap but with a static string payload",
            ),
            Self::mapping(
                RustPattern::CatchUnwind,
                vec![WasmPattern::Call, WasmPattern::If, WasmPattern::Else],
                false,
                "catch_unwind → call + landing pad check. No WASM exception handling — emulated",
            ),
            // ── Collections Mappings ──
            Self::mapping(
                RustPattern::HashMapIter,
                vec![WasmPattern::Call, WasmPattern::I32Load],
                false,
                "HashMap iteration → calls SipHash-based iterator. Order depends on hash seeds",
            ),
            Self::mapping(
                RustPattern::HashSetIter,
                vec![WasmPattern::Call, WasmPattern::I32Load],
                false,
                "HashSet iteration → same non-deterministic behavior as HashMap",
            ),
            Self::mapping(
                RustPattern::BTreeMapIter,
                vec![WasmPattern::I32Load, WasmPattern::BrIf],
                false,
                "BTreeMap iteration → deterministic in-order tree traversal",
            ),
            // ── Unsafe Mappings ──
            Self::mapping(
                RustPattern::UnsafeBlock,
                vec![WasmPattern::I32Load, WasmPattern::I32Store],
                false,
                "Unsafe block → raw memory ops. No bounds checking in WASM emit",
            ),
            Self::mapping(
                RustPattern::Transmute,
                vec![],
                false,
                "Transmute → zero WASM instructions (type-level operation only)",
            ),
            // ── Soroban-Specific Mappings ──
            Self::mapping(
                RustPattern::EnvStorageGet,
                vec![WasmPattern::Call, WasmPattern::I32Load],
                false,
                "env.storage().get() → host call + memory load of result",
            ),
            Self::mapping(
                RustPattern::EnvStorageSet,
                vec![WasmPattern::Call, WasmPattern::I32Store],
                false,
                "env.storage().set() → memory store + host call",
            ),
            Self::mapping(
                RustPattern::EnvInvokeContract,
                vec![WasmPattern::Call, WasmPattern::CallIndirect],
                false,
                "Cross-contract call → host call with indirect call table lookup",
            ),
            Self::mapping(
                RustPattern::EnvRequireAuth,
                vec![WasmPattern::Call],
                false,
                "env.require_auth() → host call for authorization check",
            ),
            // ── Additional Mappings to reach 50+ ──
            Self::mapping(RustPattern::CheckedDiv, vec![WasmPattern::I128Div, WasmPattern::TrapOnDivisionByZero], false, "Checked division"),
            Self::mapping(RustPattern::OrdinaryDiv, vec![WasmPattern::I128Div], true, "Ordinary division in release"),
            Self::mapping(RustPattern::OverflowingAdd, vec![WasmPattern::I128Add, WasmPattern::If], false, "Overflowing add returns overflow bit"),
            Self::mapping(RustPattern::BoxNew, vec![WasmPattern::MemoryGrow, WasmPattern::I32Store], false, "Box allocation on heap"),
            Self::mapping(RustPattern::VecPop, vec![WasmPattern::I32Load, WasmPattern::I32Sub, WasmPattern::I32Store], false, "Vec pop shrinks length"),
            Self::mapping(RustPattern::StringPush, vec![WasmPattern::MemoryGrow, WasmPattern::I32Store8], false, "String push may grow"),
            Self::mapping(RustPattern::StringLen, vec![WasmPattern::I32Load], false, "String len is a load"),
            Self::mapping(RustPattern::IfLet, vec![WasmPattern::If, WasmPattern::Else, WasmPattern::End], false, "if let → pattern match branch"),
            Self::mapping(RustPattern::MatchExhaustive, vec![WasmPattern::BrTable, WasmPattern::End], false, "Exhaustive match → branch table"),
            Self::mapping(RustPattern::MatchNonExhaustive, vec![WasmPattern::BrTable, WasmPattern::Unreachable], false, "Wildcard arm → unreachable for uncovered"),
            Self::mapping(RustPattern::LoopBreak, vec![WasmPattern::Loop, WasmPattern::BrIf, WasmPattern::End], false, "Loop with break"),
            Self::mapping(RustPattern::ReturnEarly, vec![WasmPattern::Return], false, "Early return"),
            Self::mapping(RustPattern::VecIter, vec![WasmPattern::I32Load, WasmPattern::I32Add, WasmPattern::BrIf], false, "Vec iteration"),
            Self::mapping(RustPattern::CfgWasm32Branch, vec![WasmPattern::If, WasmPattern::Else], false, "Conditional compilation"),
            Self::mapping(RustPattern::UnsafeFn, vec![WasmPattern::Call], false, "Unsafe function call"),
            Self::mapping(RustPattern::MaybeUninit, vec![WasmPattern::I32Store], false, "MaybeUninit → unchecked store"),
            Self::mapping(RustPattern::EnvStorageHas, vec![WasmPattern::Call], false, "Storage existence check"),
            Self::mapping(RustPattern::EnvLedgerGet, vec![WasmPattern::Call, WasmPattern::I64Load], false, "Ledger metadata access"),
            Self::mapping(RustPattern::EnvCurrentContractAddress, vec![WasmPattern::Call], false, "Get contract address"),
            Self::mapping(RustPattern::EnvAlloc, vec![WasmPattern::MemoryGrow, WasmPattern::I32Add], false, "VM memory alloc"),
            Self::mapping(RustPattern::TargetArchCheck, vec![WasmPattern::If, WasmPattern::Else], false, "Target arch check"),
            Self::mapping(RustPattern::OsCheck, vec![WasmPattern::If, WasmPattern::Else], false, "OS check"),
            Self::mapping(RustPattern::UnsafeCellGet, vec![WasmPattern::I32Load], false, "UnsafeCell raw ptr"),
            Self::mapping(RustPattern::OrdinarySub, vec![WasmPattern::I128Sub], true, "Ordinary sub in release"),
            Self::mapping(RustPattern::OrdinaryMul, vec![WasmPattern::I128Mul], true, "Ordinary mul in release"),
        ]
    }

    fn mapping(
        rust: RustPattern,
        wasm: Vec<WasmPattern>,
        opt_sensitive: bool,
        notes: &str,
    ) -> MirToWasmMapping {
        let divergent = if opt_sensitive {
            vec!["-O2".into(), "-Os".into(), "-Oz".into()]
        } else {
            vec![]
        };
        MirToWasmMapping {
            rust_pattern: rust,
            wasm_patterns: wasm,
            is_optimization_sensitive: opt_sensitive,
            divergent_at: divergent,
            notes: notes.to_string(),
        }
    }

    /// Look up the WASM patterns for a given Rust pattern.
    pub fn lookup(&self, pattern: &RustPattern) -> Option<&MirToWasmMapping> {
        self.mappings.iter().find(|m| &m.rust_pattern == pattern)
    }

    /// Get all optimization-sensitive mappings.
    pub fn optimization_sensitive_mappings(&self) -> Vec<&MirToWasmMapping> {
        self.mappings
            .iter()
            .filter(|m| m.is_optimization_sensitive)
            .collect()
    }

    /// Get all non-deterministic source patterns.
    pub fn non_deterministic_mappings(&self) -> Vec<&MirToWasmMapping> {
        self.mappings
            .iter()
            .filter(|m| m.rust_pattern.is_non_deterministic())
            .collect()
    }
}

/// Alias for backward compatibility in propagation module.
pub type CompilationMapping = MirToWasmMapping;
