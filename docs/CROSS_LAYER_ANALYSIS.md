# Cross-Layer Vulnerability Propagation Analysis

## Overview

The Cross-Layer Vulnerability Propagation Analysis module (#447) traces how
vulnerabilities propagate across the Rust → WASM → Soroban VM compilation
stack. No existing tool performs this kind of multi-layer analysis — 
vulnerabilities invisible at a single layer become detectable when the
interaction between layers is modeled.

## Architecture

```
Rust Source ──► RustAnalyzer ──┐
                               ├──► Propagation Engine ──► CrossLayerReport
WASM Binary ──► WasmAnalyzer ──┤
                               │
VM Trace    ──► VmAnalyzer ────┘
```

## Compilation Chain Model

The module includes 50+ Rust MIR → WASM opcode mappings for the
`wasm32-unknown-unknown` target, covering:

- **Arithmetic:** CheckedAdd, WrappingAdd, SaturatingAdd, UncheckedAdd, etc.
- **Memory/Borrowing:** RefCell, Cell, UnsafeCell, Vec, Box
- **Control Flow:** panic!, unwrap, expect, catch_unwind
- **Collections:** HashMap, HashSet, BTreeMap iteration (non-determinism)
- **Platform-Specific:** cfg(target_arch = "wasm32") branches
- **Unsafe:** Unsafe blocks, transmute, MaybeUninit
- **Soroban-Specific:** env.storage(), env.invoke_contract(), env.require_auth()

## Key Capabilities

### Multi-Layer IR (Phase 1)
Unified `CrossLayerIr` representing contract behavior at three levels:

| Layer | Source | Representation |
|-------|--------|---------------|
| Rust MIR | rustc driver output | MirInstruction with MIR kind |
| WASM | .wasm binary | WasmInstruction with opcode mnemonic |
| Soroban VM | Host function call trace | VmInstruction with host function name |

### Optimization Sensitivity (Phase 6)
Recompile with different optimization levels (`-O0`, `-O1`, `-O2`, `-Os`, `-Oz`)
to detect findings that only appear at certain optimization levels.
Flagged as "optimization-sensitive vulnerabilities" with high severity.

### Cross-Layer Propagation (Phase 5)
For each finding at one layer, determines if it manifests at another:

| Rust | WASM | VM Impact |
|------|------|-----------|
| RefCell::borrow_mut() panic | i32.load/i32.store/unreachable | State rollback, inconsistent state |
| HashMap::iter() | SipHash-based call | Non-deterministic validator execution |
| checked_add().unwrap() | i128.add (optimized to unchecked) | Silent overflow |
| panic!() | unreachable | VM trap, partial state rollback |

## Report Format

Three-column table: **Rust Finding → WASM Manifestation → VM Impact**

Each row includes:
- Worst severity across all layers
- Confidence score (Certain/Likely/Speculative)
- Optimization sensitivity flag
- Exploitability assessment

## Known False Positives

- **LLVM proving optimizations:** LLVM may correctly prove an overflow is
  impossible based on function preconditions. The analysis flags these as
  "optimization-sensitive" rather than definite vulnerabilities.
- **DWARF debug info:** Debug-mode DWARF sections may reference panic paths
  that are unreachable in release builds.
- **Non-deterministic iteration:** HashMap iteration is flagged even when
  the order is not observed or used for consensus.

## Writing Compilation-Safe Soroban Contracts

1. **Use checked arithmetic** (`checked_add`, `checked_sub`) — never rely on
   debug-mode overflow checks in production.
2. **Avoid HashMap/HashSet** for data that affects consensus — use BTreeMap
   for deterministic iteration.
3. **Avoid RefCell** in contract state — use explicit state management with
   the environment's storage API.
4. **Never use cfg(debug_assertions)** for security checks — these are
   compiled away in release.
5. **Check all host function return values** — `env.storage().get()` returns
   `Option`, always handle the `None` case.
6. **Avoid catch_unwind** in Soroban contracts — panics should be allowed
   to propagate for correct state cleanup.

## Testing

```bash
cargo test --lib cross_layer_analysis --features broken-modules
```
