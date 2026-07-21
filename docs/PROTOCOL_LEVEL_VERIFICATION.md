# Protocol-Level Invariant Verification

## Overview

Real Soroban protocols involve 5–20 contracts working together: token contracts, pool contracts, factory contracts, fee distributors, governance contracts, and oracles. Single-contract invariant checking cannot verify properties that span multiple contracts.

This system provides **protocol-level invariant verification** — it ingests a protocol specification, extracts invariants from developer annotations or auto-infers them, verifies them using static analysis and dynamic simulation, and reports violations with cross-contract call sequences.

## Protocol Manifest Format

Protocols are described using a YAML or JSON manifest file (`protocol.yaml` or `protocol.json`).

### Example: DEX Protocol

```yaml
name: "SorobanDEX"
version: "1.0.0"
description: "A decentralized exchange on Soroban"
contracts:
  - name: pool_a
    address: "CA3D5K7FJ9..."
    wasm_path: "./pool.wasm"
    role: amm_pool
    functions:
      - name: swap
        mutability: write
      - name: add_liquidity
        mutability: write
    storage_keys:
      - reserve_x
      - reserve_y
      - k
  - name: token_x
    role: token
    functions:
      - name: transfer
        mutability: write
interactions:
  - from_contract: pool_a
    from_function: swap
    to_contract: token_x
    to_function: transfer
invariants:
  - name: constant_product
    description: "reserve_x * reserve_y = k"
    expression:
      type: eq
      left:
        type: mul
        left:
          type: storage
          contract: pool_a
          key: reserve_x
        right:
          type: storage
          contract: pool_a
          key: reserve_y
      right:
        type: storage
        contract: pool_a
        key: k
    severity: critical
    category: dex
```

### Contract Roles

| Role | Label | Auto-Inferred Invariants |
|------|-------|-------------------------|
| AMM Pool | `amm_pool` | `reserve_x * reserve_y == k` |
| Token | `token` | — |
| Lending Pool | `lending_pool` | `total_deposits >= total_loans` |
| Bridge | `bridge` | `locked_soroban == minted_counterpart` |
| Governance | `governance` | `total_voting_power == sum(delegated_power)` |
| Factory | `factory` | — |
| Oracle | `oracle` | — |
| Fee Distributor | `fee_distributor` | — |
| Treasury | `treasury` | — |

## Expression DSL

Invariants use an internally-tagged JSON/YAML expression DSL.

### Expression Types

| Tag | Fields | Description |
|-----|--------|-------------|
| `literal` | `value: number` | Numeric constant |
| `string` | `value: string` | String constant |
| `bool` | `value: bool` | Boolean constant |
| `storage` | `contract, key` | Read storage value |
| `add` / `sub` / `mul` / `div` | `left, right` | Arithmetic |
| `eq` / `neq` / `gte` / `lte` / `gt` / `lt` | `left, right` | Comparison |
| `and` / `or` | `left, right` | Logical |
| `not` | `inner` | Logical NOT |
| `implies` | `antecedent, consequent` | Implication |
| `sum` | `items: [expr]` | Sum of expressions |
| `before` | `operation, expr` | Value before operation |
| `after` | `operation, expr` | Value after operation |
| `for_all` | `variable, collection, condition` | Universal quantifier |

### Storage-Access Shorthands

| Tag | Fields | Description |
|-----|--------|-------------|
| `reserve` | `pool, token` | AMM reserve for token |
| `constant_k` | `pool` | AMM constant product K |
| `total_supply` | `token` | Total token supply |
| `total_deposits` | `pool` | Total deposits in lending pool |
| `total_loans` | `pool` | Total loans in lending pool |
| `locked_soroban` | `bridge` | Tokens locked on Soroban |
| `minted_counterpart` | `bridge` | Tokens minted on counterpart |
| `total_voting_power` | `gov` | Total governance voting power |
| `sum_delegated_power` | `gov` | Total delegated voting power |

## CLI Usage

```bash
# Run protocol verification
stellar-scanner protocol-verify --manifest protocol.yaml

# Customize simulation
stellar-scanner protocol-verify --manifest protocol.yaml \
    --simulation-steps 50000 \
    --verbose

# Disable adversarial exploration (faster)
stellar-scanner protocol-verify --manifest protocol.yaml \
    --no-adversarial

# JSON output
stellar-scanner protocol-verify --manifest protocol.yaml \
    --format json --output report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All invariants verified |
| 1 | Invariant violations detected |
| 2 | Some invariants could not be proven |

## Architecture

### Phase 1 — Protocol Specification Format
Protocol manifest parser supporting YAML and JSON with a rich expression DSL for invariant specification.

### Phase 2 — Auto-Inference
Pattern matching engine that detects common protocol patterns (AMM, Lending, Bridge, Governance) from function signatures and storage layout, auto-inferring appropriate invariants with confidence levels.

### Phase 3 — Static Analysis
Modular verification of structural invariants through pattern matching and symbolic reasoning about storage access patterns.

### Phase 4 — Dynamic Simulation
Economic invariant verification through Monte Carlo simulation: generates random sequences of user operations (swaps, deposits, borrows, etc.) and checks invariants after each step. Defaults to 100,000 simulation steps.

### Phase 5 — Call Graph Analysis
Builds a `ProtocolCallGraph` capturing protocol-level control flow: entry point → authentication → validation → core logic → state updates → event emission → cross-contract calls → cleanup. Identifies invariant-critical sections where invariants are temporarily broken.

### Phase 6 — Adversarial Exploration
An attacker agent searches for multi-contract exploit sequences that violate protocol invariants and produce profit. Detects sandwich attacks, flash loan attacks, and cross-contract manipulation.

### Phase 7 — Health Dashboard
Generates a comprehensive health report showing invariant verification status, simulation coverage, call graph annotations, and critical sections.

### Phase 8 — CI Integration
Drop-in CLI command with proper exit codes for CI/CD pipelines. Supports console, JSON, and file output formats.

## Integration with CI

```yaml
# GitHub Actions example
- name: Protocol Verification
  run: stellar-scanner protocol-verify --manifest protocol.yaml --format json --output protocol-report.json
- name: Check Exit Code
  run: |
    if [ $? -eq 1 ]; then
      echo "Protocol invariants violated!"
      exit 1
    fi
```
