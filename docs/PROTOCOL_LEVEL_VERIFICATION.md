# Protocol-Level Invariant Verification

## Overview

The Protocol-Level Invariant Verification system extends the scanner's invariant engine from individual contract analysis to complex, multi-contract Soroban protocol analysis. Real Soroban protocols involve 5–20 contracts working together — tokens, pools, factories, fee distributors, governance contracts, and oracles — and protocol-level invariants span multiple contracts.

## Protocol Manifest Format

A protocol is described in a YAML or JSON manifest file:

```yaml
name: SimpleDEX
description: A constant-product automated market maker
contracts:
  - name: token_a
    address: CAAAA...
    wasm_path: ./contracts/token_a.wasm
    role: Token
  - name: pool
    address: CBBBB...
    wasm_path: ./contracts/pool.wasm
    role: AMMPool
interactions:
  - from_contract: token_a
    from_function: transfer
    to_contract: pool
    to_function: swap
invariants:
  - name: constant_product
    description: Reserve product before and after non-swap operations must be constant
    expression: "reserve_x[pool] * reserve_y[pool] == k_constant"
    kind: Economic
    spans_contracts:
      - pool
    status: Unknown
    auto_inferred: false
```

### Contract Roles

| Role | Description |
|------|-------------|
| `Token` | ERC-20-like fungible token contract |
| `AMMPool` | Automated market maker / liquidity pool |
| `LendingPool` | Lending/borrowing pool |
| `Factory` | Contract factory |
| `FeeDistributor` | Fee distribution contract |
| `Governance` | Governance/voting contract |
| `Oracle` | Price oracle |
| `Vault` | Collateral vault (e.g. for stablecoins) |
| `Bridge` | Cross-chain bridge |
| `StakingPool` | Staking rewards pool |
| `Other` | Custom role (supply a string name) |

### Invariant Specification DSL

The `expression` field uses a simple DSL:

- **Arithmetic**: `+`, `-`, `*`, `/`, `==`, `>=`, `<=`, `!=`
- **Summation**: `sum(balances[token_a])`
- **Collection access**: `balances[pool][token_x]`, `total_supply[token_a]`
- **Temporal operators**: `before(swap)`, `after(swap)` (used in simulation)

### Invariant Kinds

- **Structural**: Provable from the code alone via static analysis
- **Economic**: Requires simulation or market dynamics to check
- **Hybrid**: Partly structural, partly economic

## Auto-Inference Rules

For common protocol patterns, invariants are automatically inferred:

| Pattern | Auto-Inferred Invariant |
|---------|------------------------|
| AMM Pool | `reserve_x * reserve_y == k_constant` |
| AMM Pool | `reserve_x >= 0 && reserve_y >= 0` |
| Lending Pool | `total_deposits >= total_loans` |
| Bridge | `locked[soroban] == minted[counterpart]` |
| Governance | `total_voting_power == sum(delegated_power)` |
| Token | `total_supply == sum(balances)` |
| Token | `forall a: balance[a] >= 0` |
| Vault | `total_supply[stablecoin] * ratio <= sum(collateral_value)` |
| Staking Pool | `total_staked == token_balance` |

## Static vs Dynamic Verification Strategy

### Static Analysis
- Used for **Structural** invariants
- Applies modular verification: prove each individual contract function satisfies pre/post-conditions, then compose across the call graph
- Falls back to bounded model checking for protocols that don't fit the SMT model

### Dynamic Simulation
- Used for **Economic** invariants
- Initializes all contracts with genesis state
- Generates random sequences of user operations (swaps, deposits, borrows, repays, liquidations)
- Checks all protocol invariants after each operation
- Reports violation sequences with reproduction steps
- Default: 100,000 simulation steps

## Simulation Configuration

The simulator supports the following operations:
- Swap, Deposit, Borrow, Repay, Liquidate
- Mint, Burn, Transfer
- Stake, Unstake, Claim Rewards

Coverage is tracked per contract and reported as a heatmap.

## Protocol Health Reports

The `ProtocolHealth` dashboard shows:
- All defined invariants with verification status (✓ Verified / ⚠ Unknown / ✗ Violated)
- Protocol call graph with invariant annotations
- Simulation coverage heatmap
- Recent invariant violations with reproduction steps

## CLI Usage

```bash
# Run protocol verification with default 100,000 simulation steps
soroban-scanner protocol-verify --manifest protocol.yaml

# Run with custom simulation steps
soroban-scanner protocol-verify --manifest protocol.yaml --simulation-steps 50000

# Output as JSON
soroban-scanner protocol-verify --manifest protocol.yaml --format json

# Save to file
soroban-scanner protocol-verify --manifest protocol.yaml --output report.json

# Verbose mode
soroban-scanner protocol-verify --manifest protocol.yaml --verbose
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All invariants hold |
| 1 | At least one invariant is violated |
| 2 | At least one invariant is unprovable/unknown |

## Interpreting Results

1. **Verified invariants (✓)**: These hold under the verification performed. Continue to monitor.
2. **Unknown invariants (⚠)**: Could not be proven or disproven. May need manual review or increased simulation steps.
3. **Violated invariants (✗)**: A concrete violation sequence was found. Review the reproduction steps to understand and fix the issue.

## Example: DEX Protocol

```yaml
name: Soroswap
description: Soroban-based Uniswap v2 fork
contracts:
  - name: factory
    address: CAAA...
    wasm_path: ./factory.wasm
    role: Factory
  - name: pair
    address: CBBB...
    wasm_path: ./pair.wasm
    role: AMMPool
  - name: router
    address: CCCC...
    wasm_path: ./router.wasm
    role: Other("Router")
  - name: token_x
    address: CDDD...
    wasm_path: ./token_x.wasm
    role: Token
  - name: token_y
    address: CEEE...
    wasm_path: ./token_y.wasm
    role: Token
interactions:
  - from_contract: router
    from_function: swap_exact_tokens_for_tokens
    to_contract: pair
    to_function: swap
  - from_contract: pair
    from_function: swap
    to_contract: token_x
    to_function: transfer
  - from_contract: pair
    from_function: swap
    to_contract: token_y
    to_function: transfer
invariants:
  - name: pair_constant_product
    description: "x * y = k after each swap (minus fees)"
    expression: "reserve_x[pair] * reserve_y[pair] >= k_constant[pair]"
    kind: Economic
    spans_contracts:
      - pair
      - token_x
      - token_y
  - name: total_liquidity_consistent
    description: "Total LP tokens == sum of user LP balances"
    expression: "total_supply[pair_lp] == sum(balances[pair_lp])"
    kind: Structural
    spans_contracts:
      - pair
```
