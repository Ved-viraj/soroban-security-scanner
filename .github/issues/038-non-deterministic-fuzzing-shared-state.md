# Issue 38: [Differential Fuzzing] Non-Deterministic Test Execution from Shared Mutable State Across Concurrent Fuzzing Workers

**Priority:** 🟠 High
**Labels:** `bug` `differential-fuzzing` `concurrency` `core-scanner`
**Area:** Core Scanner / Correctness
**Files:** `src/differential_fuzzing/test_runner.rs`, `src/differential_fuzzing/input_generator.rs`, `src/differential_fuzzing/execution_tracer.rs`

## Description

The `TestRunner` in `src/differential_fuzzing/test_runner.rs` orchestrates multi-SDK-version execution of generated test inputs. When run with `parallel = true` (the default for performance), multiple `ExecutionTracer` instances execute concurrently against shared mutable state in the `LedgerSnapshotIntegration`. The `execution_tracer.rs` module reads and writes to a shared `HashMap<ContractId, ContractState>` without per-contract locking granularity — it uses a single `RwLock` around the entire state map. Under high concurrency (16+ workers), this creates a bottleneck that can cause: (a) deadlocks when one tracer holds a read lock while another waits for a write lock on the same map, (b) non-deterministic execution order where Contract A's state mutation by Worker 1 interleaves with Contract B's state read by Worker 2 causing different results on different runs, and (c) silent data races if `RwLock` acquires are not uniformly applied across all code paths. For a differential fuzzer whose entire purpose is to detect behavioral discrepancies across SDK versions, non-deterministic execution defeats the core detection algorithm — the fuzzer cannot distinguish between a genuine SDK discrepancy and a test-ordering artifact, producing both false positives and false negatives.

## Acceptance Criteria

- [ ] Replace the single global `RwLock<HashMap<ContractId, ContractState>>` with a `DashMap<ContractId, RwLock<ContractState>>` (per-contract locking)
- [ ] Implement deterministic test ordering: sort generated inputs by a stable hash before distributing to workers
- [ ] Add execution trace recording: each worker logs `[timestamp, contract_id, operation, pre_state_hash, post_state_hash]` for post-hoc determinism verification
- [ ] Add a `--verify-determinism` mode that runs the same input set twice and compares results — any difference is a bug in the runner, not the contract
- [ ] Add a `max_concurrency` cap based on available CPU cores, with a warning if `parallel_workers > num_cpus`
- [ ] Implement a deadlock detection watchdog: if any `RwLock::write()` takes > 5 seconds, log all held locks and abort the fuzzing run
- [ ] Write a concurrency stress test that runs 1000 inputs across 32 virtual workers and verifies deterministic output across 10 repeated runs
- [ ] Update `docs/DIFFERENTIAL_FUZZING.md` (create if needed) with determinism guarantees and known limitations

## Additional Context

- Non-deterministic fuzzing defeats the core purpose of differential analysis
- The `DashMap` approach provides per-contract granularity without a global bottleneck
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
