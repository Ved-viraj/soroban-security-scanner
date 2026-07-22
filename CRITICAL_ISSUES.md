# Soroban Security Scanner — 10 Hard & Critical Issues

> These are **novel, high-severity issues** not covered by the existing 30 issues in `ISSUES.md`.
> Each follows the standard `.github/ISSUE_TEMPLATE.md` format: detailed description + actionable acceptance criteria.

---

## Issue 31: [Admin MFA] HMAC-SHA1 Used for TOTP — Deprecated Legacy Algorithm Weakens Second-Factor Security

**Priority:** 🔴 Critical
**Area:** Security / Cryptography
**Files:** `src/admin_mfa/totp.rs`

**Description:**
The TOTP implementation in `src/admin_mfa/totp.rs` uses `ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY` for generating and verifying time-based one-time passwords. This constant's name is a clear signal from the `ring` maintainers that SHA-1 should not be used in new designs. SHA-1 has known collision vulnerabilities (SHAttered attack, 2017) and is being actively phased out across the industry. While HMAC-SHA1 is somewhat more resistant than plain SHA-1 to collision attacks, NIST SP 800-131A Rev. 2 disallows SHA-1 for digital signature generation after 2022, and major authenticator vendors (YubiKey, Google Authenticator) now default to SHA-256 for TOTP. The `hotp()` function in `totp.rs` hardcodes `HMAC_SHA1_FOR_LEGACY_USE_ONLY` with no configuration option for stronger algorithms. An attacker with sufficient resources could exploit SHA-1 weaknesses to forge valid TOTP codes, bypassing admin MFA entirely. Since admin accounts control scanner configuration, contract upgrades, and bounty payouts, a successful MFA bypass grants full platform compromise.

**Acceptance Criteria:**
- [ ] Replace `HMAC_SHA1_FOR_LEGACY_USE_ONLY` with `HMAC_SHA256` as the default algorithm in `TotpConfig`
- [ ] Add a `TotpAlgorithm` enum (`Sha1`, `Sha256`, `Sha512`) to `TotpConfig` for backward compatibility
- [ ] Default new `TotpConfig` instances to `Sha256`; mark `Sha1` as `#[deprecated]` with a migration warning
- [ ] Update `provisioning_uri()` to include `algorithm=SHA256` in the otpauth URI when using SHA-256
- [ ] Add a migration path: when verifying with SHA-256 fails, fall back to SHA-1 for legacy secrets, log a warning, and prompt the user to re-enroll
- [ ] Update all tests in `src/admin_mfa/totp.rs` to verify SHA-256 code generation/verification works correctly
- [ ] Add a test that explicitly verifies SHA-1 codes still verify for the migration path
- [ ] Document the algorithm change in a new migration note under `docs/`

---

## Issue 32: [WebAuthn] AcceptingVerifier Placeholder Has No Production Guard — Deployment Could Ship with Permissive Signature Bypass

**Priority:** 🔴 Critical
**Area:** Security / Authentication
**Files:** `src/admin_mfa/webauthn.rs`

**Description:**
The `AcceptingVerifier` in `src/admin_mfa/webauthn.rs` is explicitly documented as: "A permissive verifier used in tests and as a wiring placeholder. It checks only that a signature is present — **never** use it in production." This struct implements `AssertionVerifier` by returning `true` for any non-empty signature, completely bypassing all WebAuthn cryptographic verification. However, there is **no compile-time, runtime, or configuration guard** preventing this verifier from being used in production. The `MfaManager::verify_webauthn()` method accepts any `&dyn AssertionVerifier`, meaning if dependency injection accidentally wires in `AcceptingVerifier` instead of a real COSE verifier, all WebAuthn assertions will pass regardless of signature validity. Given that production deployments likely do not yet have a full COSE/CBOR verifier implemented (the code itself says "a production deployment can wire in a full COSE/CBOR verifier without this module pulling in a heavy crypto stack"), the risk of this placeholder reaching production is high. An attacker who discovers this could authenticate as any admin using any random bytes as a WebAuthn signature.

**Acceptance Criteria:**
- [ ] Add a `#[cfg(any(test, feature = "dangerous-accepting-verifier"))]` gate on `AcceptingVerifier` and its `impl AssertionVerifier`
- [ ] Add a runtime startup check in `main.rs` or config validation that panics or refuses to start if the feature flag is enabled and `ENV != "development"`
- [ ] Create a `CoseAssertionVerifier` stub (returning `Err` until wired) that is the default in non-test builds
- [ ] Add a `WebAuthnVerifierConfig` enum with variants `AcceptingTestOnly`, `CoseVerifier { ... }` that is validated at app startup
- [ ] Log a CRITICAL-level warning on every use of `AcceptingVerifier::verify()` in non-test builds
- [ ] Add an integration test that verifies the server refuses to start with `AcceptingVerifier` in production mode
- [ ] Document this requirement in `AUTHENTICATION_QUICK_START.md`

---

## Issue 33: [Transaction Engine] No Dead Letter Queue — Permanently Failed Transactions Leak Memory Indefinitely

**Priority:** 🔴 Critical
**Area:** Core Infrastructure / Memory Safety
**Files:** `src/transaction_engine/queue.rs`, `src/transaction_engine/processor.rs`

**Description:**
The `TransactionQueue` in `src/transaction_engine/queue.rs` manages transaction lifecycle states including `FailedPermanent`. When a transaction fails permanently (non-retryable failure), it is added to `inner.failed_permanent: Vec<Transaction>` which is **never pruned or capped**. The `cleanup_old_transactions()` method only cleans items where `metadata.updated_at > cutoff` from `completed` and `failed_permanent`, but permanent failures are matched against the same `cutoff` — however, permanent failures may have `updated_at` timestamps that are very recent (the failure happened now), meaning they remain in memory indefinitely. There is no maximum size on `failed_permanent`, no offloading to persistent storage, and no dead-letter queue abstraction. Over months of operation with high transaction volumes, this unbounded vector grows without limit, eventually causing OOM (Out of Memory) crashes. For a security scanner processing thousands of scan submissions daily, even a 1% permanent failure rate would accumulate millions of entries consuming gigabytes of RAM. Furthermore, there is no API or mechanism for operators to drain, export, or inspect the dead letter queue for forensic analysis.

**Acceptance Criteria:**
- [ ] Implement a `DeadLetterQueue<T>` generic type with configurable max size (default 10,000) and FIFO eviction
- [ ] Add a `DeadLetterEntry` struct wrapping `Transaction` with failure reason, timestamp, and a unique DLQ ID
- [ ] When `failed_permanent` exceeds `max_dlq_size`, evict the oldest entry and log a WARNING with the evicted transaction ID
- [ ] Add a `GET /api/v1/transactions/dead-letter` endpoint with pagination for inspection
- [ ] Add a `DELETE /api/v1/transactions/dead-letter/:id` endpoint for manual removal
- [ ] Add a `POST /api/v1/transactions/dead-letter/:id/requeue` endpoint to manually resubmit a dead-lettered transaction
- [ ] Implement optional DLQ persistence to database via the `database/models.rs` and `database/queries.rs` modules
- [ ] Add a `dlq_size` gauge to `ProcessorMetrics` exposed to monitoring
- [ ] Write tests that enqueue 200,000 permanent failures and verify memory stays bounded

---

## Issue 34: [Supply Chain] Dependency Integrity Not Cryptographically Verified — Malicious Package Substitution Possible

**Priority:** 🔴 Critical
**Area:** Security / Supply Chain
**Files:** `src/supply_chain/inventory.rs`, `src/supply_chain/integrity.rs`, `src/supply_chain/engine.rs`

**Description:**
The `SupplyChainGuard` in `src/supply_chain/engine.rs` maintains a `DependencyInventory` that tracks package names, versions, ecosystems, and licenses. The `src/supply_chain/integrity.rs` file exists as a module but performs **only hash computation on local files** — it does not verify those hashes against any trusted registry (crates.io checksums, npm integrity hashes from `package-lock.json`, or a vendor-maintained allowlist). The `Dependency::new()` constructor accepts any version string with no integrity verification. This means an attacker who compromises a build pipeline, CI runner, or dependency mirror could substitute a malicious package with the same name and version, and the supply chain scanner would ingest it without detecting the substitution. The `integrity.rs` module has functions like `compute_file_hash()` and `verify_file_integrity()` that compute SHA-256, but these are only called for local file verification, not for validating dependency provenance against a trusted source of truth. This defeats the entire purpose of the supply chain security module, which is designed to guarantee that dependencies are exactly what they claim to be.

**Acceptance Criteria:**
- [ ] Add a `VerifiedDependency` struct that wraps `Dependency` with a verified checksum from a trusted source
- [ ] Implement `crates.io` registry verification: validate Cargo.lock checksums against the crates.io index
- [ ] Implement npm registry verification: validate `package-lock.json` integrity hashes against the npm registry
- [ ] Add a `TrustedRegistry` abstraction with `verify(package, version, checksum) -> Result<()>` 
- [ ] Add a `--require-verified` CLI flag that rejects any dependency lacking a verified checksum
- [ ] Update `PostureReport` to include a `verified_dependencies` count and `unverified_dependencies: Vec<String>`
- [ ] When verification fails, emit a `CRITICAL`-level alert through `VulnAlerter` with the mismatched package details
- [ ] Write tests that verify a known-good dependency (e.g., `serde` at a pinned version) and a tampered dependency is rejected
- [ ] Update `DEPENDENCY_MANAGEMENT.md` (or create it) with verification process documentation

---

## Issue 35: [API Rate Limiting] In-Memory Token Buckets Have No Distributed Consistency — Rate Limits Bypassed Across Multi-Instance Deployments

**Priority:** 🔴 Critical
**Area:** Infrastructure / Rate Limiting
**Files:** `src/api_rate_limiting/limiter.rs`, `src/api_rate_limiting/store.rs`, `src/rate_limiting/limiter.rs`

**Description:**
The API rate limiting system across `src/api_rate_limiting/` and `src/rate_limiting/` implements token bucket and sliding window algorithms using in-memory data structures (RwLock-protected HashMaps). The `RateLimitStore` trait in `store.rs` has only an in-memory implementation. When the scanner is deployed across multiple instances behind a load balancer (the standard Kubernetes deployment described in `examples/kubernetes_isolated_scanning.rs`), each instance maintains **its own independent rate limit counters**. An attacker distributing requests across all instances can effectively multiply the rate limit by the number of pods — a 100 req/min limit becomes 300 req/min across 3 pods. For a security scanning platform that processes untrusted contract submissions, this is a critical bypass vector: an attacker can flood the system with malicious contracts designed to trigger expensive analysis paths (deep recursive fuzzing, large WASM parsing) across all instances simultaneously, causing a distributed denial-of-service despite rate limiting being nominally "enabled." The `RATE_LIMITING.md` documentation does not address distributed deployment considerations.

**Acceptance Criteria:**
- [ ] Implement a `RedisRateLimitStore` that uses Redis as a shared counter backend with Lua scripting for atomic token operations
- [ ] Add a `CentralizedStore` trait implementation configurable via `RateLimitConfig` with backends: `InMemory`, `Redis`, `Memcached`
- [ ] Implement clock-skew tolerance (±2 seconds) using NTP-synchronized timestamps in the Redis Lua scripts
- [ ] Add a graceful degradation mode: if Redis is unreachable, fall back to per-instance in-memory limiting with a `degraded_limit = configured_limit / instance_count` heuristic
- [ ] Create a `RateLimitConsistencyTest` in the test suite that simulates 3 instances processing overlapping request streams and verifies the aggregate limit is enforced
- [ ] Add a `GET /api/v1/rate-limits/status` debug endpoint showing per-client remaining quota across all instances
- [ ] Update `RATE_LIMITING.md` with distributed deployment guidance and Redis configuration examples

---

## Issue 36: [Encryption at Rest] Key Rotation Has No Dual-Key Read Window — Data Becomes Unreadable During Rotation

**Priority:** 🔴 Critical
**Area:** Security / Data Integrity
**Files:** `src/encryption_at_rest/service.rs`, `src/encryption_at_rest/keys.rs`, `src/encryption_at_rest/cipher.rs`

**Description:**
The encryption-at-rest module in `src/encryption_at_rest/` provides AES-256 field-level encryption with key management. The `KeyManager` in `keys.rs` supports key generation, storage, and rotation through `rotate_key()`. However, rotation is implemented as an **atomic key swap**: the old key is immediately replaced by the new key in the active key slot. Any data that was encrypted with the old key but has not yet been re-encrypted becomes permanently unreadable the moment rotation completes. In a production database with millions of encrypted rows, re-encrypting all data can take hours. During that window, any query that touches a row still encrypted with the old key will fail with a decryption error, causing cascading failures across all dependent services (bounty marketplace payouts, audit trail verification, wallet operations). The `EncryptionService` has no `try_decrypt_with_fallback()` method that attempts the new key first and falls back to recent historical keys. There is no key versioning embedded in the ciphertext (no KID/Key ID prefix), so the system cannot even determine which key was used to decrypt a given ciphertext without brute-forcing all known keys.

**Acceptance Criteria:**
- [ ] Add a 4-byte KID (Key ID) prefix to all ciphertexts identifying which key encrypted the data
- [ ] Implement a `KeyRing` that holds the active key plus up to N previous keys (default N=3) for the rotation window
- [ ] Add `encrypt_with_key_id()` and `decrypt_with_kid()` methods that use the KID prefix for routing
- [ ] Implement a background `reencrypt_batch()` worker that incrementally re-encrypts rows from old keys to the new key
- [ ] Expose re-encryption progress via `GET /api/v1/encryption/reencrypt-status` with `rows_remaining` and `estimated_completion`
- [ ] Add a `force_rotation_timeout` config: if re-encryption is not complete within the timeout, log CRITICAL and continue serving with both keys
- [ ] In `rotate_key()`, do NOT delete the old key — move it to `KeyRing.previous_keys` and only delete after re-encryption is confirmed complete
- [ ] Write tests: encrypt with key A → rotate to key B → decrypt old ciphertext → re-encrypt → verify old key can be safely removed
- [ ] Add a migration note documenting the ciphertext format change (KID prefix addition)

---

## Issue 37: [Severity Scoring] ML Model Trained on User-Contributed Labels — Adversarial Poisoning Can Downgrade Critical Vulnerabilities

**Priority:** 🟠 High
**Area:** AI/ML / Security
**Files:** `src/severity_scoring/ml.rs`, `src/severity_scoring/engine.rs`, `src/severity_scoring/context.rs`

**Description:**
The `severity_scoring/ml.rs` module implements a machine learning model for dynamic vulnerability severity scoring. According to the `SEVERITY_SCORING.md` documentation, this model learns from historical scan results to improve CVSS-based scoring accuracy. However, the training data source includes **user-submitted vulnerability reports** where the severity label is provided by the submitting researcher. A malicious actor can submit hundreds of crafted vulnerability reports where critical vulnerabilities (e.g., reentrancy with full fund drainage) are labeled as "Low" or "Info" severity. As the model retrains on this poisoned data, it gradually learns to downgrade genuinely critical vulnerabilities, causing the platform to under-prioritize severe findings. Since the bounty payout in `bounty_marketplace.rs` is tied to severity (via `RiskScore`), the attacker also financially benefits by reducing the payout owed to other researchers. The model has no anomaly detection on training labels (e.g., flagging when a user's severity rating differs from the CVSS base score by more than 3 levels), no training data provenance tracking, and no holdout validation set to detect model drift.

**Acceptance Criteria:**
- [ ] Add a `TrainingDataProvenance` struct tracking: submitter ID, submission timestamp, CVSS vector, and user-provided label for every training sample
- [ ] Implement label anomaly detection: if `|user_label - cvss_base_score| > 2.0`, flag the sample for human review and exclude from automated training
- [ ] Add a `--poisoning-threshold` CLI flag: if any submitter contributes > N% of training data with anomalous labels, quarantine ALL their submissions and alert admins
- [ ] Implement a holdout validation set (20% of data) to detect model accuracy degradation after each training epoch — if accuracy drops > 5%, roll back to previous model
- [ ] Add model versioning with `ModelSnapshot { version, trained_at, accuracy, data_hash }` stored in the database
- [ ] Expose model health via `GET /api/v1/ml/model-health` with accuracy trend, training sample distribution, and flagged submitters
- [ ] Write adversarial tests: inject 100 poisoned labels and verify the model does NOT change severity by more than 0.5 points on a held-out benchmark
- [ ] Document the anti-poisoning measures in `docs/SEVERITY_SCORING.md`

---

## Issue 38: [Differential Fuzzing] Non-Deterministic Test Execution from Shared Mutable State Across Concurrent Fuzzing Workers

**Priority:** 🟠 High
**Area:** Core Scanner / Correctness
**Files:** `src/differential_fuzzing/test_runner.rs`, `src/differential_fuzzing/input_generator.rs`, `src/differential_fuzzing/execution_tracer.rs`

**Description:**
The `TestRunner` in `src/differential_fuzzing/test_runner.rs` orchestrates multi-SDK-version execution of generated test inputs. When run with `parallel = true` (the default for performance), multiple `ExecutionTracer` instances execute concurrently against shared mutable state in the `LedgerSnapshotIntegration`. The `execution_tracer.rs` module reads and writes to a shared `HashMap<ContractId, ContractState>` without per-contract locking granularity — it uses a single `RwLock` around the entire state map. Under high concurrency (16+ workers), this creates a bottleneck that can cause: (a) deadlocks when one tracer holds a read lock while another waits for a write lock on the same map, (b) non-deterministic execution order where Contract A's state mutation by Worker 1 interleaves with Contract B's state read by Worker 2 causing different results on different runs, and (c) silent data races if `RwLock` acquires are not uniformly applied across all code paths. For a differential fuzzer whose entire purpose is to detect behavioral discrepancies across SDK versions, non-deterministic execution defeats the core detection algorithm — the fuzzer cannot distinguish between a genuine SDK discrepancy and a test-ordering artifact, producing both false positives and false negatives.

**Acceptance Criteria:**
- [ ] Replace the single global `RwLock<HashMap<ContractId, ContractState>>` with a `DashMap<ContractId, RwLock<ContractState>>` (per-contract locking)
- [ ] Implement deterministic test ordering: sort generated inputs by a stable hash before distributing to workers
- [ ] Add execution trace recording: each worker logs `[timestamp, contract_id, operation, pre_state_hash, post_state_hash]` for post-hoc determinism verification
- [ ] Add a `--verify-determinism` mode that runs the same input set twice and compares results — any difference is a bug in the runner, not the contract
- [ ] Add a `max_concurrency` cap based on available CPU cores, with a warning if `parallel_workers > num_cpus`
- [ ] Implement a deadlock detection watchdog: if any `RwLock::write()` takes > 5 seconds, log all held locks and abort the fuzzing run
- [ ] Write a concurrency stress test that runs 1000 inputs across 32 virtual workers and verifies deterministic output across 10 repeated runs
- [ ] Update `docs/DIFFERENTIAL_FUZZING.md` (create if needed) with determinism guarantees and known limitations

---

## Issue 39: [Security Monitoring] SIEM Integration Is Stub-Only — No Real Alert Delivery to External Security Platforms

**Priority:** 🟠 High
**Area:** Security Operations / Monitoring
**Files:** `src/security_monitoring/siem.rs`, `src/security_monitoring/alerting.rs`, `src/security_monitoring/engine.rs`

**Description:**
The `src/security_monitoring/siem.rs` module is designed to integrate the platform's security events with external SIEM systems (Splunk, Elastic, Datadog, etc.). However, the module contains only type definitions, stub functions, and `// TODO: Implement SIEM connector` comments throughout. The `SecurityMonitoringEngine` in `engine.rs` calls `siem.forward_alert()` but the implementation is a no-op that logs and returns `Ok(())`. The `alerting.rs` module defines `AlertChannel::Siem` and `AlertDestination` but there is no code path that actually serializes alerts to SIEM-compatible formats (CEF, LEEF, JSON Syslog) or sends them over TCP/TLS to a SIEM collector. For a platform positioned as "real-time security monitoring and incident response" (per commit `feat(security): real-time security monitoring and incident response (#333)`), this means production deployments have **zero external visibility** into security incidents. If the platform itself is compromised, there are no external alerts to notify the SOC team. Regulatory frameworks like SOC 2 and PCI DSS require centralized security monitoring with SIEM integration — the platform currently cannot satisfy these requirements.

**Acceptance Criteria:**
- [ ] Implement a `SiemForwarder` trait with methods: `send_alert()`, `send_event()`, `health_check()`, and `flush()`
- [ ] Create concrete implementations: `SplunkForwarder` (HTTP Event Collector), `ElasticForwarder` (Elasticsearch bulk API), `TcpSyslogForwarder` (RFC 5424)
- [ ] Implement CEF (Common Event Format) and JSON serialization for all `SecurityEvent` types
- [ ] Add retry logic with exponential backoff (3 attempts, 1s/5s/25s) for failed SIEM deliveries
- [ ] Implement a local ring buffer (max 10,000 events) that queues events when the SIEM is unreachable and replays on reconnect
- [ ] Add a `GET /api/v1/siem/status` endpoint showing each forwarder's health, queue depth, and last successful delivery time
- [ ] Add configuration in `config.rs` for SIEM endpoints, auth tokens, TLS settings, and batch sizes
- [ ] Write integration tests using a mock SIEM server (local TCP listener) that validates message format and delivery
- [ ] Update `docs/INCIDENT_RESPONSE.md` with SIEM integration setup instructions

---

## Issue 40: [Analysis Guard] Sandbox Escape Possible Through WASM Exploitation of Unvalidated Host Function Imports

**Priority:** 🔴 Critical
**Area:** Security / Sandbox
**Files:** `src/analysis_guard/sandbox.rs`, `src/analysis_guard/limits.rs`, `src/upload_sanitization/wasm.rs`

**Description:**
The `Sandbox` in `src/analysis_guard/sandbox.rs` executes untrusted Soroban WASM contracts in a resource-constrained environment with CPU/memory/timeout limits. The `upload_sanitization/wasm.rs` module validates WASM binaries before execution, checking for malformed modules and known malicious patterns. However, the sandbox relies on the Soroban VM's host function interface to provide limited capabilities to the contract under test. There is no validation that the WASM module's **import section** only references allowed host functions. A maliciously crafted contract could import host functions that the Soroban VM exposes but the sandbox expects to be unavailable — for example, functions that access the host filesystem, make network calls, or invoke system commands. The `wasm.rs` sanitizer checks WASM structure validity and magic bytes but does not parse the import section to build an allowlist of permitted host function signatures. An attacker who understands the Soroban host function ABI could craft a contract that imports `env.fs_read` or `env.exec` (if such functions exist in the VM) and escapes the sandbox to read scanner configuration files, encryption keys, or database credentials from the host filesystem.

**Acceptance Criteria:**
- [ ] Parse the WASM import section during sanitization and extract all `(import "env" "function_name" ...)` declarations
- [ ] Define a `HOST_FUNCTION_ALLOWLIST` containing only the host functions required for security scanning (e.g., `ledger.get`, `ledger.put`, `contract.call`, `log.log`)
- [ ] Reject any WASM module that imports a function not in the allowlist with error: `SandboxError::DisallowedHostFunction { function: String }`
- [ ] Add an `import_allowlist` configuration field to `SandboxConfig` for customizing allowed functions per deployment
- [ ] Implement a seccomp-bpf filter (Linux) or equivalent OS-level sandbox as a defense-in-depth layer around the WASM VM process
- [ ] Run the sandbox process under a dedicated non-root user with no filesystem access outside a tmpfs scratch directory
- [ ] Write an adversarial test: craft a WASM module that imports a forbidden host function and verify it is rejected during sanitization, NOT during execution
- [ ] Add a security audit checklist item to `SECURITY_IMPROVEMENTS.md` for periodic host function allowlist review

---

## Summary

| # | Issue Title | Priority | Area |
|---|-------------|----------|------|
| 31 | HMAC-SHA1 TOTP — Deprecated Legacy Algorithm | 🔴 Critical | Cryptography |
| 32 | AcceptingVerifier No Production Guard | 🔴 Critical | Authentication |
| 33 | No Dead Letter Queue — Unbounded Memory Leak | 🔴 Critical | Infra / Memory |
| 34 | Dependency Integrity Not Verified | 🔴 Critical | Supply Chain |
| 35 | Rate Limiting No Distributed Consistency | 🔴 Critical | Infra / Rate Limiting |
| 36 | Key Rotation Without Dual-Key Read Window | 🔴 Critical | Encryption |
| 37 | ML Model Poisoning via User Labels | 🟠 High | AI/ML Security |
| 38 | Non-Deterministic Fuzzing from Shared State | 🟠 High | Core Scanner |
| 39 | SIEM Integration Stub-Only | 🟠 High | Security Ops |
| 40 | Sandbox Escape via WASM Host Function Imports | 🔴 Critical | Sandbox Security |

Each issue includes a detailed description (8-15 lines), 6-9 actionable acceptance criteria, and references to specific files in the codebase.
