# Issue 34: [Supply Chain] Dependency Integrity Not Cryptographically Verified — Malicious Package Substitution Possible

**Priority:** 🔴 Critical
**Labels:** `security` `supply-chain` `dependencies`
**Area:** Security / Supply Chain
**Files:** `src/supply_chain/inventory.rs`, `src/supply_chain/integrity.rs`, `src/supply_chain/engine.rs`

## Description

The `SupplyChainGuard` in `src/supply_chain/engine.rs` maintains a `DependencyInventory` that tracks package names, versions, ecosystems, and licenses. The `src/supply_chain/integrity.rs` file exists as a module but performs **only hash computation on local files** — it does not verify those hashes against any trusted registry (crates.io checksums, npm integrity hashes from `package-lock.json`, or a vendor-maintained allowlist). The `Dependency::new()` constructor accepts any version string with no integrity verification. This means an attacker who compromises a build pipeline, CI runner, or dependency mirror could substitute a malicious package with the same name and version, and the supply chain scanner would ingest it without detecting the substitution. The `integrity.rs` module has functions like `compute_file_hash()` and `verify_file_integrity()` that compute SHA-256, but these are only called for local file verification, not for validating dependency provenance against a trusted source of truth. This defeats the entire purpose of the supply chain security module, which is designed to guarantee that dependencies are exactly what they claim to be.

## Acceptance Criteria

- [ ] Add a `VerifiedDependency` struct that wraps `Dependency` with a verified checksum from a trusted source
- [ ] Implement `crates.io` registry verification: validate Cargo.lock checksums against the crates.io index
- [ ] Implement npm registry verification: validate `package-lock.json` integrity hashes against the npm registry
- [ ] Add a `TrustedRegistry` abstraction with `verify(package, version, checksum) -> Result<()>`
- [ ] Add a `--require-verified` CLI flag that rejects any dependency lacking a verified checksum
- [ ] Update `PostureReport` to include a `verified_dependencies` count and `unverified_dependencies: Vec<String>`
- [ ] When verification fails, emit a `CRITICAL`-level alert through `VulnAlerter` with the mismatched package details
- [ ] Write tests that verify a known-good dependency (e.g., `serde` at a pinned version) and a tampered dependency is rejected
- [ ] Update `DEPENDENCY_MANAGEMENT.md` (or create it) with verification process documentation

## Additional Context

- The `integrity.rs` module only checks local file hashes, not registry provenance
- This is a supply chain blind spot affecting all ecosystem dependencies
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
