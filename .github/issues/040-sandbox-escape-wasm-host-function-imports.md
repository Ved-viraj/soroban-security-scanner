# Issue 40: [Analysis Guard] Sandbox Escape Possible Through WASM Exploitation of Unvalidated Host Function Imports

**Priority:** 🔴 Critical
**Labels:** `security` `sandbox` `wasm` `analysis-guard` `rce`
**Area:** Security / Sandbox
**Files:** `src/analysis_guard/sandbox.rs`, `src/analysis_guard/limits.rs`, `src/upload_sanitization/wasm.rs`

## Description

The `Sandbox` in `src/analysis_guard/sandbox.rs` executes untrusted Soroban WASM contracts in a resource-constrained environment with CPU/memory/timeout limits. The `upload_sanitization/wasm.rs` module validates WASM binaries before execution, checking for malformed modules and known malicious patterns. However, the sandbox relies on the Soroban VM's host function interface to provide limited capabilities to the contract under test. There is no validation that the WASM module's **import section** only references allowed host functions. A maliciously crafted contract could import host functions that the Soroban VM exposes but the sandbox expects to be unavailable — for example, functions that access the host filesystem, make network calls, or invoke system commands. The `wasm.rs` sanitizer checks WASM structure validity and magic bytes but does not parse the import section to build an allowlist of permitted host function signatures. An attacker who understands the Soroban host function ABI could craft a contract that imports `env.fs_read` or `env.exec` (if such functions exist in the VM) and escapes the sandbox to read scanner configuration files, encryption keys, or database credentials from the host filesystem.

## Acceptance Criteria

- [ ] Parse the WASM import section during sanitization and extract all `(import "env" "function_name" ...)` declarations
- [ ] Define a `HOST_FUNCTION_ALLOWLIST` containing only the host functions required for security scanning (e.g., `ledger.get`, `ledger.put`, `contract.call`, `log.log`)
- [ ] Reject any WASM module that imports a function not in the allowlist with error: `SandboxError::DisallowedHostFunction { function: String }`
- [ ] Add an `import_allowlist` configuration field to `SandboxConfig` for customizing allowed functions per deployment
- [ ] Implement a seccomp-bpf filter (Linux) or equivalent OS-level sandbox as a defense-in-depth layer around the WASM VM process
- [ ] Run the sandbox process under a dedicated non-root user with no filesystem access outside a tmpfs scratch directory
- [ ] Write an adversarial test: craft a WASM module that imports a forbidden host function and verify it is rejected during sanitization, NOT during execution
- [ ] Add a security audit checklist item to `SECURITY_IMPROVEMENTS.md` for periodic host function allowlist review

## Additional Context

- This is a sandbox escape vulnerability affecting the core analysis engine that runs untrusted user code
- Defense-in-depth requires both WASM-level import validation and OS-level seccomp restrictions
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
