# Issue 32: [WebAuthn] AcceptingVerifier Placeholder Has No Production Guard — Deployment Could Ship with Permissive Signature Bypass

**Priority:** 🔴 Critical
**Labels:** `security` `authentication` `webauthn` `admin-mfa`
**Area:** Security / Authentication
**Files:** `src/admin_mfa/webauthn.rs`

## Description

The `AcceptingVerifier` in `src/admin_mfa/webauthn.rs` is explicitly documented as: "A permissive verifier used in tests and as a wiring placeholder. It checks only that a signature is present — **never** use it in production." This struct implements `AssertionVerifier` by returning `true` for any non-empty signature, completely bypassing all WebAuthn cryptographic verification. However, there is **no compile-time, runtime, or configuration guard** preventing this verifier from being used in production. The `MfaManager::verify_webauthn()` method accepts any `&dyn AssertionVerifier`, meaning if dependency injection accidentally wires in `AcceptingVerifier` instead of a real COSE verifier, all WebAuthn assertions will pass regardless of signature validity. Given that production deployments likely do not yet have a full COSE/CBOR verifier implemented (the code itself says "a production deployment can wire in a full COSE/CBOR verifier without this module pulling in a heavy crypto stack"), the risk of this placeholder reaching production is high. An attacker who discovers this could authenticate as any admin using any random bytes as a WebAuthn signature.

## Acceptance Criteria

- [ ] Add a `#[cfg(any(test, feature = "dangerous-accepting-verifier"))]` gate on `AcceptingVerifier` and its `impl AssertionVerifier`
- [ ] Add a runtime startup check in `main.rs` or config validation that panics or refuses to start if the feature flag is enabled and `ENV != "development"`
- [ ] Create a `CoseAssertionVerifier` stub (returning `Err` until wired) that is the default in non-test builds
- [ ] Add a `WebAuthnVerifierConfig` enum with variants `AcceptingTestOnly`, `CoseVerifier { ... }` that is validated at app startup
- [ ] Log a CRITICAL-level warning on every use of `AcceptingVerifier::verify()` in non-test builds
- [ ] Add an integration test that verifies the server refuses to start with `AcceptingVerifier` in production mode
- [ ] Document this requirement in `AUTHENTICATION_QUICK_START.md`

## Additional Context

- The `AcceptingVerifier` struct is documented as test-only but has no enforcement mechanism
- WebAuthn credentials protect admin accounts with full platform control
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
