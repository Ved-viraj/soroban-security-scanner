# Issue 31: [Admin MFA] HMAC-SHA1 Used for TOTP — Deprecated Legacy Algorithm Weakens Second-Factor Security

**Priority:** 🔴 Critical
**Labels:** `security` `cryptography` `admin-mfa`
**Area:** Security / Cryptography
**Files:** `src/admin_mfa/totp.rs`

## Description

The TOTP implementation in `src/admin_mfa/totp.rs` uses `ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY` for generating and verifying time-based one-time passwords. This constant's name is a clear signal from the `ring` maintainers that SHA-1 should not be used in new designs. SHA-1 has known collision vulnerabilities (SHAttered attack, 2017) and is being actively phased out across the industry. While HMAC-SHA1 is somewhat more resistant than plain SHA-1 to collision attacks, NIST SP 800-131A Rev. 2 disallows SHA-1 for digital signature generation after 2022, and major authenticator vendors (YubiKey, Google Authenticator) now default to SHA-256 for TOTP. The `hotp()` function in `totp.rs` hardcodes `HMAC_SHA1_FOR_LEGACY_USE_ONLY` with no configuration option for stronger algorithms. An attacker with sufficient resources could exploit SHA-1 weaknesses to forge valid TOTP codes, bypassing admin MFA entirely. Since admin accounts control scanner configuration, contract upgrades, and bounty payouts, a successful MFA bypass grants full platform compromise.

## Acceptance Criteria

- [ ] Replace `HMAC_SHA1_FOR_LEGACY_USE_ONLY` with `HMAC_SHA256` as the default algorithm in `TotpConfig`
- [ ] Add a `TotpAlgorithm` enum (`Sha1`, `Sha256`, `Sha512`) to `TotpConfig` for backward compatibility
- [ ] Default new `TotpConfig` instances to `Sha256`; mark `Sha1` as `#[deprecated]` with a migration warning
- [ ] Update `provisioning_uri()` to include `algorithm=SHA256` in the otpauth URI when using SHA-256
- [ ] Add a migration path: when verifying with SHA-256 fails, fall back to SHA-1 for legacy secrets, log a warning, and prompt the user to re-enroll
- [ ] Update all tests in `src/admin_mfa/totp.rs` to verify SHA-256 code generation/verification works correctly
- [ ] Add a test that explicitly verifies SHA-1 codes still verify for the migration path
- [ ] Document the algorithm change in a new migration note under `docs/`

## Additional Context

- NIST SP 800-131A Rev. 2: SHA-1 disallowed for digital signature generation after 2022
- The `ring` crate explicitly marks `HMAC_SHA1_FOR_LEGACY_USE_ONLY` as deprecated for new designs
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
