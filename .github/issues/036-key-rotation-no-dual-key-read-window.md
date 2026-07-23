# Issue 36: [Encryption at Rest] Key Rotation Has No Dual-Key Read Window — Data Becomes Unreadable During Rotation

**Priority:** 🔴 Critical
**Labels:** `security` `encryption` `data-integrity`
**Area:** Security / Data Integrity
**Files:** `src/encryption_at_rest/service.rs`, `src/encryption_at_rest/keys.rs`, `src/encryption_at_rest/cipher.rs`

## Description

The encryption-at-rest module in `src/encryption_at_rest/` provides AES-256 field-level encryption with key management. The `KeyManager` in `keys.rs` supports key generation, storage, and rotation through `rotate_key()`. However, rotation is implemented as an **atomic key swap**: the old key is immediately replaced by the new key in the active key slot. Any data that was encrypted with the old key but has not yet been re-encrypted becomes permanently unreadable the moment rotation completes. In a production database with millions of encrypted rows, re-encrypting all data can take hours. During that window, any query that touches a row still encrypted with the old key will fail with a decryption error, causing cascading failures across all dependent services (bounty marketplace payouts, audit trail verification, wallet operations). The `EncryptionService` has no `try_decrypt_with_fallback()` method that attempts the new key first and falls back to recent historical keys. There is no key versioning embedded in the ciphertext (no KID/Key ID prefix), so the system cannot even determine which key was used to decrypt a given ciphertext without brute-forcing all known keys.

## Acceptance Criteria

- [ ] Add a 4-byte KID (Key ID) prefix to all ciphertexts identifying which key encrypted the data
- [ ] Implement a `KeyRing` that holds the active key plus up to N previous keys (default N=3) for the rotation window
- [ ] Add `encrypt_with_key_id()` and `decrypt_with_kid()` methods that use the KID prefix for routing
- [ ] Implement a background `reencrypt_batch()` worker that incrementally re-encrypts rows from old keys to the new key
- [ ] Expose re-encryption progress via `GET /api/v1/encryption/reencrypt-status` with `rows_remaining` and `estimated_completion`
- [ ] Add a `force_rotation_timeout` config: if re-encryption is not complete within the timeout, log CRITICAL and continue serving with both keys
- [ ] In `rotate_key()`, do NOT delete the old key — move it to `KeyRing.previous_keys` and only delete after re-encryption is confirmed complete
- [ ] Write tests: encrypt with key A → rotate to key B → decrypt old ciphertext → re-encrypt → verify old key can be safely removed
- [ ] Add a migration note documenting the ciphertext format change (KID prefix addition)

## Additional Context

- This issue can cause catastrophic data loss during routine key rotation operations
- The KID prefix is a standard pattern used by AWS KMS, GCP KMS, and HashiCorp Vault
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
