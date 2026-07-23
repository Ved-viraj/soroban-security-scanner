# API Versioning and Backward Compatibility

> Implements [issue #335 — Missing API Versioning and Backward Compatibility
> Strategy](https://github.com/connect-boiz/soroban-security-scanner/issues/335).

This document is the canonical reference for the soroban-security-scanner
API versioning policy. It is the source of truth for the lifetime of every
public endpoint and answers the questions:

- How are versioned URLs formed?
- How does the server decide which version a request asked for?
- How long will my version be available after a new one ships?
- How do I migrate when my version is deprecated?
- What guarantees do existing clients have?

---

## 1. URL-based versioning

Every public endpoint is mounted at **`/api/v{N}/...`** where `N` is the
major version (currently `v1`).

```
https://api.example.com/api/v1/transactions
https://api.example.com/api/v1/queue/stats
```

A handful of meta-endpoints are **intentionally unversioned**:

| Path | Purpose |
|------|---------|
| `/api`             | Service info / API discovery |
| `/api/versions`    | List all versions + their lifecycle |
| `/api/v{N}/docs`   | Version-specific documentation |

Unversioned paths under `/api/...` that are neither of the above are
auto-redirected to the current stable version via a `301 Moved Permanently`
unless `auto_redirect_unversioned` is disabled in the router config.

---

## 2. Version lifecycle

Each version lives in exactly one of five lifecycle phases:

| Phase        | Served? | Breaking changes allowed? |
|--------------|---------|---------------------------|
| `alpha`      | ✅      | ✅                        |
| `beta`       | ✅      | ✅                        |
| `stable`     | ✅      | ❌ (zero breaking changes) |
| `deprecated` | ✅ (with warnings) | ❌              |
| `sunset`     | ❌ (returns 410 Gone) | ❌           |

A version moves forward through these phases at most once; it never moves
backward. The transitions are:

```
(alpha) ─► (beta) ─► (stable) ─► (deprecated) ─► (sunset)
   │          │          │             │             │
   │          │          │             │             └─ 410 Gone
   │          │          │             └─ adds X-API-Deprecated, X-API-Sunset
   │          │          └─ frozen for clients
   │          └─ feature complete, no further additions of breaking surface
   └─ free to break
```

**Promoting to stable demotes the previous stable:** when `v{N+1}` becomes
stable, `v{N}` is automatically deprecated and inherits a **6-month**
minimum sunset window.

---

## 3. Deprecation policy

- **Minimum notice period: 180 days (6 calendar months).**
- Every response from a deprecated version carries:
  - `X-API-Deprecated: true`
  - `X-API-Sunset: <RFC3339 date>`
  - `X-API-Deprecation-Message: <human-readable hint>`
- Six urgency notifications are emitted at `<policy thresholds>` days
  before sunset. The default matrix is `[90, 60, 30, 14, 7, 1]`.
- Clients can register for email or webhook notifications through the
  ops console (`POST /api/v1/admin/notifications/subscribe`).

The full sunset procedure is the 10-step checklist in
`src/api_versioning/deprecation.rs::SunsetProcedures::checklist`.

---

## 4. Version negotiation (Accept header)

You can request a specific version via either:

- **URL prefix** (preferred): `/api/v2/transactions` → unambiguous
- **Accept header**:
  ```
  Accept: application/vnd.soroban.v2+json
  ```
- **Simple header**: `X-API-Version: v2`

Resolution order is **URL > Accept > `X-API-Version` > default current**.

If a request mixes a URL version and an Accept header version and they
disagree, the server returns `400 Bad Request` with a `VersionError::Ambiguous`
explanation.

---

## 5. Change log

Every change is recorded as a [`ChangeEntry`](../../src/api_versioning/changelog.rs)
classified as one of:

- `breaking` — clients **must** update (`💥`)
- `addition` — new functionality (`✨`)
- `improvement` — non-breaking change (`🔧`)
- `deprecation` — advance warning (`⚠️`)
- `security` — vulnerability fix (`🔒`)
- `performance` — latency or throughput (`⚡`)
- `documentation` — docs only (`📚`)

Two generator outputs are published:

- `GET /api/v1/changelog.md` — Markdown for humans
- `GET /api/v1/changelog.json` — JSON for automation / changelog aggregators

Breaking changes ship **only** while a version is in `alpha` or `beta`.
The registry refuses to record a `breaking` change against a `stable`,
`deprecated`, or `sunset` version. This is the technical enforcement of
the **"zero breaking changes for existing clients"** acceptance criterion.

---

## 6. Backward compatibility

This is enforceable, not aspirational. The crate ships a
`CompatibilityTestSuite` (see [`src/api_versioning/compatibility.rs`](../../src/api_versioning/compatibility.rs))
that asserts 16 invariants on every CI run:

1. V1 endpoints are still served.
2. The v1 media-type string is stable.
3. The v1 changelog audit trail is preserved.
4. Adding a new version never evicts an existing one.
5. Every deprecated version meets the minimum-notice window.
6. No sunset version is incorrectly marked as served.
7. At most one version is `stable` at a time.
8. No breaking changes are recorded against a stable version.
9. The Markdown change log is non-empty and well-formed.
10. The change log JSON round-trips losslessly.
11. The migration summary accurately reflects breaking changes.
12. `current_stable()` returns a real stable version.
13. `list_active_versions()` excludes every sunset version.
14. Urgency-notification thresholds match the policy array.
15. Every `ApiVersion` round-trips through `FromStr`.
16. All five lifecycle phases report the correct `is_served()` value.

The suite produces a Markdown report that can be uploaded as a CI artifact:

```
cargo test -p soroban-security-scanner api_versioning::compatibility -- --nocapture
```

---

## 7. CI/CD integration

`scripts/api_versioning_compatibility_test.sh` is the canonical CI entry
point. It runs the full compatibility suite and writes the Markdown report
to `target/api-versioning-report.md`, which the GitHub Actions pipeline
uploads as an artifact. The suite is also invoked on every PR via
`cargo test api_versioning::`.

A failing check **blocks merge** to `develop` and `main`.

---

## 8. Zero-breaking-change guarantee for existing clients

End clients are protected by:

1. **Versioning stability** — URL prefixes and media-type strings for a
   version never change after release.
2. **Contract freezing at stable** — once a version reaches `stable`, no
   breaking change can be appended to its change log (the registry refuses).
3. **6-month minimum notice** — clients have a quarter to migrate at their
   own pace.
4. **Sunset workflow** — 10-step procedure with metrics-driven enforcement:
   before a version is moved to `sunset`, the platform team confirms
   production traffic is below the configured threshold.
5. **Compatibility suite** — automated proof that the contract still
   holds across releases.

---

## 9. Migration guide template

When `v{N}` is deprecated, a guide is generated by
`SunsetProcedures::migration_guide_template(v{N}, v{N+1})` and published at
`/api/v{N}/migration-to-v{N+1}.md`. The template includes:

- Timeline (deprecation announced, sunset date, recommended deadline)
- List of breaking changes with affected endpoints
- Step-by-step migration instructions (URL, headers, body fields)
- Test recipe (`cargo test api_versioning::compatibility`)
- Support contact link

---

## 10. Release process

1. New version registered as `alpha` with a release date.
2. After feature freeze, transition to `beta`.
3. After soak period, `promote_to_stable()` is called. The previous
   stable version is automatically deprecated with a 6-month sunset.
4. Urgency notifications begin firing at the thresholds listed in
   `DeprecationPolicy::urgency_notification_days`.
5. Once traffic to the deprecated version falls below the configured
   threshold and the sunset date is reached, the platform team calls
   `sunset_version()` and the version starts returning 410 Gone.

---

## 11. Examples

### Subscribe to deprecation notifications (curl)

```bash
curl -X POST https://api.example.com/api/v1/admin/notifications/subscribe \
  -H "Content-Type: application/json" \
  -d '{"version": "v1", "channels": ["email", "webhook"], "webhook_url": "https://hooks.example.com/deprecation"}'
```

### List all available versions

```bash
curl https://api.example.com/api/versions
```

### Request a specific version via Accept header

```bash
curl -H "Accept: application/vnd.soroban.v2+json" \
  https://api.example.com/api/v1/transactions
# → 200 OK with v1 body (URL wins over Accept when they agree on intent)
```

### Trigger a breaking-change attempt (returned as 400)

```rust
// In test code:
let result = registry.add_change(ApiVersion::V1, "Removed endpoint", true);
assert!(result.is_err()); // ✅ blocked by lifecycle policy
```

---

## 13. Webhook Security

All deprecation notification webhooks sent to subscriber URLs are signed
with HMAC-SHA256 to prevent spoofing and tampering. This follows the
well-established pattern used by Stripe, GitHub, and Slack.

### How signing works

1. Each subscriber receives a unique 64-character hex-encoded signing
   secret at registration time. This secret is only displayed once and
   is never stored in plaintext in logs.
2. Every outbound webhook payload includes:
   - `X-Soroban-Signature: t=<unix_timestamp>,v1=<hex-signature>`
   - `X-Soroban-Webhook-Id: <uuid>` (unique per delivery, for replay prevention)
3. The signature is computed as:
   ```
   HMAC-SHA256(secret, "<timestamp>.<JSON body>")
   ```

### Verifying signatures (subscriber side)

**TypeScript/Node.js:**

```typescript
import crypto from 'crypto';

function verifySignature(
  body: string,
  signatureHeader: string,
  secret: string,
  toleranceSeconds = 300
): boolean {
  const parts: Record<string, string> = {};
  for (const part of signatureHeader.split(',')) {
    const [key, value] = part.split('=');
    parts[key] = value;
  }

  const timestamp = parseInt(parts['t'], 10);
  const providedSig = parts['v1'];

  if (!timestamp || !providedSig) return false;

  // Check timestamp tolerance
  if (Math.abs(Date.now() / 1000 - timestamp) > toleranceSeconds) {
    return false;
  }

  // Recompute expected signature
  const signedPayload = `${timestamp}.${body}`;
  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');

  // Constant-time comparison
  if (expectedSig.length !== providedSig.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(expectedSig),
    Buffer.from(providedSig)
  );
}
```

**Python:**

```python
import hmac
import hashlib
import time

def verify_signature(
    body: bytes,
    signature_header: str,
    secret: str,
    tolerance_seconds: int = 300
) -> bool:
    parts = {}
    for part in signature_header.split(','):
        key, value = part.split('=', 1)
        parts[key] = value

    timestamp = int(parts.get('t', '0'))
    provided_sig = parts.get('v1', '')

    if not timestamp or not provided_sig:
        return False

    # Check timestamp tolerance
    if abs(int(time.time()) - timestamp) > tolerance_seconds:
        return False

    # Recompute expected signature
    signed_payload = f"{timestamp}.".encode() + body
    expected_sig = hmac.new(
        secret.encode(),
        signed_payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected_sig, provided_sig)
```

### Test webhook endpoint

Use `POST /api/v1/admin/notifications/test-webhook` to send a signed test
payload to a subscriber's URL so they can verify their verification
implementation:

```bash
curl -X POST https://api.example.com/api/v1/admin/notifications/test-webhook \
  -H "Content-Type: application/json" \
  -d '{"subscriber_id": "<subscriber-id>"}'
```

The subscriber will receive a signed webhook with a test payload containing
the event type `webhook.test` and a timestamp.

### Replay prevention

Each webhook delivery includes a unique `X-Soroban-Webhook-Id` header.
Subscribers should track received IDs and reject any duplicate within a
configurable window (recommended: 24 hours). The `WebhookSubscriber` struct
internally tracks delivered IDs and will detect replays.

### Subscribing to webhooks

```bash
curl -X POST https://api.example.com/api/v1/admin/notifications/subscribe \
  -H "Content-Type: application/json" \
  -d '{"version": "v1", "channels": ["webhook"], "webhook_url": "https://hooks.example.com/deprecation"}'
```

The response includes the signing secret (shown once):

```json
{
  "subscriber_id": "550e8400-e29b-41d4-a716-446655440000",
  "signing_secret": "a1b2c3d4e5f6...",
  "webhook_url": "https://hooks.example.com/deprecation"
}
```

---

## 14. References

- Module: [`src/api_versioning`](../../src/api_versioning)
- Tests: [`tests/api_versioning_tests.rs`](../../tests/api_versioning_tests.rs)
- CI entry point: [`scripts/api_versioning_compatibility_test.sh`](../../scripts/api_versioning_compatibility_test.sh)
- Source issue: [#335](https://github.com/connect-boiz/soroban-security-scanner/issues/335)
