# Soroban Security Scanner — Roadmap

> **Last updated:** July 20, 2026

This roadmap organizes all 68 issues across four milestones: 30 original standard issues, 10 critical issues from `CRITICAL_ISSUES.md`, 20 new standard issues (#41–60 from `NEW_ISSUES_41_60.md`), and 8 hard research-grade issues (#61–68 from `HARD_ISSUES_61_68.md`).

---

## Milestone 1: MVP Hardening 🚀

**Target:** Q3 2026 (July–September)  
**Theme:** Fix critical security vulnerabilities and broken core functionality

This milestone addresses issues that pose security risks, cause data loss, or break fundamental platform capabilities. These should be resolved before any new feature development.

### Security Fixes

| # | Issue | Priority | Est. Effort |
|---|-------|----------|-------------|
| 14 | DefaultHasher Used Instead of Cryptographic Hash | **Critical** | 2–3 days |
| 31 | HMAC-SHA1 TOTP — Deprecated Legacy Algorithm Weakens MFA | **Critical** | 2–3 days |
| 32 | AcceptingVerifier Placeholder Has No Production Guard | **Critical** | 2–3 days |
| 34 | Dependency Integrity Not Cryptographically Verified | **Critical** | 3–4 days |
| 36 | Key Rotation Without Dual-Key Read Window | **Critical** | 3–4 days |
| 40 | Sandbox Escape via WASM Host Function Imports | **Critical** | 4–5 days |
| 24 | OAuth2 State Parameter Not Validated (CSRF) | **Critical** | 1–2 days |
| 21 | Certificate Revocation List Not Implemented | **Critical** | 2–3 days |
| 26 | Timelock Bypass in Emergency Upgrade | **Critical** | 3–4 days |
| 29 | Bounty Payout Without Escrow Balance Check | **Critical** | 2 days |
| 5 | Multi-Sig Signer Weight Thresholds Not Validated | **High** | 3–4 days |
| 45 | WASM Deep Inspection Missing Function Signature Validation | **High** | 3–4 days |
| 48 | Stateless JWT Sessions Cannot Be Force-Invalidated | **High** | 3–4 days |
| 53 | Escrow Lacks Timeout Auto-Refund — Funds Locked Indefinitely | **High** | 2–3 days |

### Core Functionality Fixes

| # | Issue | Priority | Est. Effort |
|---|-------|----------|-------------|
| 2 | Access Control False Positives for Internal Helpers | **High** | 3–5 days |
| 33 | No Dead Letter Queue — Unbounded Memory Leak | **Critical** | 2–3 days |
| 37 | ML Model Poisoning via User-Contributed Labels | **High** | 3–4 days |
| 38 | Non-Deterministic Fuzzing from Shared Mutable State | **High** | 4–5 days |
| 11 | Stuck Scans Not Automatically Detected | **High** | 3–4 days |
| 8 | Time Travel State Incompatibility with Upgraded WASM | **High** | 4–5 days |
| 9 | Fuzzing Input Generator Misses Composite Edge Cases | **High** | 3–4 days |
| 27 | Cross-Contract Simulator Ignores Recursive Calls | **High** | 4–5 days |
| 41 | Structured Logs Missing Correlation IDs | **High** | 3–4 days |
| 42 | Cache Warming Hot-Key Stampede During Cold Start | **High** | 3–4 days |

### Infrastructure Fixes

| # | Issue | Priority | Est. Effort |
|---|-------|----------|-------------|
| 35 | In-Memory Rate Limiting Bypassed in Multi-Instance Deployments | **Critical** | 3–4 days |
| 39 | SIEM Integration Stub-Only — No External Alert Delivery | **High** | 4–5 days |
| 7 | Rate Limiting Ignores Reverse Proxy Headers | **High** | 2–3 days |
| 6 | Notification Delivery Status Not Persisted | **High** | 3–4 days |
| 23 | Offline Cached Data Inaccessible | **High** | 3–4 days |
| 28 | WebSocket Subscriptions Lost on Reconnect | **High** | 2–3 days |
| 52 | File Upload Zone Extension-Only Validation | **Medium** | 2–3 days |

### Dependencies

- Issue 14 (crypto) and Issue 31 (TOTP algorithm) must be completed before any new auth features
- Issue 24 (OAuth2) blocks social login reliability
- Issue 32 (WebAuthn guard) is a prerequisite for production WebAuthn deployment
- Issue 5 (multi-sig) should precede Issue 19 (wizard validation)
- Issue 2 (access control) is a prerequisite for any scanner accuracy improvements
- Issue 34 (supply chain integrity) should precede any dependency update automation
- Issue 35 (distributed rate limiting) and Issue 7 (proxy headers) are both required for production rate limiting
- Issue 40 (WASM sandbox) must be completed before accepting untrusted contracts from external users
- Issue 45 (WASM signatures) depends on Issue 40 (sandbox escape) — both must be complete for robust WASM validation
- Issue 42 (cache stampede) and Issue 17 (DB index) together address cold-start performance
- Issue 53 (escrow timeout) is a prerequisite for production bounty marketplace reliability

### Success Criteria

- [ ] Zero critical-severity security vulnerabilities (including the 9 new critical issues from CRITICAL_ISSUES.md)
- [ ] All core scanner features produce reliable results (false positive rate < 5%)
- [ ] No data loss scenarios on service restart or network interruption (key rotation safe, DLQ bounded)
- [ ] Rate limiting works correctly behind production proxy infrastructure (distributed + proxy-aware)
- [ ] WASM sandbox enforces host function import allowlist; all untrusted code execution is contained
- [ ] SIEM integration delivers alerts to at least one external platform (Splunk or Elastic)
- [ ] WASM upload validation enforces function signature checks (Issue 45) and host function allowlisting (Issue 40)
- [ ] JWT revocation list enables immediate session invalidation on password change (Issue 48)
- [ ] Escrow contracts include timeout-based refund mechanism (Issue 53)

---

## Milestone 2: Quality & Performance 🌟

**Target:** Q4 2026 (October–December)  
**Theme:** UX polish, performance optimization, accessibility compliance, and documentation

### UX & Accessibility

| # | Issue | Priority | Est. Effort |
|---|-------|----------|-------------|
| 1 | Incomplete Error Boundary Coverage | **High** | 3–4 days |
| 3 | Account Lockout Notification Missing | **High** | 2–3 days |
| 15 | Accessibility Violations in Scan Results Table | **Medium** | 3–4 days |
| 19 | Multi-Sig Wizard Lacks Real-Time Address Validation | **Medium** | 2–3 days |
| 4 | Ledger Import Fails Silently on Timeout | **Medium** | 2–3 days |
| 25 | Skeleton Components Flash on Fast Connections | **Medium** | 1–2 days |
| 46 | Form Components Lack Accessible Error Announcements | **Medium** | 2–3 days |
| 47 | Chart Components Don't Handle Empty States | **Low** | 1–2 days |
| 56 | RTL Language Support Not Implemented | **Low** | 3–4 days |

### Performance

| # | Issue | Priority | Est. Effort |
|---|-------|----------|-------------|
| 16 | Unused Translations in Bundle (1.2MB) | **Medium** | 2–3 days |
| 17 | Missing Database Index on `transactions` | **Medium** | 1–2 days |
| 13 | Gas Estimation Not Adaptive | **Medium** | 3–4 days |
| 10 | Batch Operations Lack Gas Estimation | **Medium** | 2–3 days |
| 43 | N+1 Detection Read-Only — No Circuit Breaker | **Medium** | 3–4 days |
| 54 | Web Vitals Monitoring Lacks Alerting Thresholds | **Medium** | 2–3 days |
| 58 | No Incremental Scan — Full Re-Scan Every Change | **Medium** | 4–5 days |

### Process & Compliance

| # | Issue | Priority | Est. Effort |
|---|-------|----------|-------------|
| 18 | Accessibility Tests Not Running in CI | **Medium** | 1–2 days |
| 12 | Event Logging Lacks Export & Query API | **Medium** | 4–5 days |
| 22 | Error Messages Not Internationalized | **Medium** | 3–4 days |
| 20 | Scanner Registry Lacks Semantic Versioning | **Medium** | 2–3 days |
| 49 | DB Pool Health Metrics Not Exposed to Prometheus | **Medium** | 2–3 days |
| 50 | No Threat Intelligence Feed Integration | **Medium** | 3–4 days |
| 51 | CSP Violation Reports Have No Dashboard | **Medium** | 3–4 days |
| 55 | Anomaly Detection Has No Baseline Learning Period | **Medium** | 3–4 days |
| 59 | Deprecation Webhooks Have No Signature Verification | **Medium** | 2–3 days |
| 60 | Template Rendering Has No Preview Endpoint | **Low** | 2–3 days |

### Documentation

| # | Issue | Priority | Est. Effort |
|---|-------|----------|-------------|
| 30 | No Differential Fuzzing Documentation | **Low** | 2–3 days |

| 44 | Invariant Engine Only Point-in-Time — No Temporal | **Medium** | 4–5 days |

### Dependencies

- Issue 18 (CI tests) should precede Issue 15 (a11y fixes) to catch regressions
- Issue 16 (bundle size) is a prerequisite for Lighthouse CI threshold updates
- Issue 12 (event export) depends on Issue 6 (persistence) from Milestone 1
- Issue 46 (form a11y) and Issue 15 (table a11y) together address WCAG 2.1 AA compliance
- Issue 43 (N+1 circuit breaker) and Issue 17 (DB index) together address query performance
- Issue 56 (RTL support) should follow Issue 22 (i18n errors) to avoid rework

### Success Criteria

- [ ] WCAG 2.1 AA compliance with zero critical/serious axe-core violations
- [ ] Lighthouse Performance score ≥ 90 (mobile)
- [ ] Lighthouse Accessibility score ≥ 95
- [ ] Dashboard queries complete in under 100ms for 100k+ transactions
- [ ] All CI pipelines pass — unit, integration, e2e, and accessibility tests
- [ ] Form components provide accessible error announcements for screen readers (Issue 46)
- [ ] N+1 queries are detected and blocked by circuit breaker before causing DB overload (Issue 43)
- [ ] CSP violation dashboard enables operators to graduate from report-only to enforcing mode (Issue 51)

---

## Milestone 3: Advanced Features & Ecosystem 🎯

**Target:** Q1 2027 (January–March)  
**Theme:** Differentiated capabilities, platform maturity, and developer ecosystem

### Planned Initiatives

| Initiative | Related Issues | Est. Effort |
|------------|----------------|-------------|
| **Adaptive Gas Optimization Engine** | 10, 13 | 2–3 weeks |
| **Comprehensive Fuzzing Suite** | 9, 27 + new issues | 3–4 weeks |
| **Enterprise Compliance Pack** | 12, 21, 30 | 2–3 weeks |
| **Internationalization Completion** | 16, 22 | 2 weeks |
| **Developer SDK & API** | 20, 30 | 3–4 weeks |
| **Supply Chain Compliance** | 57 | 2–3 weeks |

### Dependencies

- All Milestone 1 and Milestone 2 issues must be resolved
- Issue 57 (SBOM transitive) requires Issue 34 (dependency integrity) from Milestone 1
- External: Community feedback and usage data from Milestone 2 release

### Success Criteria

- [ ] Gas optimization reduces user costs by average 15%
- [ ] Fuzzing suite detects reentrancy patterns up to 5 levels deep
- [ ] SOC 2 Type II audit readiness (tamper-evident logs, certificate management)
- [ ] 100% i18n coverage for top 10 locales
- [ ] Public API documentation and SDK published
- [ ] SBOM includes transitive dependencies with license compliance checks (Issue 57)

---

## Milestone 4: Research & Advanced Capabilities 🔬

**Target:** Q2–Q3 2027 (April–September)  
**Theme:** Research-grade capabilities requiring novel algorithms, deep domain expertise, and multi-phase implementation

This milestone contains advanced issues that represent weeks-to-months of senior engineering work. Each involves significant R&D: designing new algorithms, integrating with external tools (Z3, WASM instrumentation), and pushing the boundaries of what static analysis can achieve for Soroban smart contracts.

### Core Research Initiatives

| # | Issue | Priority | Est. Effort |
|---|-------|----------|-------------|
| 61 | Symbolic Execution Engine for Path-Aware Detection | 🔴 Critical | 8–12 weeks |
| 62 | Cross-Contract Taint Tracking & Composability Analysis | 🔴 Critical | 6–10 weeks |
| 63 | Economic Exploit Simulation (Flash Loans, MEV, Oracle) | 🔴 Critical | 8–12 weeks |
| 64 | SMT-Based Formal Verification with Z3 | 🔴 Critical | 10–16 weeks |
| 65 | Storage Key Collision & Orphaned State Detection | 🔴 Critical | 5–8 weeks |
| 66 | Cross-Language Vulnerability Propagation (Rust→WASM→VM) | 🟠 High | 6–10 weeks |
| 67 | Coverage-Guided Fuzzing with WASM Instrumentation | 🟠 High | 6–10 weeks |
| 68 | Protocol-Level Invariant Verification (Multi-Contract) | 🟠 High | 8–12 weeks |

### Dependencies

- Issue 61 (symbolic execution) can leverage the SMT encoding work from Issue 64 (formal verification)
- Issue 62 (taint tracking) and Issue 68 (protocol invariants) share the cross-contract call graph infrastructure
- Issue 63 (economic exploits) builds on Issue 62 (call graph) and the differential fuzzer from Milestone 3
- Issue 65 (storage collisions) integrates with the time-travel debugger (Issue 8 from Milestone 1)
- Issue 66 (cross-layer analysis) requires the compilation chain model also used by Issue 61
- Issue 67 (coverage fuzzing) replaces the deterministic fuzzer from Issue 9 (Milestone 1) and Issue 38 (Milestone 1)
- Issue 68 (protocol invariants) is the capstone — it integrates symbolic execution (Issue 61), taint tracking (Issue 62), and formal verification (Issue 64)

### Success Criteria

- [ ] Symbolic execution engine detects at least 80% of vulnerabilities in the benchmark suite that pattern matching misses
- [ ] Taint tracking analysis handles 50+ contract protocols with recall > 90%
- [ ] Economic exploit framework discovers at least 3 known historical DeFi exploit patterns (flash loan, oracle manipulation, sandwich) in synthetic benchmarks
- [ ] SMT-based verifier proves at least 15 out of 20 invariants in the verification benchmark suite
- [ ] Coverage-guided fuzzer achieves 2x+ branch coverage compared to deterministic fuzzer in equal time budget
- [ ] Storage collision detector identifies all known collision patterns in a curated test suite of 10 upgrade scenarios
- [ ] Protocol-level invariant verifier handles a complete DEX + lending protocol system (10+ contracts)

---

## Prioritization Summary

| Severity | Count | Milestone |
|----------|-------|-----------|
| 🔴 Critical | 13 | MVP Hardening |
| 🟠 High | 16 | MVP Hardening (12), Quality (4) |
| 🟡 Medium | 10 | Quality & Performance |
| 🔴 Critical | 5 | Research & Advanced (Milestone 4) |
| 🟠 High | 3 | Research & Advanced (Milestone 4) |
| 🟠 High | 6 | MVP Hardening (Milestone 1) |
| 🟡 Medium | 10 | Quality & Performance (Milestone 2) |
| 🟢 Low | 4 | Quality & Performance (Milestone 2) |

## How to Contribute

1. Pick an issue from the current milestone
2. Assign yourself on GitHub
3. Follow the issue template's acceptance criteria
4. Submit a PR referencing the issue number

---

*See [ISSUES.md](./ISSUES.md) for the 30 original standard issues, [CRITICAL_ISSUES.md](./CRITICAL_ISSUES.md) for issues #31–40, [NEW_ISSUES_41_60.md](./NEW_ISSUES_41_60.md) for issues #41–60, and [HARD_ISSUES_61_68.md](./HARD_ISSUES_61_68.md) for the 8 research-grade issues.*
