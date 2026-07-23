# Issue 37: [Severity Scoring] ML Model Trained on User-Contributed Labels — Adversarial Poisoning Can Downgrade Critical Vulnerabilities

**Priority:** 🟠 High
**Labels:** `security` `ai-ml` `severity-scoring` `adversarial`
**Area:** AI/ML / Security
**Files:** `src/severity_scoring/ml.rs`, `src/severity_scoring/engine.rs`, `src/severity_scoring/context.rs`

## Description

The `severity_scoring/ml.rs` module implements a machine learning model for dynamic vulnerability severity scoring. According to the `SEVERITY_SCORING.md` documentation, this model learns from historical scan results to improve CVSS-based scoring accuracy. However, the training data source includes **user-submitted vulnerability reports** where the severity label is provided by the submitting researcher. A malicious actor can submit hundreds of crafted vulnerability reports where critical vulnerabilities (e.g., reentrancy with full fund drainage) are labeled as "Low" or "Info" severity. As the model retrains on this poisoned data, it gradually learns to downgrade genuinely critical vulnerabilities, causing the platform to under-prioritize severe findings. Since the bounty payout in `bounty_marketplace.rs` is tied to severity (via `RiskScore`), the attacker also financially benefits by reducing the payout owed to other researchers. The model has no anomaly detection on training labels (e.g., flagging when a user's severity rating differs from the CVSS base score by more than 3 levels), no training data provenance tracking, and no holdout validation set to detect model drift.

## Acceptance Criteria

- [ ] Add a `TrainingDataProvenance` struct tracking: submitter ID, submission timestamp, CVSS vector, and user-provided label for every training sample
- [ ] Implement label anomaly detection: if `|user_label - cvss_base_score| > 2.0`, flag the sample for human review and exclude from automated training
- [ ] Add a `--poisoning-threshold` CLI flag: if any submitter contributes > N% of training data with anomalous labels, quarantine ALL their submissions and alert admins
- [ ] Implement a holdout validation set (20% of data) to detect model accuracy degradation after each training epoch — if accuracy drops > 5%, roll back to previous model
- [ ] Add model versioning with `ModelSnapshot { version, trained_at, accuracy, data_hash }` stored in the database
- [ ] Expose model health via `GET /api/v1/ml/model-health` with accuracy trend, training sample distribution, and flagged submitters
- [ ] Write adversarial tests: inject 100 poisoned labels and verify the model does NOT change severity by more than 0.5 points on a held-out benchmark
- [ ] Document the anti-poisoning measures in `docs/SEVERITY_SCORING.md`

## Additional Context

- This is a model poisoning attack via the training data pipeline, not the inference path
- Bounty payouts are directly tied to severity scores, creating financial incentive for poisoning
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
