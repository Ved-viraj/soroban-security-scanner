//! Baseline learning for anomaly detection (Issue #435).
//!
//! On first deployment (or after an administrator resets the baseline) the
//! monitor has no historical data to judge behaviour against. If anomaly
//! detection evaluated traffic immediately it would flag perfectly normal
//! activity as suspicious. The [`BaselineLearner`] solves this with a
//! configurable observation window:
//!
//! 1. During **Learning** the monitor keeps computing anomaly scores (so the
//!    detector warms up on real traffic) but suppresses alerts/incidents.
//! 2. When the learning period elapses, the learner computes per-metric
//!    baseline statistics (mean, sample standard deviation, p95, p99) from
//!    the bounded observations it retained.
//! 3. With a valid baseline the engine becomes **Active** and normal
//!    detection behaviour resumes, using the computed statistics.
//! 4. A baseline older than [`BaselineConfig::baseline_expiry_seconds`]
//!    (default 30 days) is no longer trustworthy and the engine transitions
//!    to **Degraded**, logging a warning that recommends a reset.
//!
//! Time is driven entirely by the caller-supplied `now` (unix seconds),
//! matching the rest of the monitoring pipeline which timestamps events with
//! `i64` unix seconds. This keeps the state machine deterministic and
//! testable — no wall clock is consulted.
//!
//! # Resource bounds
//!
//! The learner never stores unbounded history. Per metric it keeps at most
//! [`BaselineConfig::max_observations_per_metric`] recent samples (a bounded
//! buffer), and at most [`BaselineConfig::max_metrics`] distinct metrics
//! (evicting the least-recently-seen metric when the cap is reached). This
//! makes p95/p99 exact on the retained window without unbounded memory
//! growth.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Lifecycle state of the anomaly-detection baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaselineStatus {
    /// Collecting observations; scores are computed but alerts/incidents are
    /// suppressed (observation mode).
    Learning,
    /// A valid baseline exists; detection behaves normally.
    Active,
    /// A reset is in progress (transient state before a new learning period).
    Resetting,
    /// The baseline is missing or stale (expired / insufficient data);
    /// detection stays suppressed until an administrator resets it.
    Degraded,
}

impl BaselineStatus {
    /// Whether the engine may generate alerts/incidents in this state.
    ///
    /// Only a trustworthy, non-expired baseline may drive alerting.
    pub fn allows_detection(self) -> bool {
        matches!(self, BaselineStatus::Active)
    }
}

/// A state transition recorded by [`BaselineLearner::tick`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineTransition {
    /// State before the transition.
    pub from: BaselineStatus,
    /// State after the transition.
    pub to: BaselineStatus,
    /// Human-readable reason, for logging/diagnostics.
    pub message: String,
}

/// Baseline learning configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineConfig {
    /// How long (seconds) the learner collects observations before computing
    /// a baseline. Default: 3600 (1 hour).
    pub learning_period_seconds: i64,
    /// How old a baseline may be before it is considered stale and the
    /// engine degrades. Default: 30 days.
    pub baseline_expiry_seconds: i64,
    /// Minimum observations a metric needs to produce a trustworthy
    /// baseline. Fewer samples cannot yield a meaningful mean/stddev/percentile
    /// (see [`BaselineLearner::finalize`]); metrics below this threshold are
    /// excluded from the baseline. Default: 10.
    pub min_observations: usize,
    /// Bounded retention per metric: at most this many recent samples are
    /// kept. Caps memory during long learning periods.
    pub max_observations_per_metric: usize,
    /// Bounded number of distinct metrics tracked. When exceeded, the
    /// least-recently-seen metric is evicted.
    pub max_metrics: usize,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            learning_period_seconds: 3600,
            baseline_expiry_seconds: 30 * 24 * 60 * 60,
            min_observations: 10,
            max_observations_per_metric: 4096,
            max_metrics: 10_000,
        }
    }
}

impl BaselineConfig {
    /// Validates the configuration, rejecting values that would produce an
    /// unsafe or meaningless baseline.
    pub fn validate(&self) -> Result<(), BaselineConfigError> {
        if self.learning_period_seconds <= 0 {
            return Err(BaselineConfigError::InvalidLearningPeriod(
                self.learning_period_seconds,
            ));
        }
        if self.baseline_expiry_seconds <= 0 {
            return Err(BaselineConfigError::InvalidExpiry(
                self.baseline_expiry_seconds,
            ));
        }
        if self.min_observations < 2 {
            return Err(BaselineConfigError::InvalidMinObservations(
                self.min_observations,
            ));
        }
        if self.max_observations_per_metric == 0 {
            return Err(BaselineConfigError::InvalidRetention(
                self.max_observations_per_metric,
            ));
        }
        if self.max_metrics == 0 {
            return Err(BaselineConfigError::InvalidMaxMetrics(self.max_metrics));
        }
        Ok(())
    }
}

/// Configuration validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BaselineConfigError {
    /// Learning period must be positive (a zero/negative window cannot be
    /// safely completed).
    #[error("learning_period_seconds must be > 0, got {0}")]
    InvalidLearningPeriod(i64),
    /// Baseline expiry must be positive.
    #[error("baseline_expiry_seconds must be > 0, got {0}")]
    InvalidExpiry(i64),
    /// Fewer than 2 observations cannot yield a meaningful stddev/percentile.
    #[error("min_observations must be >= 2, got {0}")]
    InvalidMinObservations(usize),
    /// Retention cap must be positive.
    #[error("max_observations_per_metric must be > 0, got {0}")]
    InvalidRetention(usize),
    /// Metric cap must be positive.
    #[error("max_metrics must be > 0, got {0}")]
    InvalidMaxMetrics(usize),
}

/// Baseline statistics for a single monitored metric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineStatistics {
    /// The metric these statistics describe (e.g. `alice:AuthFailure`).
    pub metric: String,
    /// Number of observations used.
    pub count: u64,
    /// Arithmetic mean of the retained samples.
    pub mean: f64,
    /// Sample standard deviation (n-1 denominator; 0 for < 2 samples).
    pub stddev: f64,
    /// 95th percentile (nearest-rank) of the retained samples.
    pub p95: f64,
    /// 99th percentile (nearest-rank) of the retained samples.
    pub p99: f64,
    /// When the baseline was calculated (unix seconds).
    pub calculated_at: i64,
}

/// Bounded per-metric sample history.
#[derive(Debug, Clone, Default)]
struct MetricSamples {
    values: std::collections::VecDeque<f64>,
    last_seen: i64,
}

/// Collects observations during the learning period and computes baseline
/// statistics. See the module docs for the lifecycle.
#[derive(Debug, Clone)]
pub struct BaselineLearner {
    config: BaselineConfig,
    status: BaselineStatus,
    /// When the current learning window started (set on first observation or
    /// when a reset transitions back to Learning).
    learning_started_at: Option<i64>,
    observations: HashMap<String, MetricSamples>,
    baselines: HashMap<String, BaselineStatistics>,
    baseline_calculated_at: Option<i64>,
    /// One-shot flag so the stale-baseline warning is logged at the
    /// transition, not on every subsequent event.
    expiry_warned: bool,
}

impl BaselineLearner {
    /// Creates a learner with the given (validated) configuration.
    pub fn new(config: BaselineConfig) -> Result<Self, BaselineConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            status: BaselineStatus::Learning,
            learning_started_at: None,
            observations: HashMap::new(),
            baselines: HashMap::new(),
            baseline_calculated_at: None,
            expiry_warned: false,
        })
    }

    /// The learner's configuration.
    pub fn config(&self) -> BaselineConfig {
        self.config
    }

    /// Current baseline status. Transitions are driven by [`Self::tick`].
    pub fn status(&self) -> BaselineStatus {
        self.status
    }

    /// When the current learning window started, if it has.
    pub fn learning_started_at(&self) -> Option<i64> {
        self.learning_started_at
    }

    /// When the active baseline was calculated, if any.
    pub fn baseline_calculated_at(&self) -> Option<i64> {
        self.baseline_calculated_at
    }

    /// Statistics for one metric, if a valid baseline exists for it.
    pub fn baseline(&self, metric: &str) -> Option<&BaselineStatistics> {
        self.baselines.get(metric)
    }

    /// All baseline statistics (only populated in Active state).
    pub fn baselines(&self) -> &HashMap<String, BaselineStatistics> {
        &self.baselines
    }

    /// Number of metrics currently being observed.
    pub fn observed_metrics(&self) -> usize {
        self.observations.len()
    }

    /// Number of retained samples across all metrics.
    pub fn observation_count(&self) -> usize {
        self.observations.values().map(|m| m.values.len()).sum()
    }

    /// Records one observation for `metric` while the learner is collecting
    /// (Learning / Resetting / Degraded). Values that are not finite (NaN or
    /// infinite) are rejected so a malicious or corrupt metric can never
    /// poison the baseline. Retention is bounded per metric and the metric
    /// table itself is bounded.
    pub fn record(&mut self, metric: &str, value: f64, now: i64) {
        if !value.is_finite() {
            log::debug!("baseline: ignoring non-finite observation for {metric}: {value}");
            return;
        }
        // Active baselines are fixed; stop collecting once we have one.
        if self.status == BaselineStatus::Active {
            return;
        }
        if self.learning_started_at.is_none() {
            self.learning_started_at = Some(now);
        }

        if !self.observations.contains_key(metric)
            && self.observations.len() >= self.config.max_metrics
        {
            self.evict_least_recently_seen();
        }

        let entry = self
            .observations
            .entry(metric.to_string())
            .or_insert_with(|| MetricSamples {
                values: std::collections::VecDeque::with_capacity(
                    self.config.max_observations_per_metric,
                ),
                last_seen: now,
            });
        entry.last_seen = now;
        entry.values.push_back(value);
        if entry.values.len() > self.config.max_observations_per_metric {
            entry.values.pop_front();
        }
    }

    /// Advances the state machine to `now` and returns the transition that
    /// occurred, if any:
    ///
    /// - `Resetting` → `Learning` (a new learning window starts at `now`)
    /// - `Learning` → `Active` once the learning period has elapsed and a
    ///   valid baseline could be computed
    /// - `Learning` → `Degraded` when the period elapsed but too few
    ///   observations exist to form a trustworthy baseline
    /// - `Active` → `Degraded` when the baseline is older than the expiry
    ///
    /// Call this with every event timestamp (or periodically) so learning
    /// completion and baseline expiry are observed deterministically.
    pub fn tick(&mut self, now: i64) -> Option<BaselineTransition> {
        match self.status {
            BaselineStatus::Resetting => {
                self.status = BaselineStatus::Learning;
                self.learning_started_at = Some(now);
                self.expiry_warned = false;
                log::info!(
                    "security-monitoring: baseline reset complete, new {}s learning period started at {now}",
                    self.config.learning_period_seconds
                );
                Some(BaselineTransition {
                    from: BaselineStatus::Resetting,
                    to: BaselineStatus::Learning,
                    message: "baseline reset; new learning period started".to_string(),
                })
            }
            BaselineStatus::Learning => {
                let started = match self.learning_started_at {
                    Some(s) => s,
                    None => {
                        self.learning_started_at = Some(now);
                        return None;
                    }
                };
                if now.saturating_sub(started) >= self.config.learning_period_seconds {
                    self.finalize(now)
                } else {
                    None
                }
            }
            BaselineStatus::Active => {
                let calculated = self.baseline_calculated_at.unwrap_or(now);
                if now.saturating_sub(calculated) > self.config.baseline_expiry_seconds {
                    self.status = BaselineStatus::Degraded;
                    self.expiry_warned = true;
                    log::warn!(
                        "security-monitoring: baseline is {now} (calculated {calculated}) — older than the {}s expiry; degraded. Reset the baseline to resume detection.",
                        self.config.baseline_expiry_seconds
                    );
                    Some(BaselineTransition {
                        from: BaselineStatus::Active,
                        to: BaselineStatus::Degraded,
                        message: "baseline expired; degraded until reset".to_string(),
                    })
                } else {
                    None
                }
            }
            BaselineStatus::Degraded => None,
        }
    }

    /// Ends the learning period: computes per-metric statistics from the
    /// retained observations and transitions to `Active`, or to `Degraded`
    /// when no metric has enough observations to be trustworthy.
    ///
    /// A metric with fewer than `min_observations` samples is excluded from
    /// the baseline (its statistics would be mathematically meaningless) and
    /// simply cold-starts in the anomaly detector as before. The overall
    /// baseline is only considered valid when at least one metric produced
    /// usable statistics — otherwise detection must not silently activate.
    fn finalize(&mut self, now: i64) -> Option<BaselineTransition> {
        let mut baselines: HashMap<String, BaselineStatistics> = HashMap::new();
        let mut retained = 0usize;
        for (metric, samples) in &self.observations {
            if samples.values.len() < self.config.min_observations {
                continue;
            }
            retained += 1;
            baselines.insert(
                metric.clone(),
                compute_statistics(metric, &samples.values, now),
            );
        }

        if retained == 0 {
            self.status = BaselineStatus::Degraded;
            self.baselines.clear();
            self.baseline_calculated_at = None;
            log::warn!(
                "security-monitoring: learning period ended but no metric accumulated >= {} observations; baseline degraded. Reset the baseline to retry.",
                self.config.min_observations
            );
            return Some(BaselineTransition {
                from: BaselineStatus::Learning,
                to: BaselineStatus::Degraded,
                message: "insufficient observations for a trustworthy baseline".to_string(),
            });
        }

        self.baselines = baselines;
        self.baseline_calculated_at = Some(now);
        self.status = BaselineStatus::Active;
        log::info!(
            "security-monitoring: baseline active with statistics for {retained} metrics (calculated at {now})"
        );
        Some(BaselineTransition {
            from: BaselineStatus::Learning,
            to: BaselineStatus::Active,
            message: format!("baseline calculated for {retained} metrics"),
        })
    }

    /// Invalidates the current baseline and observation state and enters the
    /// transient `Resetting` state. The next [`Self::tick`] starts a fresh
    /// learning period.
    pub fn reset(&mut self, now: i64) {
        let _ = now;
        self.status = BaselineStatus::Resetting;
        self.learning_started_at = None;
        self.observations.clear();
        self.baselines.clear();
        self.baseline_calculated_at = None;
        self.expiry_warned = false;
        log::info!("security-monitoring: baseline reset requested");
    }

    /// Whether a valid, non-expired baseline currently exists.
    pub fn has_valid_baseline(&self) -> bool {
        self.status == BaselineStatus::Active
            && !self.baselines.is_empty()
            && self.baseline_calculated_at.is_some()
    }

    /// Drops the least-recently-seen metric to keep the metric table bounded.
    fn evict_least_recently_seen(&mut self) {
        let victim = self
            .observations
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| k.clone());
        if let Some(k) = victim {
            self.observations.remove(&k);
        }
    }
}

/// Computes baseline statistics for one metric from its retained samples.
///
/// - mean: arithmetic mean
/// - stddev: sample standard deviation (n-1 denominator); 0 for < 2 samples
/// - p95/p99: nearest-rank percentiles over the retained samples
///
/// Samples are guaranteed finite and non-empty by the caller.
fn compute_statistics(
    metric: &str,
    samples: &std::collections::VecDeque<f64>,
    now: i64,
) -> BaselineStatistics {
    let n = samples.len();
    let count = n as u64;
    let mean = samples.iter().sum::<f64>() / n as f64;
    let variance = if n < 2 {
        0.0
    } else {
        samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    };

    let mut sorted: Vec<f64> = samples.iter().copied().collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    BaselineStatistics {
        metric: metric.to_string(),
        count,
        mean,
        stddev: variance.sqrt(),
        p95: nearest_rank_percentile(&sorted, 95.0),
        p99: nearest_rank_percentile(&sorted, 99.0),
        calculated_at: now,
    }
}

/// Nearest-rank percentile: `ceil(pct/100 * N)`-th smallest sample (1-indexed),
/// clamped to the valid range. `sorted` must be non-empty and finite.
fn nearest_rank_percentile(sorted: &[f64], pct: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn learner() -> BaselineLearner {
        BaselineLearner::new(BaselineConfig::default()).unwrap()
    }

    fn record_n(learner: &mut BaselineLearner, metric: &str, n: usize, value: f64, start: i64) {
        for i in 0..n {
            learner.record(metric, value, start + i as i64);
        }
    }

    #[test]
    fn default_config_has_expected_values() {
        let cfg = BaselineConfig::default();
        assert_eq!(cfg.learning_period_seconds, 3600);
        assert_eq!(cfg.baseline_expiry_seconds, 30 * 24 * 60 * 60);
        assert_eq!(cfg.min_observations, 10);
    }

    #[test]
    fn invalid_configurations_are_rejected() {
        for cfg in [
            BaselineConfig {
                learning_period_seconds: 0,
                ..BaselineConfig::default()
            },
            BaselineConfig {
                learning_period_seconds: -5,
                ..BaselineConfig::default()
            },
            BaselineConfig {
                baseline_expiry_seconds: 0,
                ..BaselineConfig::default()
            },
            BaselineConfig {
                min_observations: 0,
                ..BaselineConfig::default()
            },
            BaselineConfig {
                min_observations: 1,
                ..BaselineConfig::default()
            },
            BaselineConfig {
                max_observations_per_metric: 0,
                ..BaselineConfig::default()
            },
            BaselineConfig {
                max_metrics: 0,
                ..BaselineConfig::default()
            },
        ] {
            assert!(
                cfg.validate().is_err(),
                "config should be rejected: {cfg:?}"
            );
            assert!(BaselineLearner::new(cfg).is_err());
        }
    }

    #[test]
    fn initial_state_is_learning() {
        assert_eq!(learner().status(), BaselineStatus::Learning);
    }

    #[test]
    fn observations_collected_during_learning() {
        let mut l = learner();
        l.record("alice:AuthFailure", 1.0, 1000);
        l.record("alice:AuthFailure", 1.0, 1001);
        l.record("bob:AuthSuccess", 1.0, 1002);
        assert_eq!(l.observed_metrics(), 2);
        assert_eq!(l.observation_count(), 3);
        assert_eq!(l.learning_started_at(), Some(1000));
    }

    #[test]
    fn non_finite_values_are_rejected() {
        let mut l = learner();
        l.record("m:1", f64::NAN, 1000);
        l.record("m:1", f64::INFINITY, 1001);
        l.record("m:1", f64::NEG_INFINITY, 1002);
        l.record("m:1", 1.0, 1003);
        assert_eq!(l.observed_metrics(), 1);
        assert_eq!(l.observation_count(), 1);
    }

    #[test]
    fn learning_completes_when_period_elapses() {
        let mut l = learner();
        record_n(&mut l, "alice:AuthFailure", 20, 1.0, 1000);
        assert_eq!(l.status(), BaselineStatus::Learning);

        // Still learning just before the deadline.
        assert!(l.tick(1000 + 3599).is_none());
        assert_eq!(l.status(), BaselineStatus::Learning);

        // At/after the deadline the baseline is computed.
        let transition = l.tick(1000 + 3600).unwrap();
        assert_eq!(transition.from, BaselineStatus::Learning);
        assert_eq!(transition.to, BaselineStatus::Active);
        assert_eq!(l.status(), BaselineStatus::Active);
        assert!(l.has_valid_baseline());
    }

    #[test]
    fn insufficient_observations_never_activate() {
        let mut l = learner();
        record_n(&mut l, "quiet:AuthSuccess", 3, 1.0, 1000); // below min_observations
        let transition = l.tick(1000 + 3600).unwrap();
        assert_eq!(transition.to, BaselineStatus::Degraded);
        assert_eq!(l.status(), BaselineStatus::Degraded);
        assert!(!l.has_valid_baseline());
        assert!(!BaselineStatus::Degraded.allows_detection());

        // It stays degraded (no silent activation) until reset.
        assert!(l.tick(1000 + 7200).is_none());
        assert_eq!(l.status(), BaselineStatus::Degraded);
    }

    #[test]
    fn mean_stddev_p95_p99_are_correct() {
        let mut l = learner();
        // 1..=20 -> mean 10.5
        for i in 0..20 {
            l.record("m:1", (i + 1) as f64, 1000 + i as i64);
        }
        l.tick(1000 + 3600).unwrap();
        let stats = l.baseline("m:1").unwrap();
        assert_eq!(stats.count, 20);
        assert!((stats.mean - 10.5).abs() < 1e-9);
        // Sample stddev of 1..=20.
        let expected_var = (1..=20).map(|x| (x as f64 - 10.5).powi(2)).sum::<f64>() / 19.0;
        assert!((stats.stddev - expected_var.sqrt()).abs() < 1e-9);
        // Nearest-rank: ceil(0.95*20)=19th smallest (=19), ceil(0.99*20)=20th (=20).
        assert_eq!(stats.p95, 19.0);
        assert_eq!(stats.p99, 20.0);
        assert_eq!(stats.calculated_at, 1000 + 3600);
    }

    #[test]
    fn constant_values_produce_zero_stddev() {
        let mut l = learner();
        record_n(&mut l, "const:1", 15, 7.0, 1000);
        l.tick(1000 + 3600).unwrap();
        let stats = l.baseline("const:1").unwrap();
        assert_eq!(stats.mean, 7.0);
        assert_eq!(stats.stddev, 0.0);
        assert_eq!(stats.p95, 7.0);
        assert_eq!(stats.p99, 7.0);
    }

    #[test]
    fn one_observation_never_forms_a_baseline() {
        let mut l = learner();
        l.record("solo:1", 42.0, 1000);
        l.tick(1000 + 3600).unwrap();
        assert_eq!(l.status(), BaselineStatus::Degraded);
        assert!(l.baseline("solo:1").is_none());
    }

    #[test]
    fn metrics_below_min_observations_are_excluded_but_valid_ones_activate() {
        let mut l = learner();
        record_n(&mut l, "busy:AuthFailure", 15, 1.0, 1000);
        record_n(&mut l, "quiet:AuthSuccess", 3, 1.0, 1000);
        l.tick(1000 + 3600).unwrap();
        assert_eq!(l.status(), BaselineStatus::Active);
        assert!(l.baseline("busy:AuthFailure").is_some());
        assert!(l.baseline("quiet:AuthSuccess").is_none());
    }

    #[test]
    fn baseline_expires_after_thirty_days() {
        let mut l = learner();
        record_n(&mut l, "alice:AuthFailure", 20, 1.0, 1000);
        l.tick(1000 + 3600).unwrap(); // Active, calculated at 4600
        assert_eq!(l.status(), BaselineStatus::Active);

        // 29 days later: still active.
        let day = 24 * 60 * 60;
        assert!(l.tick(4600 + 29 * day).is_none());
        assert_eq!(l.status(), BaselineStatus::Active);

        // 30 days + 1s: expired -> degraded (single transition).
        let transition = l.tick(4600 + 30 * day + 1).unwrap();
        assert_eq!(transition.from, BaselineStatus::Active);
        assert_eq!(transition.to, BaselineStatus::Degraded);
        assert!(!l.has_valid_baseline());

        // No repeated warnings: further ticks produce no transitions.
        assert!(l.tick(4600 + 60 * day).is_none());
    }

    #[test]
    fn reset_clears_state_and_restarts_learning() {
        let mut l = learner();
        record_n(&mut l, "alice:AuthFailure", 20, 1.0, 1000);
        l.tick(1000 + 3600).unwrap();
        assert_eq!(l.status(), BaselineStatus::Active);

        l.reset(10_000);
        assert_eq!(l.status(), BaselineStatus::Resetting);
        assert!(l.baselines().is_empty());
        assert!(l.baseline_calculated_at().is_none());
        assert_eq!(l.observation_count(), 0);

        // Next tick starts the new learning period.
        let transition = l.tick(10_000).unwrap();
        assert_eq!(transition.from, BaselineStatus::Resetting);
        assert_eq!(transition.to, BaselineStatus::Learning);
        assert_eq!(l.learning_started_at(), Some(10_000));
        assert_eq!(l.status(), BaselineStatus::Learning);
        assert!(!l.has_valid_baseline());
    }

    #[test]
    fn observations_during_resetting_are_collected_into_new_window() {
        let mut l = learner();
        record_n(&mut l, "a:1", 20, 1.0, 1000);
        l.tick(1000 + 3600).unwrap();
        l.reset(5000);

        // Events arrive before the reset tick: still collected.
        l.record("a:1", 1.0, 5001);
        l.record("a:1", 1.0, 5002);
        l.tick(5003);
        assert_eq!(l.status(), BaselineStatus::Learning);
        assert_eq!(l.observation_count(), 2);
    }

    #[test]
    fn retention_is_bounded_per_metric() {
        let cfg = BaselineConfig {
            max_observations_per_metric: 8,
            min_observations: 4, // retained samples (8) must still qualify
            ..BaselineConfig::default()
        };
        let mut l = BaselineLearner::new(cfg).unwrap();
        record_n(&mut l, "hot:1", 100, 1.0, 1000);
        assert_eq!(l.observation_count(), 8);
        // Oldest samples were dropped; the retained ones are the last 8.
        l.tick(1000 + 3600).unwrap();
        assert_eq!(l.baseline("hot:1").unwrap().count, 8);
        assert_eq!(l.baseline("hot:1").unwrap().mean, 1.0);
    }

    #[test]
    fn metric_table_is_bounded() {
        let cfg = BaselineConfig {
            max_metrics: 3,
            min_observations: 2,
            ..BaselineConfig::default()
        };
        let mut l = BaselineLearner::new(cfg).unwrap();
        // 5 distinct metrics; the 2 least-recently-seen get evicted.
        l.record("m1", 1.0, 1000);
        l.record("m2", 1.0, 1001);
        l.record("m3", 1.0, 1002);
        l.record("m4", 1.0, 1003);
        l.record("m5", 1.0, 1004);
        assert!(l.observed_metrics() <= 3);
        // Touch m1 again so it survives; m5 is freshest.
        l.record("m1", 1.0, 1005);
        assert!(l.observed_metrics() <= 3);
    }

    #[test]
    fn out_of_order_timestamps_are_safe() {
        let mut l = learner();
        // An event with an earlier timestamp than the window start is safe.
        l.record("a:1", 1.0, 10_000);
        assert!(l.tick(5_000).is_none()); // saturating_sub -> still learning
        assert_eq!(l.status(), BaselineStatus::Learning);
    }
}
