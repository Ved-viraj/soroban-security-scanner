//! The security monitoring engine.
//!
//! Orchestrates the full pipeline for each ingested event: rule detection →
//! ML anomaly scoring → correlation into incidents → alert dispatch → SIEM
//! forwarding → automated playbook execution. Also exposes a dashboard snapshot
//! and the security metrics (MTTD/MTTR/posture).

use crate::security_monitoring::alerting::{AlertDispatcher, DispatchResult};
use crate::security_monitoring::anomaly::{AnomalyConfig, AnomalyDetector};
use crate::security_monitoring::baseline::{
    BaselineConfig, BaselineConfigError, BaselineLearner, BaselineStatistics, BaselineStatus,
};
use crate::security_monitoring::detection::{DetectionConfig, Finding, RuleEngine};
use crate::security_monitoring::event::{SecurityEvent, SecuritySeverity};
use crate::security_monitoring::incident::{Incident, IncidentStatus, Priority};
use crate::security_monitoring::metrics::{compute_metrics, SecurityMetrics};
use crate::security_monitoring::playbook::{PlaybookRegistry, PlaybookRun};
use crate::security_monitoring::siem::SiemForwarder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Correlation window: findings about the same subject within this many seconds
/// fold into the same open incident.
const CORRELATION_WINDOW_SECS: i64 = 600;

/// What happened when an event was processed.
#[derive(Debug, Clone, Default)]
pub struct ProcessOutcome {
    /// Findings the rules produced.
    pub findings: Vec<Finding>,
    /// Incident ids opened or updated.
    pub incidents: Vec<Uuid>,
    /// Whether the ML detector flagged the event as anomalous.
    pub anomalous: bool,
    /// The anomaly z-score, when the detector had enough data to score
    /// (available for diagnostics even during the baseline learning period).
    pub anomaly_z: Option<f64>,
    /// Alerts dispatched, keyed by incident id.
    pub dispatched: Vec<DispatchResult>,
    /// Playbook runs triggered.
    pub playbook_runs: Vec<PlaybookRun>,
}

/// A dashboard snapshot for threat visualization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// Current security metrics.
    pub metrics: SecurityMetrics,
    /// Open incidents ordered by priority (highest first).
    pub top_incidents: Vec<Incident>,
    /// Count of incidents per priority bucket (P1..P4).
    pub by_priority: [usize; 4],
}

/// The orchestrating security monitor.
pub struct SecurityMonitor {
    rules: RuleEngine,
    anomaly: AnomalyDetector,
    dispatcher: AlertDispatcher,
    playbooks: PlaybookRegistry,
    siem: Option<SiemForwarder>,
    incidents: HashMap<Uuid, Incident>,
    /// Most recent open incident per subject, for correlation.
    open_by_subject: HashMap<String, Uuid>,
    /// Baseline learning for anomaly detection (Issue #435).
    baseline: BaselineLearner,
}

impl SecurityMonitor {
    /// Builds a monitor with the default baseline configuration (1-hour
    /// learning period, 30-day expiry). The dispatcher should already have
    /// its channels registered; SIEM forwarding is optional.
    pub fn new(
        detection: DetectionConfig,
        anomaly: AnomalyConfig,
        dispatcher: AlertDispatcher,
        playbooks: PlaybookRegistry,
        siem: Option<SiemForwarder>,
    ) -> Self {
        Self::with_baseline_config(
            detection,
            anomaly,
            BaselineConfig::default(),
            dispatcher,
            playbooks,
            siem,
        )
        .expect("default baseline configuration is valid")
    }

    /// Builds a monitor with a custom baseline configuration. Returns an
    /// error for invalid configurations (see [`BaselineConfig::validate`]).
    pub fn with_baseline_config(
        detection: DetectionConfig,
        anomaly: AnomalyConfig,
        baseline: BaselineConfig,
        dispatcher: AlertDispatcher,
        playbooks: PlaybookRegistry,
        siem: Option<SiemForwarder>,
    ) -> Result<Self, BaselineConfigError> {
        Ok(Self {
            rules: RuleEngine::new(detection),
            anomaly: AnomalyDetector::new(anomaly),
            dispatcher,
            playbooks,
            siem,
            incidents: HashMap::new(),
            open_by_subject: HashMap::new(),
            baseline: BaselineLearner::new(baseline)?,
        })
    }

    /// Ingests and fully processes one security event.
    ///
    /// The baseline learner always computes anomaly scores, but while no
    /// valid baseline exists (Learning / Resetting / Degraded) findings are
    /// recorded for diagnostics only — no incidents are opened and no alerts
    /// are dispatched. Once the baseline is Active, normal detection resumes.
    pub fn ingest(&mut self, event: &SecurityEvent) -> ProcessOutcome {
        let mut outcome = ProcessOutcome::default();

        // 0. Advance the baseline state machine (learning completion, expiry).
        let prev_status = self.baseline.status();
        self.baseline.tick(event.at);
        if self.baseline.status() == BaselineStatus::Active && prev_status != BaselineStatus::Active
        {
            // The baseline was just computed: seed the detector so scores use
            // the calculated statistics instead of a cold start.
            self.seed_anomaly_from_baseline();
        }

        // 1. Always forward to SIEM (raw telemetry), best-effort.
        if let Some(siem) = &self.siem {
            let _ = siem.forward(event);
        }

        // 2. ML anomaly scoring (1.0 per occurrence of this event kind/subject).
        //    Scores are always computed, including during the learning period
        //    (observation mode), so they remain available for diagnostics.
        let subject = event.correlation_key();
        let metric = format!("{subject}:{:?}", event.kind);
        if let Some(score) = self.anomaly.observe(&metric, 1.0) {
            outcome.anomalous = score.anomalous;
            outcome.anomaly_z = Some(score.z);
        }

        // 3. The baseline learner collects observations while not Active.
        self.baseline.record(&metric, 1.0, event.at);

        // 4. Rule detection (recorded for diagnostics in every state).
        outcome.findings = self.rules.evaluate(event);

        // 5. Correlate findings into incidents and respond, but only once a
        //    valid baseline exists — never during Learning/Resetting/Degraded.
        if self.baseline.status() == BaselineStatus::Active {
            for finding in &outcome.findings {
                let incident_id = self.correlate(finding, event.at);
                outcome.incidents.push(incident_id);

                let incident = self.incidents.get(&incident_id).unwrap().clone();
                // Alert.
                outcome.dispatched.push(self.dispatcher.dispatch(&incident));
                // Automated response.
                outcome
                    .playbook_runs
                    .extend(self.playbooks.execute(&incident));
            }
        }

        outcome
    }

    /// Copies the freshly calculated baseline statistics into the anomaly
    /// detector so post-learning z-scores are evaluated against the baseline.
    fn seed_anomaly_from_baseline(&mut self) {
        let stats: Vec<(String, u64, f64, f64)> = self
            .baseline
            .baselines()
            .values()
            .map(|s| (s.metric.clone(), s.count, s.mean, s.stddev))
            .collect();
        for (metric, count, mean, stddev) in stats {
            self.anomaly.seed_baseline(&metric, count, mean, stddev);
        }
    }

    /// Folds a finding into an existing open incident for the subject (within
    /// the correlation window) or opens a new one. Returns the incident id.
    fn correlate(&mut self, finding: &Finding, event_at: i64) -> Uuid {
        if let Some(&existing) = self.open_by_subject.get(&finding.subject) {
            if let Some(inc) = self.incidents.get_mut(&existing) {
                let recent = event_at - inc.detected_at <= CORRELATION_WINDOW_SECS;
                if inc.status != IncidentStatus::Resolved && recent {
                    inc.correlate(finding);
                    return existing;
                }
            }
        }
        // Open a new incident. Detection is "now" (event_at); first_event_at is
        // the finding's originating event time.
        let incident = Incident::open(finding, finding.at, event_at);
        let id = incident.id;
        self.open_by_subject.insert(finding.subject.clone(), id);
        self.incidents.insert(id, incident);
        id
    }

    /// Acknowledges an incident.
    pub fn acknowledge(&mut self, id: Uuid, at: i64) -> bool {
        match self.incidents.get_mut(&id) {
            Some(inc) => {
                inc.acknowledge(at);
                true
            }
            None => false,
        }
    }

    /// Resolves an incident and clears it from the open-subject index.
    pub fn resolve(&mut self, id: Uuid, at: i64) -> bool {
        match self.incidents.get_mut(&id) {
            Some(inc) => {
                inc.resolve(at);
                self.open_by_subject.retain(|_, v| *v != id);
                true
            }
            None => false,
        }
    }

    /// All incidents (unordered).
    pub fn incidents(&self) -> Vec<Incident> {
        self.incidents.values().cloned().collect()
    }

    /// Current security metrics.
    pub fn metrics(&self) -> SecurityMetrics {
        compute_metrics(&self.incidents())
    }

    /// A dashboard snapshot: metrics, top open incidents and priority counts.
    pub fn dashboard(&self) -> DashboardSnapshot {
        let mut all = self.incidents();
        let mut by_priority = [0usize; 4];
        for inc in &all {
            let idx = match inc.priority() {
                Priority::P1 => 0,
                Priority::P2 => 1,
                Priority::P3 => 2,
                Priority::P4 => 3,
            };
            by_priority[idx] += 1;
        }

        let mut open: Vec<Incident> = all
            .drain(..)
            .filter(|i| i.status != IncidentStatus::Resolved)
            .collect();
        // Highest priority first, then most severe.
        open.sort_by_key(|i| std::cmp::Reverse((i.priority(), i.severity)));
        open.truncate(10);

        DashboardSnapshot {
            metrics: self.metrics(),
            top_incidents: open,
            by_priority,
        }
    }

    /// Convenience: does the current MTTD meet the <5min critical target?
    pub fn meets_mttd_target(&self) -> bool {
        self.metrics().meets_mttd_target
    }

    /// Highest severity currently open, if any.
    pub fn worst_open_severity(&self) -> Option<SecuritySeverity> {
        self.incidents
            .values()
            .filter(|i| i.status != IncidentStatus::Resolved)
            .map(|i| i.severity)
            .max()
    }

    // ---- Baseline learning (Issue #435) ----

    /// Current baseline lifecycle state.
    pub fn baseline_status(&self) -> BaselineStatus {
        self.baseline.status()
    }

    /// The active baseline configuration.
    pub fn baseline_config(&self) -> BaselineConfig {
        self.baseline.config()
    }

    /// Baseline statistics per metric (empty unless a baseline is Active).
    pub fn baseline_statistics(&self) -> HashMap<String, BaselineStatistics> {
        self.baseline.baselines().clone()
    }

    /// Invalidates the current baseline and observation state and starts a
    /// fresh learning period. Returns the resulting status (Learning).
    /// `now` is the current unix-seconds timestamp.
    pub fn reset_baseline(&mut self, now: i64) -> BaselineStatus {
        self.baseline.reset(now);
        // The detector's running statistics describe the old baseline; clear
        // them so the new learning period starts from a clean slate.
        self.anomaly.reset();
        self.baseline.tick(now);
        self.baseline.status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_monitoring::alerting::{
        AlertMessage, AlertRouting, ChannelKind, NotificationChannel,
    };
    use crate::security_monitoring::event::{Component, EventKind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingChannel {
        kind: ChannelKind,
        count: Arc<AtomicUsize>,
    }
    impl NotificationChannel for CountingChannel {
        fn kind(&self) -> ChannelKind {
            self.kind
        }
        fn deliver(&self, _m: &AlertMessage) -> Result<(), String> {
            self.count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn monitor(counter: Arc<AtomicUsize>) -> SecurityMonitor {
        let mut dispatcher = AlertDispatcher::new(AlertRouting::default());
        for kind in [
            ChannelKind::Email,
            ChannelKind::Slack,
            ChannelKind::Sms,
            ChannelKind::PagerDuty,
        ] {
            dispatcher.register(Box::new(CountingChannel {
                kind,
                count: Arc::clone(&counter),
            }));
        }
        let mut mon = SecurityMonitor::new(
            DetectionConfig::default(),
            AnomalyConfig::default(),
            dispatcher,
            PlaybookRegistry::with_defaults(),
            None,
        );
        complete_learning(&mut mon);
        mon
    }

    /// Fast-forwards through the baseline learning period: feeds enough
    /// benign observations (auth successes produce no findings) to establish
    /// a valid baseline, then lets the learning period elapse so the monitor
    /// starts in Active state. Deterministic — driven by event timestamps.
    fn complete_learning(mon: &mut SecurityMonitor) {
        for i in 0..15 {
            mon.ingest(
                &SecurityEvent::new(
                    1000 + i,
                    EventKind::AuthSuccess,
                    Component::Auth,
                    SecuritySeverity::Info,
                )
                .with_principal("warmup"),
            );
        }
        mon.ingest(
            &SecurityEvent::new(
                1000 + 3600,
                EventKind::AuthSuccess,
                Component::Auth,
                SecuritySeverity::Info,
            )
            .with_principal("warmup"),
        );
    }

    fn auth_fail(at: i64, who: &str) -> SecurityEvent {
        SecurityEvent::new(
            at,
            EventKind::AuthFailure,
            Component::Auth,
            SecuritySeverity::Low,
        )
        .with_principal(who)
        .with_ip("10.0.0.1")
    }

    #[test]
    fn brute_force_opens_incident_and_alerts() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = monitor(Arc::clone(&counter));
        let mut outcome = ProcessOutcome::default();
        for i in 0..5 {
            outcome = mon.ingest(&auth_fail(1000 + i, "alice"));
        }
        // The 5th event fires the brute-force rule and opens an incident.
        assert!(!outcome.findings.is_empty());
        assert_eq!(outcome.incidents.len(), 1);
        assert_eq!(mon.incidents().len(), 1);
        // High severity → P2 → Slack+Email (2 channels) at least once delivered.
        assert!(counter.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn attack_signature_triggers_p1_playbook() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = monitor(Arc::clone(&counter));
        let ev = SecurityEvent::new(
            1000,
            EventKind::AttackSignature,
            Component::Network,
            SecuritySeverity::High,
        )
        .with_ip("8.8.8.8")
        .with_detail("RCE attempt");
        let outcome = mon.ingest(&ev);
        assert_eq!(outcome.findings[0].severity, SecuritySeverity::Critical);
        assert!(outcome
            .playbook_runs
            .iter()
            .any(|r| r.playbook == "critical-attack-response"));
        // P1 fans out to 4 channels.
        assert_eq!(counter.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn repeated_findings_correlate_into_one_incident() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = monitor(counter);
        // Two attack signatures for the same subject within the window.
        let mk = |at: i64| {
            SecurityEvent::new(
                at,
                EventKind::AttackSignature,
                Component::Network,
                SecuritySeverity::High,
            )
            .with_ip("8.8.8.8")
        };
        mon.ingest(&mk(1000));
        mon.ingest(&mk(1100));
        assert_eq!(mon.incidents().len(), 1);
        assert_eq!(mon.incidents()[0].finding_count, 2);
    }

    #[test]
    fn resolve_clears_open_correlation() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = monitor(counter);
        let outcome = mon.ingest(
            &SecurityEvent::new(
                1000,
                EventKind::AttackSignature,
                Component::Network,
                SecuritySeverity::High,
            )
            .with_ip("9.9.9.9"),
        );
        let id = outcome.incidents[0];
        assert!(mon.resolve(id, 1200));
        // A later event for the same subject opens a NEW incident.
        mon.ingest(
            &SecurityEvent::new(
                2000,
                EventKind::AttackSignature,
                Component::Network,
                SecuritySeverity::High,
            )
            .with_ip("9.9.9.9"),
        );
        assert_eq!(mon.incidents().len(), 2);
    }

    #[test]
    fn dashboard_orders_by_priority_and_counts() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = monitor(counter);
        mon.ingest(
            &SecurityEvent::new(
                1000,
                EventKind::AttackSignature,
                Component::Network,
                SecuritySeverity::High,
            )
            .with_ip("1.1.1.1"),
        ); // critical → P1
        mon.ingest(
            &SecurityEvent::new(
                1000,
                EventKind::SensitiveChange,
                Component::Database,
                SecuritySeverity::Medium,
            )
            .with_principal("svc"),
        ); // medium → P3
        let dash = mon.dashboard();
        assert_eq!(dash.top_incidents[0].priority(), Priority::P1);
        assert_eq!(dash.by_priority[0], 1); // one P1
    }

    #[test]
    fn fast_detection_meets_mttd_target() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = monitor(counter);
        mon.ingest(
            &SecurityEvent::new(
                1000,
                EventKind::AttackSignature,
                Component::Network,
                SecuritySeverity::High,
            )
            .with_ip("1.1.1.1"),
        );
        // Detected same second as the event → MTTD 0.
        assert!(mon.meets_mttd_target());
        assert_eq!(mon.worst_open_severity(), Some(SecuritySeverity::Critical));
    }

    // ---- Baseline learning (Issue #435) ----

    /// A monitor that stays in the default (Learning) state — no warm-up.
    fn fresh_monitor(counter: Arc<AtomicUsize>) -> SecurityMonitor {
        let mut dispatcher = AlertDispatcher::new(AlertRouting::default());
        for kind in [
            ChannelKind::Email,
            ChannelKind::Slack,
            ChannelKind::Sms,
            ChannelKind::PagerDuty,
        ] {
            dispatcher.register(Box::new(CountingChannel {
                kind,
                count: Arc::clone(&counter),
            }));
        }
        SecurityMonitor::new(
            DetectionConfig::default(),
            AnomalyConfig::default(),
            dispatcher,
            PlaybookRegistry::with_defaults(),
            None,
        )
    }

    fn auth_failure(at: i64, who: &str) -> SecurityEvent {
        SecurityEvent::new(
            at,
            EventKind::AuthFailure,
            Component::Auth,
            SecuritySeverity::Low,
        )
        .with_principal(who)
        .with_ip("10.0.0.1")
    }

    #[test]
    fn initial_state_is_learning() {
        let mon = fresh_monitor(Arc::new(AtomicUsize::new(0)));
        assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
        // The default learning period is one hour.
        assert_eq!(mon.baseline_config().learning_period_seconds, 3600);
        assert_eq!(
            mon.baseline_config().baseline_expiry_seconds,
            30 * 24 * 60 * 60
        );
    }

    #[test]
    fn learning_suppresses_incidents_and_alerts_but_scores_are_computed() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = fresh_monitor(Arc::clone(&counter));

        // Enough events for both the rule engine and the anomaly detector.
        let mut last = ProcessOutcome::default();
        for i in 0..15 {
            last = mon.ingest(&auth_failure(1000 + i, "alice"));
        }
        // Findings are still computed (observation mode)...
        assert!(!last.findings.is_empty());
        // ...and anomaly scores are still calculated...
        assert!(
            last.anomaly_z.is_some(),
            "scores must be computed during learning"
        );
        // ...but no incidents were opened and no alerts were dispatched.
        assert!(last.incidents.is_empty());
        assert!(last.dispatched.is_empty());
        assert!(mon.incidents().is_empty());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
    }

    #[test]
    fn learning_completion_activates_detection() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = fresh_monitor(Arc::clone(&counter));

        // Fifteen brute-force failures during learning (below the 5-in-window
        // threshold is irrelevant — everything is suppressed anyway).
        for i in 0..15 {
            mon.ingest(&auth_failure(1000 + i, "alice"));
        }
        assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
        assert!(mon.incidents().is_empty());

        // An event at/past the learning deadline finalizes the baseline.
        let outcome = mon.ingest(&auth_failure(1000 + 3600, "alice"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);
        assert!(!mon.baseline_statistics().is_empty());

        // A single failure past the deadline should not fire the brute-force
        // rule (needs 5 in the window) — but the pipeline is now live.
        assert!(outcome.findings.is_empty());

        // Now a real burst fires incidents and alerts.
        let mut last = ProcessOutcome::default();
        for i in 0..5 {
            last = mon.ingest(&auth_failure(1000 + 3700 + i, "bob"));
        }
        assert!(!last.findings.is_empty());
        assert_eq!(last.incidents.len(), 1);
        assert_eq!(mon.incidents().len(), 1);
        assert!(counter.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn insufficient_observations_leave_monitor_degraded_not_active() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = fresh_monitor(counter);
        // Only 3 observations in the whole learning window (min is 10).
        for i in 0..3 {
            mon.ingest(&auth_failure(1000 + i, "alice"));
        }
        mon.ingest(&auth_failure(1000 + 3600, "alice"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Degraded);
        assert!(mon.baseline_statistics().is_empty());

        // Detection stays suppressed in Degraded: no incidents from findings.
        let mut last = ProcessOutcome::default();
        for i in 0..6 {
            last = mon.ingest(&auth_failure(10_000 + i, "mallory"));
        }
        assert!(!last.findings.is_empty());
        assert!(mon.incidents().is_empty());
        assert_eq!(mon.baseline_status(), BaselineStatus::Degraded);
    }

    #[test]
    fn baseline_expiry_degrades_after_thirty_days() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = fresh_monitor(counter);
        for i in 0..15 {
            mon.ingest(&auth_failure(1000 + i, "alice"));
        }
        mon.ingest(&auth_failure(1000 + 3600, "alice"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);

        let day = 24 * 60 * 60;
        let calculated = 1000 + 3600;
        // 29 days later: still active.
        mon.ingest(&auth_failure(calculated + 29 * day, "alice"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);

        // Past 30 days: degraded.
        mon.ingest(&auth_failure(calculated + 30 * day + 1, "alice"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Degraded);

        // Suppressed again: no incidents while degraded.
        let mut last = ProcessOutcome::default();
        for i in 0..6 {
            last = mon.ingest(&auth_failure(calculated + 31 * day + i, "eve"));
        }
        assert!(!last.findings.is_empty());
        assert!(mon.incidents().is_empty());
    }

    #[test]
    fn reset_invalidates_baseline_and_restarts_learning() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = fresh_monitor(counter);
        for i in 0..15 {
            mon.ingest(&auth_failure(1000 + i, "alice"));
        }
        mon.ingest(&auth_failure(1000 + 3600, "alice"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);
        assert!(!mon.baseline_statistics().is_empty());

        // Reset from Active: baseline invalidated, learning restarts.
        let status = mon.reset_baseline(20_000);
        assert_eq!(status, BaselineStatus::Learning);
        assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
        assert!(mon.baseline_statistics().is_empty());

        // Detection is suppressed again until the new window completes.
        let mut last = ProcessOutcome::default();
        for i in 0..15 {
            last = mon.ingest(&auth_failure(20_000 + i, "dave"));
        }
        assert!(!last.findings.is_empty());
        assert!(mon.incidents().is_empty());
        assert_eq!(mon.baseline_status(), BaselineStatus::Learning);

        // The new window completes and detection activates again.
        mon.ingest(&auth_failure(20_000 + 3600, "dave"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);
        for i in 0..5 {
            mon.ingest(&auth_failure(30_000 + i, "dave"));
        }
        assert_eq!(mon.incidents().len(), 1);
    }

    #[test]
    fn repeated_resets_do_not_corrupt_state() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = fresh_monitor(counter);
        for _ in 0..50 {
            let status = mon.reset_baseline(1000);
            assert_eq!(status, BaselineStatus::Learning);
            assert!(mon.baseline_statistics().is_empty());
            assert!(mon.incidents().is_empty());
        }
    }

    #[test]
    fn concurrent_resets_are_serialized_safely() {
        use std::sync::Mutex;

        let counter = Arc::new(AtomicUsize::new(0));
        let mut mon = fresh_monitor(Arc::clone(&counter));
        for i in 0..15 {
            mon.ingest(&auth_failure(1000 + i, "alice"));
        }
        mon.ingest(&auth_failure(1000 + 3600, "alice"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);

        // Share the monitor behind a mutex (as the HTTP layer does) and fire
        // concurrent resets. All resets use the same deterministic timestamp.
        let shared = Arc::new(Mutex::new(mon));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let shared = Arc::clone(&shared);
            handles.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    let mut guard = shared.lock().unwrap();
                    let status = guard.reset_baseline(50_000);
                    assert_eq!(status, BaselineStatus::Learning);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let mut mon = Arc::try_unwrap(shared)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
        assert!(mon.baseline_statistics().is_empty());

        // Still functional: a fresh learning window completes normally.
        for i in 0..15 {
            mon.ingest(&auth_failure(50_000 + i, "carol"));
        }
        mon.ingest(&auth_failure(50_000 + 3600, "carol"));
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);
        for i in 0..5 {
            mon.ingest(&auth_failure(60_000 + i, "carol"));
        }
        assert_eq!(mon.incidents().len(), 1);
    }
}
