//! Web Vitals Alerting System
//!
//! Evaluates the p75 of each Core Web Vital metric over a rolling 5-minute
//! window and triggers alerts when thresholds are exceeded.
//! Alerts are routed through the LogAlerter for notification.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Alert severity levels for web vitals
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VitalsAlertSeverity {
    Warning,
    Critical,
}

/// A web vitals alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VitalsAlert {
    pub metric: String,
    pub value: f64,
    pub threshold: f64,
    pub severity: VitalsAlertSeverity,
    pub message: String,
    pub timestamp: String,
}

/// Alert thresholds for each web vital metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VitalsThresholds {
    pub lcp_warning_ms: f64,
    pub lcp_critical_ms: f64,
    pub cls_warning: f64,
    pub cls_critical: f64,
    pub inp_warning_ms: f64,
    pub inp_critical_ms: f64,
    pub ttfb_warning_ms: f64,
    pub ttfb_critical_ms: f64,
}

impl Default for VitalsThresholds {
    fn default() -> Self {
        Self {
            lcp_warning_ms: 2500.0,
            lcp_critical_ms: 4000.0,
            cls_warning: 0.1,
            cls_critical: 0.25,
            inp_warning_ms: 200.0,
            inp_critical_ms: 500.0,
            ttfb_warning_ms: 800.0,
            ttfb_critical_ms: 3000.0,
        }
    }
}

/// A single web vitals metric sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VitalsSample {
    pub metric: String,
    pub value: f64,
    pub timestamp: Instant,
}

/// VitalsAlerter — evaluates p75 of each metric over a rolling window
pub struct VitalsAlerter {
    thresholds: VitalsThresholds,
    samples: VecDeque<VitalsSample>,
    window_duration: Duration,
    active_alerts: Vec<VitalsAlert>,
}

impl VitalsAlerter {
    /// Create a new VitalsAlerter with default thresholds and 5-minute window
    pub fn new() -> Self {
        Self::with_config(VitalsThresholds::default(), Duration::from_secs(300))
    }

    /// Create a VitalsAlerter with custom thresholds and window duration
    pub fn with_config(thresholds: VitalsThresholds, window_duration: Duration) -> Self {
        Self {
            thresholds,
            samples: VecDeque::new(),
            window_duration,
            active_alerts: Vec::new(),
        }
    }

    /// Record a new web vitals metric sample
    pub fn record(&mut self, metric: &str, value: f64) {
        self.samples.push_back(VitalsSample {
            metric: metric.to_string(),
            value,
            timestamp: Instant::now(),
        });
        self.prune_old_samples();
    }

    /// Remove samples older than the rolling window
    fn prune_old_samples(&mut self) {
        let cutoff = Instant::now() - self.window_duration;
        while let Some(front) = self.samples.front() {
            if front.timestamp < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Calculate the p75 of a specific metric over the rolling window
    pub fn calculate_p75(&self, metric: &str) -> Option<f64> {
        let mut values: Vec<f64> = self
            .samples
            .iter()
            .filter(|s| s.metric == metric)
            .map(|s| s.value)
            .collect();

        if values.is_empty() {
            return None;
        }

        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p75_index = (values.len() as f64 * 0.75) as usize;
        Some(values[p75_index.min(values.len() - 1)])
    }

    /// Evaluate all metrics against thresholds and update active alerts
    pub fn evaluate(&mut self) -> Vec<VitalsAlert> {
        self.active_alerts.clear();

        let checks = [
            ("LCP", self.calculate_p75("LCP"), self.thresholds.lcp_warning_ms, self.thresholds.lcp_critical_ms, "ms"),
            ("CLS", self.calculate_p75("CLS"), Some(self.thresholds.cls_warning), self.thresholds.cls_critical, ""),
            ("INP", self.calculate_p75("INP"), Some(self.thresholds.inp_warning_ms), self.thresholds.inp_critical_ms, "ms"),
            ("TTFB", self.calculate_p75("TTFB"), Some(self.thresholds.ttfb_warning_ms), self.thresholds.ttfb_critical_ms, "ms"),
        ];

        for (metric, p75, warning, critical, unit) in checks {
            if let Some(value) = p75 {
                let critical_val = critical;
                let warning_val = warning.unwrap_or(0.0);

                if value >= critical_val {
                    self.active_alerts.push(VitalsAlert {
                        metric: metric.to_string(),
                        value,
                        threshold: critical_val,
                        severity: VitalsAlertSeverity::Critical,
                        message: format!("{} p75={:.2}{} exceeds critical threshold ({:.2}{})", metric, value, unit, critical_val, unit),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    });
                } else if value >= warning_val {
                    self.active_alerts.push(VitalsAlert {
                        metric: metric.to_string(),
                        value,
                        threshold: warning_val,
                        severity: VitalsAlertSeverity::Warning,
                        message: format!("{} p75={:.2}{} exceeds warning threshold ({:.2}{})", metric, value, unit, warning_val, unit),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        self.active_alerts.clone()
    }

    /// Get currently active alerts
    pub fn get_active_alerts(&self) -> &[VitalsAlert] {
        &self.active_alerts
    }

    /// Get the current thresholds
    pub fn get_thresholds(&self) -> &VitalsThresholds {
        &self.thresholds
    }
}

impl Default for VitalsAlerter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lcp_critical_alert() {
        let mut alerter = VitalsAlerter::new();
        // Simulate LCP spike — p75 should exceed 4000ms (critical)
        for _ in 0..10 {
            alerter.record("LCP", 2100.0); // Good values
        }
        for _ in 0..10 {
            alerter.record("LCP", 4500.0); // Critical values
        }

        let alerts = alerter.evaluate();
        assert!(alerts.iter().any(|a| a.metric == "LCP" && a.severity == VitalsAlertSeverity::Critical));
    }

    #[test]
    fn test_lcp_warning_alert() {
        let mut alerter = VitalsAlerter::new();
        for _ in 0..20 {
            alerter.record("LCP", 3000.0); // Warning range
        }

        let alerts = alerter.evaluate();
        assert!(alerts.iter().any(|a| a.metric == "LCP" && a.severity == VitalsAlertSeverity::Warning));
    }

    #[test]
    fn test_no_alert_when_good() {
        let mut alerter = VitalsAlerter::new();
        for _ in 0..20 {
            alerter.record("LCP", 1500.0); // Good
        }

        let alerts = alerter.evaluate();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_cls_critical_alert() {
        let mut alerter = VitalsAlerter::new();
        for _ in 0..20 {
            alerter.record("CLS", 0.3); // Critical
        }

        let alerts = alerter.evaluate();
        assert!(alerts.iter().any(|a| a.metric == "CLS" && a.severity == VitalsAlertSeverity::Critical));
    }

    #[test]
    fn test_p75_calculation() {
        let mut alerter = VitalsAlerter::new();
        for v in [100.0, 200.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0] {
            alerter.record("TTFB", v);
        }
        // p75 of 8 values = index 6 = 700.0
        let p75 = alerter.calculate_p75("TTFB");
        assert_eq!(p75, Some(700.0));
    }
}
