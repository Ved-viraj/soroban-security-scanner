//! Pool monitoring with Prometheus metric exposure and alert thresholds.
//!
//! The PoolMonitor tracks:
//! - Active, idle, and total connection counts (gauges)
//! - Wait queue depth (gauge)
//! - Connection acquisition latency (histogram)
//! - Pool utilization percentage with WARN/CRITICAL alert thresholds

use crate::db_pool::config::{AlertThresholds, DbPoolConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Pool monitor that collects and exposes connection pool metrics
#[derive(Debug, Clone)]
pub struct PoolMonitor {
    /// Configuration
    config: DbPoolConfig,
    /// Current pool metrics snapshot
    metrics: Arc<RwLock<PoolMetrics>>,
    /// Alert state to implement hysteresis
    alert_state: Arc<RwLock<AlertState>>,
    /// Whether the monitor is running
    running: Arc<RwLock<bool>>,
    /// Latency histogram for tracking connection acquisition durations
    latency_histogram: Arc<RwLock<LatencyHistogram>>,
}

/// Snapshot of pool metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMetrics {
    /// Timestamp of the metrics snapshot
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Active connections currently in use
    pub active_connections: u64,
    /// Idle connections available
    pub idle_connections: u64,
    /// Total connections (active + idle)
    pub total_connections: u64,
    /// Maximum connections allowed
    pub max_connections: u64,
    /// Number of waiters in the queue
    pub wait_queue_depth: u64,
    /// Connection acquisition latency in milliseconds (recent)
    pub acquire_latency_ms: f64,
    /// Pool utilization as a fraction (0.0 - 1.0)
    pub utilization_pct: f64,
    /// Current alert level
    pub alert_level: AlertLevel,
    /// Alert message if any
    pub alert_message: Option<String>,
}

/// Alert level
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertLevel {
    /// No alerts
    Normal,
    /// Warning threshold reached
    Warning,
    /// Critical threshold reached
    Critical,
}

/// Alert state for hysteresis tracking
#[derive(Debug, Clone)]
struct AlertState {
    current_level: AlertLevel,
    warn_active: bool,
    critical_active: bool,
    last_warn_time: Option<Instant>,
    last_critical_time: Option<Instant>,
}

impl AlertState {
    fn new() -> Self {
        Self {
            current_level: AlertLevel::Normal,
            warn_active: false,
            critical_active: false,
            last_warn_time: None,
            last_critical_time: None,
        }
    }
}

impl PoolMonitor {
    /// Create a new pool monitor
    pub fn new(config: DbPoolConfig) -> Self {
        let histogram_buckets = vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0];
        Self {
            metrics: Arc::new(RwLock::new(PoolMetrics {
                timestamp: chrono::Utc::now(),
                active_connections: 0,
                idle_connections: 0,
                total_connections: 0,
                max_connections: config.max_connections as u64,
                wait_queue_depth: 0,
                acquire_latency_ms: 0.0,
                utilization_pct: 0.0,
                alert_level: AlertLevel::Normal,
                alert_message: None,
            })),
            alert_state: Arc::new(RwLock::new(AlertState::new())),
            running: Arc::new(RwLock::new(false)),
            latency_histogram: Arc::new(RwLock::new(LatencyHistogram::new(histogram_buckets))),
            config,
        }
    }

    /// Start the monitoring loop
    pub async fn start(&self) {
        let mut running = self.running.write().await;
        if *running {
            return;
        }
        *running = true;
        drop(running);

        let metrics = self.metrics.clone();
        let alert_state = self.alert_state.clone();
        let config = self.config.clone();
        let running_flag = self.running.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(config.metrics_interval_secs));

            loop {
                let is_running = *running_flag.read().await;
                if !is_running {
                    break;
                }

                interval.tick().await;

                // Check alert thresholds
                let mut current_metrics = metrics.read().await.clone();
                let mut state = alert_state.write().await;

                let utilization = current_metrics.utilization_pct;
                let thresholds = &config.alert_thresholds;

                // Evaluate alert levels with hysteresis
                let (new_level, message) = Self::evaluate_alerts(
                    utilization,
                    current_metrics.acquire_latency_ms,
                    thresholds,
                    &state,
                );

                current_metrics.alert_level = new_level.clone();
                current_metrics.alert_message = message;

                // Update state
                state.current_level = new_level.clone();
                match new_level {
                    AlertLevel::Warning => {
                        state.warn_active = true;
                        state.last_warn_time = Some(Instant::now());
                    }
                    AlertLevel::Critical => {
                        state.critical_active = true;
                        state.last_critical_time = Some(Instant::now());
                    }
                    AlertLevel::Normal => {
                        state.warn_active = false;
                        state.critical_active = false;
                    }
                }

                // Update metrics
                *metrics.write().await = current_metrics;
            }
        });
    }

    /// Stop the monitoring loop
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Update pool metrics from the connection pool
    pub async fn update_metrics(
        &self,
        active: u64,
        idle: u64,
        total: u64,
        wait_queue: u64,
        acquire_latency: f64,
    ) {
        let max = self.config.max_connections as u64;
        let utilization = if max > 0 {
            (active as f64) / (max as f64)
        } else {
            0.0
        };

        // Record latency in histogram (convert from milliseconds to seconds for Prometheus)
        {
            let mut hist = self.latency_histogram.write().await;
            hist.observe(acquire_latency / 1000.0);
        }

        let mut metrics = self.metrics.write().await;
        metrics.timestamp = chrono::Utc::now();
        metrics.active_connections = active;
        metrics.idle_connections = idle;
        metrics.total_connections = total;
        metrics.max_connections = max;
        metrics.wait_queue_depth = wait_queue;
        metrics.acquire_latency_ms = acquire_latency;
        metrics.utilization_pct = utilization;

        // Emit as Prometheus metrics (logged in a format Prometheus can scrape)
        tracing::info!(
            target: "db_pool_metrics",
            active_connections = active,
            idle_connections = idle,
            total_connections = total,
            wait_queue_depth = wait_queue,
            acquire_latency_ms = acquire_latency,
            utilization_pct = utilization,
            alert_level = ?metrics.alert_level,
        );
    }

    /// Get the current metrics snapshot
    pub async fn get_metrics(&self) -> PoolMetrics {
        self.metrics.read().await.clone()
    }

    /// Evaluate alert levels with hysteresis
    fn evaluate_alerts(
        utilization: f64,
        latency_ms: f64,
        thresholds: &AlertThresholds,
        state: &AlertState,
    ) -> (AlertLevel, Option<String>) {
        let hysteresis = thresholds.hysteresis_pct;

        // Critical check (with hysteresis)
        let critical_trigger = thresholds.critical_utilization_pct;
        let critical_release = critical_trigger * (1.0 - hysteresis);

        if utilization >= critical_trigger || latency_ms >= thresholds.critical_latency_ms as f64 {
            let reason = if utilization >= critical_trigger {
                format!(
                    "Pool utilization at {:.1}% (threshold: {:.1}%)",
                    utilization * 100.0,
                    critical_trigger * 100.0
                )
            } else {
                format!(
                    "Connection latency at {:.0}ms (threshold: {}ms)",
                    latency_ms, thresholds.critical_latency_ms
                )
            };
            return (AlertLevel::Critical, Some(format!("CRITICAL: {}", reason)));
        }

        // If we were in critical, check if we've dropped below release threshold
        if state.current_level == AlertLevel::Critical {
            if utilization < critical_release {
                // Fall through to warning check
            } else {
                return (
                    AlertLevel::Critical,
                    Some("CRITICAL: Pool still above release threshold".to_string()),
                );
            }
        }

        // Warning check (with hysteresis)
        let warn_trigger = thresholds.warn_utilization_pct;
        let warn_release = warn_trigger * (1.0 - hysteresis);

        if utilization >= warn_trigger || latency_ms >= thresholds.warn_latency_ms as f64 {
            let reason = if utilization >= warn_trigger {
                format!(
                    "Pool utilization at {:.1}% (threshold: {:.1}%)",
                    utilization * 100.0,
                    warn_trigger * 100.0
                )
            } else {
                format!(
                    "Connection latency at {:.0}ms (threshold: {}ms)",
                    latency_ms, thresholds.warn_latency_ms
                )
            };
            return (AlertLevel::Warning, Some(format!("WARNING: {}", reason)));
        }

        // If we were in warning, check release
        if state.current_level == AlertLevel::Warning {
            if utilization < warn_release {
                return (AlertLevel::Normal, None);
            }
            return (
                AlertLevel::Warning,
                Some("WARNING: Pool still above release threshold".to_string()),
            );
        }

        (AlertLevel::Normal, None)
    }

    /// Get Prometheus-formatted metrics text
    pub async fn format_prometheus_metrics(&self) -> String {
        let metrics = self.metrics.read().await.clone();
        let hist = self.latency_histogram.read().await.clone();
        let ts = metrics.timestamp.timestamp_millis();

        let mut output = String::new();

        // Gauges
        output.push_str("# HELP db_pool_active_connections Active connections in the pool\n");
        output.push_str("# TYPE db_pool_active_connections gauge\n");
        output.push_str(&format!(
            "db_pool_active_connections {} {}\n\n",
            metrics.active_connections, ts
        ));

        output.push_str("# HELP db_pool_idle_connections Idle connections in the pool\n");
        output.push_str("# TYPE db_pool_idle_connections gauge\n");
        output.push_str(&format!(
            "db_pool_idle_connections {} {}\n\n",
            metrics.idle_connections, ts
        ));

        output.push_str("# HELP db_pool_total_connections Total connections in the pool\n");
        output.push_str("# TYPE db_pool_total_connections gauge\n");
        output.push_str(&format!(
            "db_pool_total_connections {} {}\n\n",
            metrics.total_connections, ts
        ));

        output.push_str("# HELP db_pool_wait_queue_depth Number of waiters in the queue\n");
        output.push_str("# TYPE db_pool_wait_queue_depth gauge\n");
        output.push_str(&format!(
            "db_pool_wait_queue_depth {} {}\n\n",
            metrics.wait_queue_depth, ts
        ));

        // Histogram
        output.push_str("# HELP db_pool_connection_acquire_duration_seconds Connection acquisition latency in seconds\n");
        output.push_str("# TYPE db_pool_connection_acquire_duration_seconds histogram\n");

        for (i, bucket) in hist.buckets.iter().enumerate() {
            let count = hist.counts.get(i).copied().unwrap_or(0);
            output.push_str(&format!(
                "db_pool_connection_acquire_duration_seconds_bucket{{le=\"{}\"}} {} {}\n",
                bucket, count, ts
            ));
        }
        // +Inf bucket
        let inf_count = hist.counts.last().copied().unwrap_or(0);
        output.push_str(&format!(
            "db_pool_connection_acquire_duration_seconds_bucket{{le=\"+Inf\"}} {} {}\n",
            inf_count, ts
        ));

        output.push_str(&format!(
            "db_pool_connection_acquire_duration_seconds_sum {} {}\n",
            hist.sum, ts
        ));
        output.push_str(&format!(
            "db_pool_connection_acquire_duration_seconds_count {} {}\n",
            hist.count, ts
        ));

        output
    }
}

/// JSON response for the /api/v1/db-pool/metrics endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbPoolMetricsResponse {
    pub success: bool,
    pub data: PoolMetrics,
    pub prometheus_text: String,
}

impl PoolMonitor {
    /// Generate a JSON response for the metrics endpoint
    pub async fn metrics_response(&self) -> DbPoolMetricsResponse {
        let metrics = self.get_metrics().await;
        let prometheus_text = self.format_prometheus_metrics().await;

        DbPoolMetricsResponse {
            success: true,
            data: metrics,
            prometheus_text,
        }
    }
}

/// In-memory latency histogram for demonstration
#[derive(Debug, Clone)]
pub struct LatencyHistogram {
    buckets: Vec<f64>,
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}

impl LatencyHistogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let len = buckets.len();
        Self {
            buckets,
            counts: vec![0; len + 1], // +1 for +Inf
            sum: 0.0,
            count: 0,
        }
    }

    pub fn observe(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;

        for (i, bucket) in self.buckets.iter().enumerate() {
            if value <= *bucket {
                self.counts[i] += 1;
            }
        }
        self.counts[self.buckets.len()] = self.count; // +Inf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> DbPoolConfig {
        DbPoolConfig {
            max_connections: 20,
            metrics_interval_secs: 1,
            alert_thresholds: AlertThresholds {
                warn_utilization_pct: 0.80,
                critical_utilization_pct: 0.95,
                warn_latency_ms: 100,
                critical_latency_ms: 500,
                hysteresis_pct: 0.05,
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_pool_monitor_creation() {
        let config = create_test_config();
        let monitor = PoolMonitor::new(config);
        let metrics = monitor.get_metrics().await;
        assert_eq!(metrics.max_connections, 20);
        assert_eq!(metrics.alert_level, AlertLevel::Normal);
    }

    #[tokio::test]
    async fn test_metrics_update() {
        let config = create_test_config();
        let monitor = PoolMonitor::new(config);
        monitor.update_metrics(10, 5, 15, 2, 50.0).await;
        let metrics = monitor.get_metrics().await;
        assert_eq!(metrics.active_connections, 10);
        assert_eq!(metrics.idle_connections, 5);
        assert_eq!(metrics.total_connections, 15);
        assert_eq!(metrics.wait_queue_depth, 2);
    }

    #[test]
    fn test_alert_normal_utilization() {
        let thresholds = AlertThresholds::default();
        let state = AlertState::new();
        let (level, msg) = PoolMonitor::evaluate_alerts(0.5, 10.0, &thresholds, &state);
        assert_eq!(level, AlertLevel::Normal);
        assert!(msg.is_none());
    }

    #[test]
    fn test_alert_warning_utilization() {
        let thresholds = AlertThresholds::default();
        let state = AlertState::new();
        let (level, msg) = PoolMonitor::evaluate_alerts(0.85, 10.0, &thresholds, &state);
        assert_eq!(level, AlertLevel::Warning);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("WARNING"));
    }

    #[test]
    fn test_alert_critical_utilization() {
        let thresholds = AlertThresholds::default();
        let state = AlertState::new();
        let (level, msg) = PoolMonitor::evaluate_alerts(0.96, 10.0, &thresholds, &state);
        assert_eq!(level, AlertLevel::Critical);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("CRITICAL"));
    }

    #[test]
    fn test_alert_critical_latency() {
        let thresholds = AlertThresholds::default();
        let state = AlertState::new();
        let (level, msg) = PoolMonitor::evaluate_alerts(0.5, 600.0, &thresholds, &state);
        assert_eq!(level, AlertLevel::Critical);
        assert!(msg.unwrap().contains("latency"));
    }

    #[test]
    fn test_hysteresis_prevents_flapping() {
        let thresholds = AlertThresholds::default();
        // State where we're currently in warning
        let mut state = AlertState::new();
        state.current_level = AlertLevel::Warning;
        state.warn_active = true;

        // Slightly below the release threshold
        let warn_release = thresholds.warn_utilization_pct * (1.0 - thresholds.hysteresis_pct);
        let (level, _) =
            PoolMonitor::evaluate_alerts(warn_release - 0.01, 10.0, &thresholds, &state);
        assert_eq!(level, AlertLevel::Normal);
    }

    #[tokio::test]
    async fn test_prometheus_format() {
        let config = create_test_config();
        let monitor = PoolMonitor::new(config);
        monitor.update_metrics(10, 5, 15, 2, 50.0).await;
        let prom_text = monitor.format_prometheus_metrics().await;
        assert!(prom_text.contains("db_pool_active_connections"));
        assert!(prom_text.contains("db_pool_idle_connections"));
        assert!(prom_text.contains("db_pool_wait_queue_depth"));
        assert!(prom_text.contains("db_pool_connection_acquire_duration_seconds"));
    }

    #[tokio::test]
    async fn test_metrics_response() {
        let config = create_test_config();
        let monitor = PoolMonitor::new(config);
        monitor.update_metrics(10, 5, 15, 2, 50.0).await;
        let response = monitor.metrics_response().await;
        assert!(response.success);
        assert_eq!(response.data.active_connections, 10);
        assert!(response
            .prometheus_text
            .contains("db_pool_active_connections"));
    }
}
