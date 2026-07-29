//! Configuration for the database connection pool.
//!
//! Provides configurable settings for connection limits,
//! monitoring intervals, and alert thresholds.

use serde::{Deserialize, Serialize};

/// Configuration for the database connection pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbPoolConfig {
    /// Database connection URL
    pub database_url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum number of idle connections
    pub min_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
    /// Idle connection timeout in seconds
    pub idle_timeout_secs: u64,
    /// Maximum connection lifetime in seconds
    pub max_lifetime_secs: u64,
    /// Metrics collection interval in seconds
    pub metrics_interval_secs: u64,
    /// Whether Prometheus metrics are enabled
    pub prometheus_enabled: bool,
    /// Prometheus metrics endpoint path
    pub metrics_endpoint_path: String,
    /// Prometheus metrics port
    pub metrics_port: u16,
    /// Alert thresholds for pool utilization
    pub alert_thresholds: AlertThresholds,
}

/// Alert thresholds for pool monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Warning threshold as a percentage (0.0 - 1.0)
    pub warn_utilization_pct: f64,
    /// Critical threshold as a percentage (0.0 - 1.0)
    pub critical_utilization_pct: f64,
    /// Warning threshold for connection acquisition latency in milliseconds
    pub warn_latency_ms: u64,
    /// Critical threshold for connection acquisition latency in milliseconds
    pub critical_latency_ms: u64,
    /// Hysteresis percentage to prevent alert flapping
    pub hysteresis_pct: f64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            warn_utilization_pct: 0.80,
            critical_utilization_pct: 0.95,
            warn_latency_ms: 100,
            critical_latency_ms: 500,
            hysteresis_pct: 0.05,
        }
    }
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://postgres:password@localhost:5432/soroban_security_scanner"
                .to_string(),
            max_connections: 20,
            min_connections: 5,
            connect_timeout_secs: 30,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800,
            metrics_interval_secs: 15,
            prometheus_enabled: true,
            metrics_endpoint_path: "/metrics".to_string(),
            metrics_port: 9090,
            alert_thresholds: AlertThresholds::default(),
        }
    }
}

impl DbPoolConfig {
    /// Create a new configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgresql://postgres:password@localhost:5432/soroban_security_scanner".to_string()
            }),
            max_connections: std::env::var("DB_POOL_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "20".to_string())
                .parse()
                .unwrap_or(20),
            min_connections: std::env::var("DB_POOL_MIN_CONNECTIONS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            connect_timeout_secs: std::env::var("DB_POOL_CONNECT_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            idle_timeout_secs: std::env::var("DB_POOL_IDLE_TIMEOUT")
                .unwrap_or_else(|_| "600".to_string())
                .parse()
                .unwrap_or(600),
            max_lifetime_secs: std::env::var("DB_POOL_MAX_LIFETIME")
                .unwrap_or_else(|_| "1800".to_string())
                .parse()
                .unwrap_or(1800),
            metrics_interval_secs: std::env::var("DB_POOL_METRICS_INTERVAL")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .unwrap_or(15),
            prometheus_enabled: std::env::var("DB_POOL_PROMETHEUS_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            metrics_endpoint_path: std::env::var("DB_POOL_METRICS_PATH")
                .unwrap_or_else(|_| "/metrics".to_string()),
            metrics_port: std::env::var("DB_POOL_METRICS_PORT")
                .unwrap_or_else(|_| "9090".to_string())
                .parse()
                .unwrap_or(9090),
            alert_thresholds: AlertThresholds::default(),
        }
    }
}
