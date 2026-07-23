//! Database connection pool with Prometheus/Grafana metrics integration.
//!
//! Provides a secure connection pool with:
//! - Connection pooling with configurable limits
//! - Prometheus metrics exposure (gauges + histograms)
//! - Pool health monitoring with alert thresholds
//! - REST endpoint for ad-hoc metrics debugging

pub mod config;
pub mod monitoring;
pub mod pool;

pub use self::config::DbPoolConfig;
pub use self::monitoring::PoolMonitor;
pub use self::pool::DbPool;
