//! Database connection pool with integrated metrics monitoring.
//!
//! Uses sqlx PgPool under the hood and exposes health metrics
//! through PoolMonitor.

use crate::db_pool::config::DbPoolConfig;
use crate::db_pool::monitoring::PoolMonitor;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Database connection pool with monitoring
#[derive(Debug, Clone)]
pub struct DbPool {
    /// Pool configuration
    config: DbPoolConfig,
    /// The underlying sqlx pool (optional since it requires actual DB)
    pool: Option<sqlx::PgPool>,
    /// Pool monitor for metrics
    monitor: PoolMonitor,
    /// Whether the pool is initialized
    initialized: Arc<RwLock<bool>>,
}

impl DbPool {
    /// Create a new database pool without connecting yet
    pub fn new(config: DbPoolConfig) -> Self {
        let monitor = PoolMonitor::new(config.clone());
        Self {
            config,
            pool: None,
            monitor,
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Initialize the connection pool and start monitoring
    pub async fn initialize(&mut self) -> Result<()> {
        let mut initialized = self.initialized.write().await;
        if *initialized {
            return Ok(());
        }

        info!(
            "Initializing database connection pool (max: {}, min: {})",
            self.config.max_connections, self.config.min_connections
        );

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(self.config.max_connections)
            .min_connections(self.config.min_connections)
            .connect_timeout(Duration::from_secs(self.config.connect_timeout_secs))
            .idle_timeout(Duration::from_secs(self.config.idle_timeout_secs))
            .max_lifetime(Duration::from_secs(self.config.max_lifetime_secs))
            .connect(&self.config.database_url)
            .await?;

        self.pool = Some(pool);

        // Start monitoring
        self.monitor.start().await;

        *initialized = true;
        info!("Database pool initialized successfully");
        Ok(())
    }

    /// Get a reference to the underlying pool
    pub fn pool(&self) -> Option<&sqlx::PgPool> {
        self.pool.as_ref()
    }

    /// Get the pool monitor
    pub fn monitor(&self) -> &PoolMonitor {
        &self.monitor
    }

    /// Update metrics from the pool state
    pub async fn refresh_metrics(&self) {
        if let Some(ref pool) = self.pool {
            let size = pool.size() as u64;
            let idle = pool.num_idle() as u64;
            let active = size.saturating_sub(idle);

            self.monitor
                .update_metrics(active, idle, size, 0, 0.0)
                .await;
        }
    }

    /// Perform a health check on the pool
    pub async fn health_check(&self) -> Result<bool> {
        match self.pool {
            Some(ref pool) => {
                sqlx::query("SELECT 1").fetch_one(pool).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Close the pool
    pub async fn close(&self) {
        self.monitor.stop().await;
        if let Some(ref pool) = self.pool {
            pool.close().await;
        }
        info!("Database pool closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_pool_creation() {
        let config = DbPoolConfig::default();
        let pool = DbPool::new(config);
        assert!(pool.pool().is_none());
    }

    #[tokio::test]
    async fn test_pool_metrics_refresh_without_connection() {
        let config = DbPoolConfig::default();
        let pool = DbPool::new(config);
        // Without actual connection, refresh should not panic
        pool.refresh_metrics().await;
        let metrics = pool.monitor().get_metrics().await;
        assert_eq!(metrics.max_connections, 20);
    }

    #[tokio::test]
    async fn test_pool_health_check_without_connection() {
        let config = DbPoolConfig::default();
        let pool = DbPool::new(config);
        let healthy = pool.health_check().await.unwrap_or(false);
        assert!(!healthy);
    }
}
