//! HTTP API for security monitoring (Issue #435).
//!
//! Exposes the security-monitoring baseline controls. The only endpoint
//! today is the admin-only baseline reset:
//!
//! `POST /api/v1/security-monitoring/reset-baseline`
//!
//! # Authorization
//!
//! The endpoint follows the repository's auth-middleware pattern
//! (`src/auth/middleware.rs`): an authenticating layer validates the caller
//! and inserts a role-carrying context into the request extensions; the
//! handler then rejects requests without one (`401`) and requests whose role
//! is not `admin` (`403`). The context type is defined here — rather than
//! importing the (currently unwired, non-compiling) `src/auth` module — so
//! the security-monitoring API stays self-contained and fail-closed: without
//! an injected context every request is rejected. Bridging the real JWT
//! middleware to this endpoint is a two-line adapter that inserts
//! [`SecurityMonitoringAuthContext`] with the authenticated user's role.

use crate::security_monitoring::baseline::BaselineStatus;
use crate::security_monitoring::engine::SecurityMonitor;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::Serialize;
use std::sync::{Arc, Mutex};

/// The role required to reset the security-monitoring baseline.
pub const ADMIN_ROLE: &str = "admin";

/// Minimal role-carrying auth context inserted into request extensions by the
/// authenticating layer. Mirrors the `role` contract of
/// `crate::auth::middleware::AuthContext` so the two bridge cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityMonitoringAuthContext {
    /// Authenticated user id (for audit).
    pub user_id: String,
    /// Role claim (e.g. `admin`).
    pub role: String,
}

impl SecurityMonitoringAuthContext {
    /// An admin context (used by tests and the auth bridge).
    pub fn admin(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            role: ADMIN_ROLE.to_string(),
        }
    }

    /// Whether this context authorizes administrative actions.
    pub fn is_admin(&self) -> bool {
        self.role == ADMIN_ROLE
    }
}

/// Shared state for the security-monitoring HTTP API.
///
/// The engine is not internally thread-safe (single-threaded `&mut self`
/// API), so concurrent requests serialize on this mutex.
#[derive(Clone)]
pub struct SecurityMonitoringApiState {
    /// The shared security monitor.
    pub monitor: Arc<Mutex<SecurityMonitor>>,
}

/// Response body for `POST /api/v1/security-monitoring/reset-baseline`.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct ResetBaselineResponse {
    /// Always `true` on a successful reset.
    pub success: bool,
    /// The resulting baseline state (always `Learning`).
    pub baseline_status: BaselineStatus,
    /// Configured learning period in seconds (the new window length).
    pub learning_period_seconds: i64,
    /// Human-readable confirmation.
    pub message: String,
}

/// Builds the security-monitoring router.
pub fn build_security_monitoring_routes(state: SecurityMonitoringApiState) -> Router {
    Router::new()
        .route(
            "/api/v1/security-monitoring/reset-baseline",
            post(reset_baseline),
        )
        .with_state(state)
}

/// Admin-only: invalidates the current baseline and starts a new learning
/// period. The monitor enters `Resetting` and immediately transitions to
/// `Learning` with a fresh observation window.
async fn reset_baseline(
    State(state): State<SecurityMonitoringApiState>,
    request: Request,
) -> Result<(StatusCode, Json<ResetBaselineResponse>), StatusCode> {
    // The auth layer inserts the context into request extensions. Missing
    // context = unauthenticated (401).
    let auth = request
        .extensions()
        .get::<SecurityMonitoringAuthContext>()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    // Non-admin users cannot reset security monitoring (403).
    if !auth.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let now = chrono::Utc::now().timestamp();
    let mut monitor = state
        .monitor
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let status = monitor.reset_baseline(now);
    let learning_period_seconds = monitor.baseline_config().learning_period_seconds;

    Ok((
        StatusCode::OK,
        Json(ResetBaselineResponse {
            success: true,
            baseline_status: status,
            learning_period_seconds,
            message: "Baseline reset; a new learning period has started".to_string(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_monitoring::alerting::{AlertDispatcher, AlertRouting};
    use crate::security_monitoring::anomaly::AnomalyConfig;
    use crate::security_monitoring::detection::DetectionConfig;
    use crate::security_monitoring::event::{
        Component, EventKind, SecurityEvent, SecuritySeverity,
    };
    use crate::security_monitoring::playbook::PlaybookRegistry;
    use axum::body::Body;
    use axum::http::Method;
    use tower::ServiceExt;

    fn monitor() -> SecurityMonitor {
        SecurityMonitor::new(
            DetectionConfig::default(),
            AnomalyConfig::default(),
            AlertDispatcher::new(AlertRouting::default()),
            PlaybookRegistry::with_defaults(),
            None,
        )
    }

    fn api_state() -> SecurityMonitoringApiState {
        SecurityMonitoringApiState {
            monitor: Arc::new(Mutex::new(monitor())),
        }
    }

    /// Completes the 1-hour learning window with benign observations so the
    /// monitor becomes Active (driven by event timestamps — deterministic).
    fn activate(mon: &mut SecurityMonitor) {
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
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);
    }

    fn reset_request(role: Option<&str>) -> axum::http::Request<Body> {
        let mut builder = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/v1/security-monitoring/reset-baseline");
        if let Some(role) = role {
            builder = builder.extension(SecurityMonitoringAuthContext {
                user_id: "user-1".to_string(),
                role: role.to_string(),
            });
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn admin_reset_succeeds_and_enters_learning() {
        let state = api_state();
        {
            let mut mon = state.monitor.lock().unwrap();
            activate(&mut mon);
        }

        let app = build_security_monitoring_routes(state.clone());
        let response = app.oneshot(reset_request(Some("admin"))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body: ResetBaselineResponse = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(body.success);
        assert_eq!(body.baseline_status, BaselineStatus::Learning);
        assert_eq!(body.learning_period_seconds, 3600);

        // The previous baseline was invalidated.
        let mon = state.monitor.lock().unwrap();
        assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
        assert!(mon.baseline_statistics().is_empty());
    }

    #[tokio::test]
    async fn unauthenticated_reset_is_rejected_with_401() {
        let state = api_state();
        let app = build_security_monitoring_routes(state);
        let response = app.oneshot(reset_request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_admin_reset_is_rejected_with_403() {
        let state = api_state();
        let app = build_security_monitoring_routes(state.clone());
        for role in ["user", "operator", "viewer"] {
            let response = app
                .clone()
                .oneshot(reset_request(Some(role)))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "role {role} must be rejected"
            );
            // The baseline was not touched by rejected requests.
            let mon = state.monitor.lock().unwrap();
            assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
        }
    }

    #[tokio::test]
    async fn rejected_reset_does_not_modify_state() {
        let state = api_state();
        {
            let mut mon = state.monitor.lock().unwrap();
            activate(&mut mon);
        }

        let app = build_security_monitoring_routes(state.clone());
        // Non-admin attempt is rejected and leaves the active baseline intact.
        let response = app
            .clone()
            .oneshot(reset_request(Some("user")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let mon = state.monitor.lock().unwrap();
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);
        assert!(!mon.baseline_statistics().is_empty());
    }

    #[tokio::test]
    async fn reset_does_not_corrupt_concurrent_monitoring() {
        let state = api_state();
        let app = build_security_monitoring_routes(state.clone());

        // Fire several resets concurrently while the monitor keeps ingesting.
        let mut handles = Vec::new();
        for _ in 0..4 {
            let app = app.clone();
            handles.push(tokio::spawn(async move {
                let response = app.oneshot(reset_request(Some("admin"))).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            }));
        }
        {
            let mut mon = state.monitor.lock().unwrap();
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
        }
        for h in handles {
            h.await.unwrap();
        }

        // State is consistent: no baseline survived the churn.
        let mut mon = state.monitor.lock().unwrap();
        assert!(matches!(
            mon.baseline_status(),
            BaselineStatus::Learning | BaselineStatus::Resetting
        ));
        assert!(mon.baseline_statistics().is_empty());

        // Anchor a deterministic new learning window and verify the engine
        // still functions after all the concurrent resets.
        assert_eq!(mon.reset_baseline(60_000), BaselineStatus::Learning);
        for i in 0..15 {
            mon.ingest(
                &SecurityEvent::new(
                    60_000 + i,
                    EventKind::AuthSuccess,
                    Component::Auth,
                    SecuritySeverity::Info,
                )
                .with_principal("warmup"),
            );
        }
        mon.ingest(
            &SecurityEvent::new(
                60_000 + 3600,
                EventKind::AuthSuccess,
                Component::Auth,
                SecuritySeverity::Info,
            )
            .with_principal("warmup"),
        );
        assert_eq!(mon.baseline_status(), BaselineStatus::Active);
    }
}
