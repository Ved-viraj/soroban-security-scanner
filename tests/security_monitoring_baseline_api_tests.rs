//! Integration tests for the security-monitoring baseline API (Issue #435).
//!
//! Covers the `POST /api/v1/security-monitoring/reset-baseline` endpoint:
//! admin success, unauthenticated rejection, non-admin rejection, response
//! shape, baseline invalidation, and safety under concurrent resets.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use soroban_security_scanner::security_monitoring::{
    build_security_monitoring_routes, AlertDispatcher, AlertRouting, AnomalyConfig, BaselineStatus,
    DetectionConfig, EventKind, ResetBaselineResponse, SecurityEvent, SecurityMonitor,
    SecurityMonitoringApiState, SecurityMonitoringAuthContext, SecuritySeverity,
};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// The endpoint under test.
const RESET_BASELINE_PATH: &str = "/api/v1/security-monitoring/reset-baseline";

fn monitor() -> SecurityMonitor {
    SecurityMonitor::new(
        DetectionConfig::default(),
        AnomalyConfig::default(),
        AlertDispatcher::new(AlertRouting::default()),
        soroban_security_scanner::security_monitoring::PlaybookRegistry::with_defaults(),
        None,
    )
}

fn state() -> SecurityMonitoringApiState {
    SecurityMonitoringApiState {
        monitor: Arc::new(Mutex::new(monitor())),
    }
}

/// Walks the monitor through a full learning period so its baseline becomes
/// Active (deterministic — driven by event timestamps).
fn activate(mon: &mut SecurityMonitor) {
    for i in 0..15 {
        mon.ingest(
            &SecurityEvent::new(
                1000 + i,
                EventKind::AuthSuccess,
                soroban_security_scanner::security_monitoring::Component::Auth,
                SecuritySeverity::Info,
            )
            .with_principal("warmup"),
        );
    }
    mon.ingest(
        &SecurityEvent::new(
            1000 + 3600,
            EventKind::AuthSuccess,
            soroban_security_scanner::security_monitoring::Component::Auth,
            SecuritySeverity::Info,
        )
        .with_principal("warmup"),
    );
    assert_eq!(mon.baseline_status(), BaselineStatus::Active);
}

fn reset_request(role: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(RESET_BASELINE_PATH);
    if let Some(role) = role {
        builder = builder.extension(SecurityMonitoringAuthContext {
            user_id: "integration-user".to_string(),
            role: role.to_string(),
        });
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn admin_can_reset_the_baseline() {
    let state = state();
    {
        let mut mon = state.monitor.lock().unwrap();
        activate(&mut mon);
    }

    let app = build_security_monitoring_routes(state.clone());
    let response = app
        .clone()
        .oneshot(reset_request(Some("admin")))
        .await
        .unwrap();

    // 200 + structured JSON body.
    assert_eq!(response.status(), StatusCode::OK);
    let body: ResetBaselineResponse = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(body.success);
    assert_eq!(body.baseline_status, BaselineStatus::Learning);
    assert_eq!(
        body.learning_period_seconds, 3600,
        "default 1-hour learning period"
    );

    // The engine is back in Learning with the previous baseline invalidated.
    let mon = state.monitor.lock().unwrap();
    assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
    assert!(mon.baseline_statistics().is_empty());
}

#[tokio::test]
async fn unauthenticated_request_is_rejected() {
    let state = state();
    let app = build_security_monitoring_routes(state);
    let response = app.oneshot(reset_request(None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn non_admin_request_is_rejected() {
    let state = state();
    let app = build_security_monitoring_routes(state.clone());
    for role in ["user", "operator", "viewer", "auditor"] {
        let response = app
            .clone()
            .oneshot(reset_request(Some(role)))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "role {role} must be forbidden"
        );
        // Rejected requests never touch the baseline.
        let mon = state.monitor.lock().unwrap();
        assert_eq!(mon.baseline_status(), BaselineStatus::Learning);
    }
}

#[tokio::test]
async fn rejected_request_leaves_active_baseline_intact() {
    let state = state();
    {
        let mut mon = state.monitor.lock().unwrap();
        activate(&mut mon);
    }

    let app = build_security_monitoring_routes(state.clone());
    let response = app.oneshot(reset_request(Some("user"))).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Active baseline survived the rejected attempt.
    let mon = state.monitor.lock().unwrap();
    assert_eq!(mon.baseline_status(), BaselineStatus::Active);
    assert!(!mon.baseline_statistics().is_empty());
}

#[tokio::test]
async fn concurrent_resets_do_not_corrupt_monitoring_state() {
    let state = state();
    let app = build_security_monitoring_routes(state.clone());

    // Concurrent admin resets all succeed.
    let mut handles = Vec::new();
    for _ in 0..6 {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            let response = app.oneshot(reset_request(Some("admin"))).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // A single consistent post-condition holds: Learning, no baseline.
    let mut mon = state.monitor.lock().unwrap();
    assert!(matches!(
        mon.baseline_status(),
        BaselineStatus::Learning | BaselineStatus::Resetting
    ));
    assert!(mon.baseline_statistics().is_empty());

    // Monitoring still works after the churn: a fresh window completes and
    // detection activates again.
    assert_eq!(mon.reset_baseline(1_000_000), BaselineStatus::Learning);
    for i in 0..15 {
        mon.ingest(
            &SecurityEvent::new(
                1_000_000 + i,
                EventKind::AuthSuccess,
                soroban_security_scanner::security_monitoring::Component::Auth,
                SecuritySeverity::Info,
            )
            .with_principal("warmup"),
        );
    }
    mon.ingest(
        &SecurityEvent::new(
            1_000_000 + 3600,
            EventKind::AuthSuccess,
            soroban_security_scanner::security_monitoring::Component::Auth,
            SecuritySeverity::Info,
        )
        .with_principal("warmup"),
    );
    assert_eq!(mon.baseline_status(), BaselineStatus::Active);
}
