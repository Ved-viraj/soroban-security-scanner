# Issue 39: [Security Monitoring] SIEM Integration Is Stub-Only — No Real Alert Delivery to External Security Platforms

**Priority:** 🟠 High
**Labels:** `security-operations` `monitoring` `siem` `compliance`
**Area:** Security Operations / Monitoring
**Files:** `src/security_monitoring/siem.rs`, `src/security_monitoring/alerting.rs`, `src/security_monitoring/engine.rs`

## Description

The `src/security_monitoring/siem.rs` module is designed to integrate the platform's security events with external SIEM systems (Splunk, Elastic, Datadog, etc.). However, the module contains only type definitions, stub functions, and `// TODO: Implement SIEM connector` comments throughout. The `SecurityMonitoringEngine` in `engine.rs` calls `siem.forward_alert()` but the implementation is a no-op that logs and returns `Ok(())`. The `alerting.rs` module defines `AlertChannel::Siem` and `AlertDestination` but there is no code path that actually serializes alerts to SIEM-compatible formats (CEF, LEEF, JSON Syslog) or sends them over TCP/TLS to a SIEM collector. For a platform positioned as "real-time security monitoring and incident response" (per commit `feat(security): real-time security monitoring and incident response (#333)`), this means production deployments have **zero external visibility** into security incidents. If the platform itself is compromised, there are no external alerts to notify the SOC team. Regulatory frameworks like SOC 2 and PCI DSS require centralized security monitoring with SIEM integration — the platform currently cannot satisfy these requirements.

## Acceptance Criteria

- [ ] Implement a `SiemForwarder` trait with methods: `send_alert()`, `send_event()`, `health_check()`, and `flush()`
- [ ] Create concrete implementations: `SplunkForwarder` (HTTP Event Collector), `ElasticForwarder` (Elasticsearch bulk API), `TcpSyslogForwarder` (RFC 5424)
- [ ] Implement CEF (Common Event Format) and JSON serialization for all `SecurityEvent` types
- [ ] Add retry logic with exponential backoff (3 attempts, 1s/5s/25s) for failed SIEM deliveries
- [ ] Implement a local ring buffer (max 10,000 events) that queues events when the SIEM is unreachable and replays on reconnect
- [ ] Add a `GET /api/v1/siem/status` endpoint showing each forwarder's health, queue depth, and last successful delivery time
- [ ] Add configuration in `config.rs` for SIEM endpoints, auth tokens, TLS settings, and batch sizes
- [ ] Write integration tests using a mock SIEM server (local TCP listener) that validates message format and delivery
- [ ] Update `docs/INCIDENT_RESPONSE.md` with SIEM integration setup instructions

## Additional Context

- Required for SOC 2 Type II and PCI DSS compliance
- The platform commit history claims "real-time security monitoring" is a delivered feature
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
