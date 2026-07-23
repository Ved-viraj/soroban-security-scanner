# Business Continuity Plan

## Overview

This document outlines the business continuity procedures for the Soroban Security Scanner platform. It covers disaster recovery, high availability, backup strategies, and security hardening measures.

## Table of Contents

1. [Disaster Recovery](#disaster-recovery)
2. [High Availability](#high-availability)
3. [Backup and Restore](#backup-and-restore)
4. [Security Hardening](#security-hardening)
5. [Incident Response](#incident-response)
6. [Monitoring and Alerting](#monitoring-and-alerting)

---

## Disaster Recovery

### Recovery Time Objectives (RTO)

| Component | RTO | Description |
|-----------|-----|-------------|
| Scanner API | 5 minutes | API service recovery |
| Database | 15 minutes | Database failover |
| Full Platform | 30 minutes | Complete system recovery |

### Recovery Point Objectives (RPO)

| Data Type | RPO | Description |
|-----------|-----|-------------|
| Scan Results | 5 minutes | Maximum data loss acceptable |
| User Data | 1 minute | User configuration data |
| Audit Logs | 1 hour | Audit trail data |

### Recovery Procedures

1. **Automated Failover**: The system automatically detects failures and initiates failover to standby instances.
2. **Manual Intervention**: If automated failover fails, operations team can trigger manual failover via the admin console.
3. **Data Restoration**: Restore from the most recent backup. Apply incremental backups to minimize data loss.

---

## High Availability

### Architecture

The platform runs in a multi-zone Kubernetes cluster with:
- Minimum 3 replicas of each service
- Pod anti-affinity rules to spread across zones
- Horizontal Pod Autoscaling based on CPU/memory utilization
- Readiness and liveness probes configured for all services

### Connection Pool Management

The database connection pool is configured with:
- Maximum connections: 20 (configurable)
- Minimum idle connections: 5
- Connection timeout: 30 seconds
- Health check every 15 seconds

Pool utilization is monitored via Prometheus metrics (see [Monitoring and Alerting](#monitoring-and-alerting)).

---

## Backup and Restore

### Database Backups

- **Full backup**: Daily at 02:00 UTC
- **Incremental backup**: Every 6 hours
- **Transaction log backup**: Every 5 minutes
- **Retention**: 30 days for daily, 7 days for incremental

### Configuration Backups

- Scanner configuration stored in version control
- Environment-specific configs in Kubernetes ConfigMaps
- Secrets managed via HashiCorp Vault

---

## Security Hardening

### WASM Upload Sanitization

All uploaded WASM binaries are validated through a multi-stage sanitization pipeline:

#### Stages

1. **Magic Byte Verification**
   - Validates the WASM magic bytes (`\0asm`) and version (1)
   - Rejects binaries with invalid or missing magic bytes

2. **Malware Signature Scanning**
   - Scans against known malware signatures
   - Detects suspicious patterns (oversized binaries, unusual section names)
   - Flags functions with suspicious names (e.g., patterns matching `exec`, `shell`, `inject`)

3. **Content Type Validation**
   - Validates file extension (`.wasm`)
   - Validates MIME type (`application/wasm`)
   - Ensures file content matches expected type

4. **Function Signature Validation (SEI Compliance)**
   - Parses the WASM export section to extract exported function signatures
   - Validates each exported function against the Stellar Environment Interface (SEI)
   - Checks: function name, parameter count, parameter types, return types
   - Supports standard Soroban contract entry points: `init`, `transfer`, `allowance`, `approve`, `balance`, `mint`, `burn`, `upgrade`, `name`, `symbol`, `decimals`, `total_supply`

#### Configuration

The SEI interface is defined in a configurable JSON file (`config/sei-interface.json`). This file can be updated when Stellar updates the SEI specification without requiring code changes.

#### Strict Signature Checking

The `--strict-signature-check` flag enables strict mode:
- Rejects uploads with any function signature mismatches
- Rejects uploads containing functions not in the known SEI interface
- Recommended for production deployments with high security requirements

#### Warning Levels

| Level | Condition | Action |
|-------|-----------|--------|
| INFO | Function matches expected interface | No action required |
| WARNING | Function not found in known interface | Review function for legitimacy |
| WARNING | Function parameter count mismatch | Reject or flag for manual review |
| ERROR | Required function missing | Reject upload |
| CRITICAL | Strict mode violation | Automatically reject upload |

### Database Connection Pool Security

- All database connections use TLS encryption
- Connection pooling with configurable limits prevents connection exhaustion
- Pool utilization alerts at 80% (WARNING) and 95% (CRITICAL)
- Automated alerting via Prometheus/Grafana integration

### API Security

- Rate limiting on all endpoints
- Authentication via JWT tokens with configurable expiry
- Account lockout after multiple failed login attempts
- OAuth2 support for third-party authentication

---

## Incident Response

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| SEV-1 | Complete system outage | < 15 minutes |
| SEV-2 | Partial system degradation | < 30 minutes |
| SEV-3 | Minor issue, no user impact | < 4 hours |
| SEV-4 | Cosmetic issue | < 24 hours |

### Incident Response Steps

1. **Detection**: Automated monitoring detects anomalies and triggers alerts
2. **Triage**: On-call engineer assesses severity and impact
3. **Containment**: Isolate affected components to prevent cascading failures
4. **Resolution**: Apply fix or initiate recovery procedures
5. **Post-mortem**: Document root cause and preventive measures

---

## Monitoring and Alerting

### Prometheus Metrics

The following metrics are exposed for the database connection pool:

| Metric Name | Type | Description |
|-------------|------|-------------|
| `db_pool_active_connections` | Gauge | Currently active connections |
| `db_pool_idle_connections` | Gauge | Currently idle connections |
| `db_pool_total_connections` | Gauge | Total connections in pool |
| `db_pool_wait_queue_depth` | Gauge | Number of waiters in queue |
| `db_pool_connection_acquire_duration_seconds` | Histogram | Connection acquisition latency |

### Grafana Dashboard

A pre-configured Grafana dashboard is available at `grafana/db-pool-dashboard.json` with panels for:
- Pool Utilization % (gauge with WARNING/CRITICAL thresholds)
- Active vs Idle Connections (time series)
- Connection Wait Time (time series with threshold overlays)
- Wait Queue Depth (stat panel)
- Connection Distribution (stacked bar chart)
- Alert Status (color-coded stat)
- 99th Percentile Acquisition Latency

### Alert Thresholds

| Metric | WARNING | CRITICAL |
|--------|---------|----------|
| Pool Utilization | > 80% | > 95% |
| Connection Latency | > 100ms | > 500ms |

Hysteresis of 5% is applied to prevent alert flapping.

---

## Maintenance Windows

- **Scheduled maintenance**: Every Sunday 03:00-05:00 UTC
- **Emergency maintenance**: As needed with 15-minute notice
- **Database migrations**: Zero-downtime using rolling updates

---

## Contact Information

- **Primary On-call**: ops@soroban-scanner.io
- **Security Incidents**: security@soroban-scanner.io
- **Escalation Path**: Platform Engineering Lead → CTO

---

*Last updated: 2026-07-23*
*Version: 1.0.0*
