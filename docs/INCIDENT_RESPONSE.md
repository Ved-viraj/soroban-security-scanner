# Incident Response Procedures

> **Document Version:** 1.0  
> **Last Updated:** June 28, 2026  
> **Issue:** #338  

---

## 1. Incident Response Lifecycle

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ DETECT   │───▶│  TRIAGE  │───▶│ CONTAIN  │───▶│ RESOLVE  │───▶│  LEARN   │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
    5 min           15 min          1-4 hrs         4-24 hrs        48 hrs
```

---

## 2. Detection & Alerting

### 2.1 Monitoring Sources

| Source | What It Detects | Alert Channel |
|--------|----------------|---------------|
| AWS CloudWatch | Service health, CPU/memory spikes | PagerDuty |
| Prometheus/Grafana | Application metrics, error rates | PagerDuty + Slack |
| Uptime checks (Route53) | External availability | PagerDuty |
| Sentry | Application errors, crashes | Slack |
| Database metrics | Connection pool, slow queries | Slack |
| Custom health endpoints | API, scanner, frontend | PagerDuty |

### 2.2 Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| API error rate | >1% | >5% |
| API latency (p95) | >500ms | >2000ms |
| Database connections | >80% pool | >95% pool |
| Disk usage | >80% | >90% |
| CPU usage | >70% (sustained) | >90% |
| Memory usage | >80% | >95% |

---

## 3. Triage & Classification

### 3.1 Severity Classification

```yaml
SEV1 - Critical:
  definition: "Complete platform outage or data loss"
  examples:
    - All API endpoints returning 5xx
    - Database unreachable
    - Security breach with data exfiltration
  response_time: "15 minutes"
  escalation: "CTO, DevOps Lead"

SEV2 - High:
  definition: "Critical service degraded, workaround available"
  examples:
    - Scan engine down but API still functional
    - Intermittent 5xx errors (>10% of requests)
    - Bounty marketplace unavailable
  response_time: "30 minutes"
  escalation: "DevOps Lead"

SEV3 - Medium:
  definition: "Non-critical service affected"
  examples:
    - Notification service down
    - Analytics dashboard unavailable
    - Slow performance (not affecting critical path)
  response_time: "2 hours"
  escalation: "On-call engineer"

SEV4 - Low:
  definition: "Minor issue, no user impact"
  examples:
    - Documentation site down
    - Non-critical cron job failure
    - Cosmetic UI issues
  response_time: "Next business day"
  escalation: "Engineering team"
```

---

## 4. Incident Commander Role

The first responder automatically becomes the **Incident Commander** until relieved. Responsibilities:

1. **Declare** the incident severity level
2. **Open** a dedicated Slack channel (#incident-{date}-{brief})
3. **Assign** roles: Communications Lead, Operations Lead, Engineering Lead
4. **Update** the status page within 15 minutes (SEV1/SEV2)
5. **Document** timeline in the incident channel
6. **Escalate** if not resolved within RTO
7. **Declare** incident resolved and initiate post-mortem

---

## 5. Communication Templates

### 5.1 Initial Status Page Update (SEV1/SEV2)

```
Title: Investigating service disruption

We are currently investigating reports of [brief description of issue].
Users may experience [symptoms].

Our engineering team has been engaged and is working to identify the cause.

Next update: [time, usually 30 minutes from now]
```

### 5.2 Status Update (During Incident)

```
Title: [Issue identified / Fix in progress / Monitoring]

[Brief description of what's happening]

Current status: [what's been done, what's in progress]
Estimated resolution: [time or "unknown"]

Next update: [time]
```

### 5.3 Resolution Announcement

```
Title: Service restored

The [issue] has been resolved and all services are operating normally.

Root cause: [brief description]
Duration: [start time] to [end time] ([duration])

A detailed post-mortem will be published within 48 hours.

We apologize for the disruption.
```

### 5.4 Internal Slack Notification

```
🚨 INCIDENT DECLARED: SEV[1-4]

Description: [brief]
Start time: [time]
Impact: [what's affected]
Incident Commander: @username
Channel: #incident-[date]-[brief]

Current action: [what's being done]
Next update: [time]
```

### 5.5 Enterprise Customer Email

```
Subject: [URGENT/INFORMATIONAL] Soroban Security Scanner - Service Update

Dear [Customer Name],

We are writing to inform you of [a service disruption / scheduled maintenance]
affecting the Soroban Security Scanner platform.

WHAT HAPPENED:
[Brief, clear description]

IMPACT TO YOU:
[Specific impact, if any]

WHAT WE'RE DOING:
[Actions taken]

ESTIMATED RESOLUTION:
[Time or "we will update you within X minutes"]

We apologize for any inconvenience. Our team is fully engaged on this issue.

For urgent concerns, reply to this email or contact [phone].

Sincerely,
Soroban Security Scanner Team
```

---

## 6. Post-Incident Process

### 6.1 Post-Mortem Template

Every SEV1 and SEV2 incident must have a written post-mortem within 48 hours.

```markdown
# Incident Post-Mortem: [Title]

**Date:** [date]
**Duration:** [start] - [end] ([duration])
**Severity:** SEV[1-4]
**Incident Commander:** [name]

## Summary
[2-3 sentence summary]

## Timeline (UTC)
| Time | Event |
|------|-------|
| HH:MM | Incident detected by [monitoring/alert/report] |
| HH:MM | Incident Commander engaged |
| HH:MM | Root cause identified |
| HH:MM | Fix deployed |
| HH:MM | Services restored |
| HH:MM | Incident resolved |

## Root Cause
[Detailed technical explanation]

## Impact
- Users affected: [number/percentage]
- Data loss: [yes/no, details]
- Revenue impact: [estimate]
- Services affected: [list]

## Resolution
[What was done to fix the issue]

## Detection
- How was it detected? [monitoring/customer report]
- Time to detect: [minutes]
- Time to resolve: [minutes]
- Could detection have been faster? How?

## Prevention
- [ ] Action item 1 (owner: @username, due: [date])
- [ ] Action item 2 (owner: @username, due: [date])
- [ ] Action item 3 (owner: @username, due: [date])

## Lessons Learned
[What went well, what could be improved]
```

### 6.2 Action Item Tracking

- All action items from post-mortems are tracked as GitHub issues
- Label: `post-mortem-action`
- Reviewed at weekly engineering sync
- Escalated if past due date

---

## 7. Emergency Contacts

### 7.1 Internal Team

| Name | Role | Phone | Email |
|------|------|-------|-------|
| DevOps Lead | Primary on-call | [REDACTED] | devops@soroban-scanner.com |
| Security Lead | Security incidents | [REDACTED] | security@soroban-scanner.com |
| Engineering Manager | Escalation | [REDACTED] | eng-mgr@soroban-scanner.com |
| CTO | SEV1 escalation | [REDACTED] | cto@soroban-scanner.com |

### 7.2 External Contacts

| Service | Support Contact | SLA |
|---------|----------------|-----|
| AWS Support | aws.amazon.com/support | Business (1 hour) |
| Stellar.org | stellar.org/community | Community |
| Twilio (SMS) | twilio.com/console/support | Standard |
| SendGrid (Email) | sendgrid.com/support | Standard |

### 7.3 On-Call Rotation

The on-call rotation is managed in PagerDuty:
- **Primary:** DevOps engineer (weekly rotation)
- **Secondary:** Backend engineer (weekly rotation)
- **Escalation:** DevOps Lead (always)

---

## 8. Incident Runbooks

### 8.1 Database Failover

See: `scripts/failover.sh --promote-database`

### 8.2 Full Region Failover

See: `scripts/failover.sh --full-failover`

### 8.3 Backup Restoration

See: `scripts/backup-test.sh --restore --verify`

### 8.4 Service Restart

```bash
# Restart all services in order
kubectl rollout restart deployment/soroban-api
kubectl rollout restart deployment/soroban-scanner
kubectl rollout restart deployment/soroban-frontend
kubectl rollout restart deployment/soroban-notification

# Verify
kubectl get pods -w
```

---

## 8.5 Baseline Learning for Anomaly Detection (Issue #435)

### 8.5.1 What Baseline Learning Is

When the security monitor first starts (or after an administrator resets the
baseline), the anomaly detector has no historical data to judge behaviour
against. Without a learning period, perfectly normal traffic on day one would
be flagged as suspicious, generating alert fatigue during the most critical
post-deployment window.

The monitor therefore runs a **baseline learning period** before anomaly
detection is allowed to alert:

1. During **Learning**, the monitor keeps computing anomaly scores (so the
   model warms up on real traffic) but **suppresses alerts and incidents**.
   Findings are still recorded for diagnostics.
2. When the learning period completes, the `BaselineLearner` computes
   baseline statistics — **mean, standard deviation, p95, p99** — for every
   monitored metric from the observations it collected.
3. With a valid baseline the monitor becomes **Active** and normal detection
   resumes, using the calculated statistics.

### 8.5.2 Defaults and Configuration

| Setting | Default | Notes |
|---------|---------|-------|
| `learning_period_seconds` | **3600** (1 hour) | Configurable via `BaselineConfig` |
| `baseline_expiry_seconds` | **2,592,000** (30 days) | A baseline older than this is stale |
| `min_observations` | 10 | Minimum samples per metric for a trustworthy baseline |

Invalid configurations (e.g. zero/negative learning periods) are rejected at
construction.

### 8.5.3 Baseline States

The engine exposes a `baseline_status` with four states:

| State | Meaning |
|-------|---------|
| `Learning` | Collecting observations; scores computed, alerts/incidents suppressed |
| `Active` | Valid baseline; normal detection behaviour |
| `Resetting` | Transient state during a baseline reset |
| `Degraded` | Baseline missing or stale (expired / insufficient data); detection suppressed until reset |

Lifecycle:

```
initialisation → Learning → (period elapses, baseline valid) → Active
Active → (baseline > 30 days old) → Degraded
Active/Degraded → (admin reset) → Resetting → Learning
Learning → (insufficient observations) → Degraded
```

A missing or insufficient baseline is **never** treated as active: if the
learning period ends without enough observations, or the baseline expires,
the monitor degrades and keeps alerting suppressed rather than generating
misleading alerts.

### 8.5.4 Why Alerts Are Suppressed During Learning

Alerting without a baseline produces false positives (new deployments look
like DDoS attacks). Suppressing during the learning window lets the system
observe its own normal traffic and only start alerting once the baseline is
trustworthy. The suppression happens at the engine boundary: anomaly scores
and rule findings are still computed and available for diagnostics, but no
incidents are opened and no alerts are dispatched.

### 8.5.5 Baseline Expiry (30 Days) and the Degraded State

A baseline more than **30 days** old no longer reflects current traffic
patterns (for example after a major feature launch or traffic shift). The
monitor then:

- transitions to `Degraded`;
- logs a **WARNING** recommending a baseline reset (once, at the transition);
- keeps collecting observations;
- keeps alerts/incidents suppressed until the baseline is reset.

Operators should interpret a `Degraded`/stale-baseline warning as: *"the
current baseline is too old to trust — reset it after confirming traffic is
stable."*

### 8.5.6 Resetting the Baseline (Admin Only)

```
POST /api/v1/security-monitoring/reset-baseline
Authorization: Bearer <admin jwt>
```

- **Admin-only**: unauthenticated requests are rejected with `401`;
  non-admin roles with `403`.
- On success the endpoint returns `200` with a JSON body containing
  `baseline_status: "Learning"` and the configured learning period.
- Reset behaviour:
  1. The monitor enters `Resetting`.
  2. The current baseline and observation state are invalidated/cleared.
  3. A fresh 1-hour learning period starts (`Learning`).

After a reset, operators should expect:

- Anomaly **scores** continue to be computed immediately.
- Alerts/incidents are **suppressed** for the new learning period (default
  1 hour).
- Detection resumes automatically once the new baseline is calculated —
  provided enough observations were collected; otherwise the monitor goes
  `Degraded` and stays suppressed until another reset.

Reset after major infrastructure changes, configuration changes, or traffic
pattern shifts — and only when traffic has been stable enough to re-learn
from.

---

## 9. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-06-28 | Emmanuel-Ugochukwu1 | Initial incident response procedures (Issue #338) |
| 1.1 | 2026-08-20 | Codebuff | Added baseline learning for anomaly detection (Issue #435) |

---

*For emergencies, contact the on-call engineer via PagerDuty or call [REDACTED]*
