# Issue 35: [API Rate Limiting] In-Memory Token Buckets Have No Distributed Consistency — Rate Limits Bypassed Across Multi-Instance Deployments

**Priority:** 🔴 Critical
**Labels:** `security` `rate-limiting` `infrastructure` `kubernetes`
**Area:** Infrastructure / Rate Limiting
**Files:** `src/api_rate_limiting/limiter.rs`, `src/api_rate_limiting/store.rs`, `src/rate_limiting/limiter.rs`

## Description

The API rate limiting system across `src/api_rate_limiting/` and `src/rate_limiting/` implements token bucket and sliding window algorithms using in-memory data structures (RwLock-protected HashMaps). The `RateLimitStore` trait in `store.rs` has only an in-memory implementation. When the scanner is deployed across multiple instances behind a load balancer (the standard Kubernetes deployment described in `examples/kubernetes_isolated_scanning.rs`), each instance maintains **its own independent rate limit counters**. An attacker distributing requests across all instances can effectively multiply the rate limit by the number of pods — a 100 req/min limit becomes 300 req/min across 3 pods. For a security scanning platform that processes untrusted contract submissions, this is a critical bypass vector: an attacker can flood the system with malicious contracts designed to trigger expensive analysis paths (deep recursive fuzzing, large WASM parsing) across all instances simultaneously, causing a distributed denial-of-service despite rate limiting being nominally "enabled." The `RATE_LIMITING.md` documentation does not address distributed deployment considerations.

## Acceptance Criteria

- [ ] Implement a `RedisRateLimitStore` that uses Redis as a shared counter backend with Lua scripting for atomic token operations
- [ ] Add a `CentralizedStore` trait implementation configurable via `RateLimitConfig` with backends: `InMemory`, `Redis`, `Memcached`
- [ ] Implement clock-skew tolerance (±2 seconds) using NTP-synchronized timestamps in the Redis Lua scripts
- [ ] Add a graceful degradation mode: if Redis is unreachable, fall back to per-instance in-memory limiting with a `degraded_limit = configured_limit / instance_count` heuristic
- [ ] Create a `RateLimitConsistencyTest` in the test suite that simulates 3 instances processing overlapping request streams and verifies the aggregate limit is enforced
- [ ] Add a `GET /api/v1/rate-limits/status` debug endpoint showing per-client remaining quota across all instances
- [ ] Update `RATE_LIMITING.md` with distributed deployment guidance and Redis configuration examples

## Additional Context

- The Kubernetes deployment in `examples/kubernetes_isolated_scanning.rs` uses multiple pods
- In-memory rate limiting is fundamentally incompatible with horizontal scaling
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
