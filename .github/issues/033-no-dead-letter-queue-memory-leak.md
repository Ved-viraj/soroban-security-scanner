# Issue 33: [Transaction Engine] No Dead Letter Queue — Permanently Failed Transactions Leak Memory Indefinitely

**Priority:** 🔴 Critical
**Labels:** `bug` `memory-safety` `transaction-engine` `infrastructure`
**Area:** Core Infrastructure / Memory Safety
**Files:** `src/transaction_engine/queue.rs`, `src/transaction_engine/processor.rs`

## Description

The `TransactionQueue` in `src/transaction_engine/queue.rs` manages transaction lifecycle states including `FailedPermanent`. When a transaction fails permanently (non-retryable failure), it is added to `inner.failed_permanent: Vec<Transaction>` which is **never pruned or capped**. The `cleanup_old_transactions()` method only cleans items where `metadata.updated_at > cutoff` from `completed` and `failed_permanent`, but permanent failures are matched against the same `cutoff` — however, permanent failures may have `updated_at` timestamps that are very recent (the failure happened now), meaning they remain in memory indefinitely. There is no maximum size on `failed_permanent`, no offloading to persistent storage, and no dead-letter queue abstraction. Over months of operation with high transaction volumes, this unbounded vector grows without limit, eventually causing OOM (Out of Memory) crashes. For a security scanner processing thousands of scan submissions daily, even a 1% permanent failure rate would accumulate millions of entries consuming gigabytes of RAM. Furthermore, there is no API or mechanism for operators to drain, export, or inspect the dead letter queue for forensic analysis.

## Acceptance Criteria

- [ ] Implement a `DeadLetterQueue<T>` generic type with configurable max size (default 10,000) and FIFO eviction
- [ ] Add a `DeadLetterEntry` struct wrapping `Transaction` with failure reason, timestamp, and a unique DLQ ID
- [ ] When `failed_permanent` exceeds `max_dlq_size`, evict the oldest entry and log a WARNING with the evicted transaction ID
- [ ] Add a `GET /api/v1/transactions/dead-letter` endpoint with pagination for inspection
- [ ] Add a `DELETE /api/v1/transactions/dead-letter/:id` endpoint for manual removal
- [ ] Add a `POST /api/v1/transactions/dead-letter/:id/requeue` endpoint to manually resubmit a dead-lettered transaction
- [ ] Implement optional DLQ persistence to database via the `database/models.rs` and `database/queries.rs` modules
- [ ] Add a `dlq_size` gauge to `ProcessorMetrics` exposed to monitoring
- [ ] Write tests that enqueue 200,000 permanent failures and verify memory stays bounded

## Additional Context

- This is an OOM vulnerability that manifests over time, making it hard to detect in CI
- The unbounded Vec growth is in the hot path of transaction processing
- See [CRITICAL_ISSUES.md](../../CRITICAL_ISSUES.md) for the full analysis
