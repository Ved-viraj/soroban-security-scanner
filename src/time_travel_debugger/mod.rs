pub mod cache;
pub mod contract_upgrade;
pub mod orphaned_state;
pub mod state_injection;

#[cfg(test)]
mod tests;

pub use cache::CacheStats;
pub use contract_upgrade::{
    ContractUpgradeSimulator, IssueCategory, KeyCompatibility, ResourceRequirements,
    StorageDiff, StorageDiffEntry, StorageKeyStatus, StorageLayoutInfo, StorageMigrationReport,
    StorageType, UpgradeProcessResult, UpgradeSimulationResult,
};
pub use orphaned_state::{
    DataLossRisk, OrphanedEntry, OrphanedStateTracker, OrphanedSummary, OverallRisk,
    RecoveryRecommendation, RecommendationPriority,
};
pub use state_injection::{
    ContractState, ForkedState, LedgerSnapshot, TestResult, TimeTravelConfig,
    TimeTravelDebugger,
};
