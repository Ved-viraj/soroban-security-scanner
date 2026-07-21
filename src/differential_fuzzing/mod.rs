pub mod cross_contract_simulator;
pub mod deterministic_detector;
pub mod discrepancy_detector;
pub mod execution_tracer;
pub mod input_generator;
pub mod ledger_snapshot_integration;
pub mod taint_tracker;
pub mod test_runner;

#[cfg(test)]
mod tests;

pub use cross_contract_simulator::{
    CallEdge, CallGraph, CallNode, CallType, ContractABI, ContractInfo, ControlFlow,
    CrossContractSimulationResult, CrossContractSimulator, ExternalCall, FunctionBody,
    FunctionInfo, FunctionSignature, GasAnalysis, Mutability, NodeType, Parameter,
    ReentrancyCycle, ReentrancyPattern, ReentrancyVulnerability, StateAccess, StateAccessInfo,
    StateAccessType, StateConsistencyIssue, StateConsistencyType, StateVariable, Statement,
    Visibility,
};
pub use taint_tracker::{
    ComposabilityVulnerability, ComposabilityVulnType, SourceOrigin, TaintAnalysisConfig,
    TaintAnalysisReport, TaintCallEdge, TaintCallGraph, TaintCallNode, TaintFlowPath,
    TaintSink, TaintSummary, TaintTag, TaintTracker, SinkType,
};
