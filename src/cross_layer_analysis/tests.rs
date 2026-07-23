#[cfg(test)]
mod tests {
    use super::*;
    // Import specific names to avoid RustFinding collision between
    // rust_analyzer::RustFinding and report::RustFinding.
    // Use RustAnalysisFinding (aliased in mod.rs) for analyzer types.
    use super::rust_analyzer::{RustAnalyzer, RustFindingKind};
    use super::wasm_analyzer::*;
    use super::vm_analyzer::*;
    use super::compilation_mapping::*;
    use super::cross_layer_ir::*;
    use super::propagation::*;
    use super::optimization_sensitivity::*;
    use super::report::*;

    // ── Rust Analyzer Tests ──────────────────────────────────────────

    #[test]
    fn rust_analyzer_detects_refcell_panic_risk() {
        let mut analyzer = RustAnalyzer::new();
        let source = "let data = RefCell::new(0); *data.borrow_mut() += 1;";
        analyzer.analyze_source(source, "test.rs");

        let findings = analyzer.findings();
        assert!(!findings.is_empty(), "Should detect RefCell borrow_mut");
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert!(findings[0].can_propagate_to_wasm);
    }

    #[test]
    fn rust_analyzer_detects_hashmap_iteration() {
        let mut analyzer = RustAnalyzer::new();
        let source = "let map = HashMap::new(); for (k, v) in map.iter() {}";
        analyzer.analyze_source(source, "test.rs");

        let findings = analyzer.findings();
        assert!(!findings.is_empty(), "Should detect HashMap iteration");
    }

    #[test]
    fn rust_analyzer_detects_silent_overflow() {
        let mut analyzer = RustAnalyzer::new();
        let source = "let balance = 100; let new = balance + amount;";
        analyzer.analyze_source(source, "test.rs");

        let findings = analyzer.findings();
        assert!(!findings.is_empty(), "Should detect potential silent overflow");
    }

    #[test]
    fn rust_analyzer_detects_missing_auth() {
        let mut analyzer = RustAnalyzer::new();
        let source = "fn transfer(to: Address, amount: i128) { /* no auth check */ }";
        analyzer.analyze_source(source, "test.rs");

        let findings: Vec<_> = analyzer
            .findings()
            .iter()
            .filter(|f| f.kind == RustFindingKind::MissingAuthCheck)
            .collect();
        assert!(!findings.is_empty(), "Should detect missing auth check");
    }

    #[test]
    fn rust_analyzer_detects_catch_unwind() {
        let mut analyzer = RustAnalyzer::new();
        let source = "let result = catch_unwind(|| { dangerous_op(); });";
        analyzer.analyze_source(source, "test.rs");

        let findings: Vec<_> = analyzer
            .findings()
            .iter()
            .filter(|f| f.kind == RustFindingKind::CatchUnwindSuppression)
            .collect();
        assert!(!findings.is_empty());
    }

    #[test]
    fn rust_analyzer_empty_source_produces_no_findings() {
        let mut analyzer = RustAnalyzer::new();
        analyzer.analyze_source("// just comments\n", "test.rs");
        assert!(analyzer.findings().is_empty());
    }

    #[test]
    fn rust_analyzer_propagatable_findings() {
        let mut analyzer = RustAnalyzer::new();
        let source = r#"
            let map: HashMap<String, u64> = HashMap::new();
            for (k, v) in map.iter() { }
            let x = RefCell::new(0);
            *x.borrow_mut() += 1;
        "#;
        analyzer.analyze_source(source, "test.rs");
        let propagatable = analyzer.propagatable_findings();
        assert!(!propagatable.is_empty());
    }

    // ── WASM Analyzer Tests ──────────────────────────────────────────

    #[test]
    fn wasm_analyzer_detects_unreachable() {
        let mut analyzer = WasmAnalyzer::new();
        // Minimal WASM-like bytes with an unreachable (0x00)
        let bytes = vec![0x00, 0x01, 0x02, 0x00, 0x03];
        analyzer.analyze_binary(&bytes);

        let findings = analyzer.findings();
        assert!(!findings.is_empty());
    }

    #[test]
    fn wasm_analyzer_empty_binary_no_findings() {
        let mut analyzer = WasmAnalyzer::new();
        analyzer.analyze_binary(&[]);
        assert!(analyzer.findings().is_empty());
    }

    #[test]
    fn wasm_analyzer_severity_counts() {
        let mut analyzer = WasmAnalyzer::new();
        // Byte 0x00 = unreachable (medium severity via TrapInstruction)
        let bytes = vec![0x00];
        analyzer.analyze_binary(&bytes);
        let (_, _, med, _) = analyzer.severity_counts();
        assert!(med > 0 || analyzer.findings().is_empty());
    }

    // ── VM Analyzer Tests ────────────────────────────────────────────

    #[test]
    fn vm_analyzer_detects_state_before_metering() {
        let mut analyzer = VmAnalyzer::new();
        let trace = vec![
            HostFunctionCall::new("host__ledger_put"),
            HostFunctionCall::new("host__ledger_put"),
            HostFunctionCall::new("host__meter"),
        ];
        analyzer.analyze_trace(&trace);

        let findings = analyzer.findings();
        assert!(!findings.is_empty(), "Should detect state mutation before metering");
    }

    #[test]
    fn vm_analyzer_detects_excessive_call_depth() {
        let mut analyzer = VmAnalyzer::with_max_call_depth(3);
        let mut trace = Vec::new();
        for _ in 0..5 {
            trace.push(HostFunctionCall::new("host__call"));
        }
        analyzer.analyze_trace(&trace);

        let findings: Vec<&VmFinding> = analyzer
            .findings()
            .iter()
            .filter(|f| f.kind == VmFindingKind::ExcessiveCallDepth)
            .collect();
        assert!(!findings.is_empty());
    }

    #[test]
    fn vm_analyzer_empty_trace_no_findings() {
        let mut analyzer = VmAnalyzer::new();
        analyzer.analyze_trace(&[]);
        assert!(analyzer.findings().is_empty());
    }

    // ── Compilation Mapping Tests ────────────────────────────────────

    #[test]
    fn compilation_model_has_50_plus_mappings() {
        let model = CompilationChainModel::new();
        assert!(
            model.total_mappings >= 50,
            "Should have at least 50 mappings, found {}",
            model.total_mappings
        );
    }

    #[test]
    fn compilation_model_lookup_works() {
        let model = CompilationChainModel::new();
        let mapping = model.lookup(&RustPattern::CheckedAdd);
        assert!(mapping.is_some());
        assert!(mapping.unwrap().wasm_patterns.contains(&WasmPattern::I128Add));
    }

    #[test]
    fn compilation_model_has_optimization_sensitive() {
        let model = CompilationChainModel::new();
        let sensitive = model.optimization_sensitive_mappings();
        assert!(!sensitive.is_empty(), "Should have optimization-sensitive mappings");
    }

    #[test]
    fn compilation_model_has_non_deterministic() {
        let model = CompilationChainModel::new();
        let non_det = model.non_deterministic_mappings();
        assert!(
            non_det.iter().any(|m| m.rust_pattern == RustPattern::HashMapIter),
            "Should detect HashMap iteration as non-deterministic"
        );
    }

    // ── Cross-Layer IR Tests ─────────────────────────────────────────

    #[test]
    fn cross_layer_ir_insert_and_retrieve() {
        let mut ir = CrossLayerIr::new();
        let inst = LayerInstruction::RustMir(MirInstruction {
            inner: IrInstruction {
                id: 0,
                layer: CompilationLayer::RustMir,
                opcode: "CheckedAdd".into(),
                location: None,
                operands: vec!["a".into(), "b".into()],
                annotations: std::collections::HashMap::new(),
            },
            mir_kind: "CheckedAdd".into(),
        });
        let id = ir.insert(inst);
        assert!(id > 0);
        assert_eq!(ir.layer_instructions(CompilationLayer::RustMir).len(), 1);
    }

    #[test]
    fn cross_layer_ir_add_mapping() {
        let mut ir = CrossLayerIr::new();
        ir.add_mapping(InstructionMapping {
            source_id: 1,
            source_layer: CompilationLayer::RustMir,
            target_ids: vec![5, 6],
            target_layer: CompilationLayer::Wasm,
            is_deterministic: true,
            optimization_level: "-O0".into(),
            confidence: 1.0,
        });
        let mappings = ir.layer_mappings(CompilationLayer::RustMir, CompilationLayer::Wasm);
        assert_eq!(mappings.len(), 1);
    }

    // ── Propagation Tests ────────────────────────────────────────────

    #[test]
    fn propagation_engine_propagates_refcell() {
        let engine = CrossLayerPropagationEngine::new();
        let findings = vec![RustAnalysisFinding {
            kind: RustFindingKind::RefCellPanicRisk,
            description: "RefCell borrow_mut risk".into(),
            file: "test.rs".into(),
            line: 10,
            column: 5,
            can_propagate_to_wasm: true,
            severity: FindingSeverity::High,
            code_context: "*data.borrow_mut() += 1".into(),
        }];

        let propagated = engine.propagate(&findings);
        assert!(!propagated.is_empty());
        assert_eq!(propagated[0].wasm_manifestation.wasm_opcode, "i32.load / i32.store / unreachable");
        assert!(propagated[0].wasm_manifestation.can_trap);
    }

    #[test]
    fn propagation_engine_skips_non_propagatable() {
        let engine = CrossLayerPropagationEngine::new();
        let findings = vec![RustAnalysisFinding {
            kind: RustFindingKind::CellMisuse,
            description: "Cell misuse".into(),
            file: "test.rs".into(),
            line: 1,
            column: 1,
            can_propagate_to_wasm: false,
            severity: FindingSeverity::Info,
            code_context: String::new(),
        }];

        let propagated = engine.propagate(&findings);
        assert!(propagated.is_empty());
    }

    // ── Optimization Sensitivity Tests ──────────────────────────────

    #[test]
    fn optimization_analyzer_detects_level_specific() {
        let mut analyzer = OptimizationSensitivityAnalyzer::new();
        analyzer.observe("check removed", OptimizationLevel::O2, true);
        analyzer.observe("check removed", OptimizationLevel::Os, true);

        assert!(analyzer.is_optimization_sensitive());
        let level_specific = analyzer.level_specific_findings();
        assert!(!level_specific.is_empty());
    }

    #[test]
    fn optimization_analyzer_check_elimination() {
        let mut analyzer = OptimizationSensitivityAnalyzer::new();
        analyzer.observe("overflow check removed at -O2", OptimizationLevel::O2, true);
        let eliminations = analyzer.check_elimination_findings();
        assert!(!eliminations.is_empty());
        assert!(eliminations[0].is_check_elimination);
    }

    // ── Report Tests ─────────────────────────────────────────────────

    #[test]
    fn cross_layer_report_adds_rows() {
        let mut report = CrossLayerReport::new("Test Report", "test_contract");
        report.add_row(CrossLayerReportRow {
            id: 1,
            rust_finding: RustFinding {
                kind: "RefCell panic".into(),
                description: "test".into(),
                file: "test.rs".into(),
                line: 1,
                column: 0,
                code_snippet: "code".into(),
                can_propagate_to_wasm: true,
                severity: FindingSeverity::High,
            },
            wasm_manifestation: WasmManifestation {
                wasm_opcode: "unreachable".into(),
                description: "traps".into(),
                can_trap: true,
                gas_impact: None,
                was_protection_optimized_away: false,
                severity_change: Some(SeverityChange::Unchanged),
            },
            vm_impact: VmImpact {
                description: "state rollback".into(),
                exploitability: ExploitabilityLevel::Practical,
                state_inconsistency_risk: true,
                metering_impact: None,
                severity_change: Some(SeverityChange::Unchanged),
            },
            worst_severity: FindingSeverity::High,
            confidence: ConfidenceLevel::Certain,
            is_optimization_sensitive: false,
            optimization_levels: vec![],
            impact_level: ImpactLevel::High,
        });

        assert_eq!(report.summary.total_findings, 1);
        assert_eq!(report.summary.high, 1);
    }

    #[test]
    fn cross_layer_report_sorted_by_severity() {
        let mut report = CrossLayerReport::new("Test", "contract");
        // Add a low severity row first
        report.add_row(CrossLayerReportRow {
            id: 1,
            rust_finding: RustFinding {
                kind: "low".into(),
                description: "low".into(),
                file: "".into(),
                line: 0,
                column: 0,
                code_snippet: "".into(),
                can_propagate_to_wasm: false,
                severity: FindingSeverity::Low,
            },
            wasm_manifestation: WasmManifestation {
                wasm_opcode: "".into(),
                description: "".into(),
                can_trap: false,
                gas_impact: None,
                was_protection_optimized_away: false,
                severity_change: None,
            },
            vm_impact: VmImpact {
                description: "".into(),
                exploitability: ExploitabilityLevel::None,
                state_inconsistency_risk: false,
                metering_impact: None,
                severity_change: None,
            },
            worst_severity: FindingSeverity::Low,
            confidence: ConfidenceLevel::Likely,
            is_optimization_sensitive: false,
            optimization_levels: vec![],
            impact_level: ImpactLevel::Low,
        });
        // Add a critical row
        report.add_row(CrossLayerReportRow {
            id: 2,
            rust_finding: RustFinding {
                kind: "critical".into(),
                description: "critical".into(),
                file: "".into(),
                line: 0,
                column: 0,
                code_snippet: "".into(),
                can_propagate_to_wasm: true,
                severity: FindingSeverity::Critical,
            },
            wasm_manifestation: WasmManifestation {
                wasm_opcode: "".into(),
                description: "".into(),
                can_trap: true,
                gas_impact: None,
                was_protection_optimized_away: false,
                severity_change: None,
            },
            vm_impact: VmImpact {
                description: "".into(),
                exploitability: ExploitabilityLevel::Trivial,
                state_inconsistency_risk: true,
                metering_impact: None,
                severity_change: None,
            },
            worst_severity: FindingSeverity::Critical,
            confidence: ConfidenceLevel::Certain,
            is_optimization_sensitive: false,
            optimization_levels: vec![],
            impact_level: ImpactLevel::Critical,
        });

        let sorted = report.sorted_by_severity();
        assert_eq!(sorted[0].worst_severity, FindingSeverity::Critical);
        assert_eq!(sorted[1].worst_severity, FindingSeverity::Low);
    }

    #[test]
    fn rust_finding_kinds_have_descriptions() {
        let kinds = vec![
            RustFindingKind::RefCellPanicRisk,
            RustFindingKind::HashMapIteration,
        ];
        for kind in &kinds {
            assert!(!kind.description().is_empty());
        }
    }

    #[test]
    fn wasm_finding_kinds_have_descriptions() {
        let kinds = vec![
            WasmFindingKind::MissingMemoryGrowCheck,
            WasmFindingKind::TrapInstruction,
        ];
        for kind in &kinds {
            assert!(!kind.description().is_empty());
        }
    }

    #[test]
    fn vm_finding_kinds_have_descriptions() {
        let kinds = vec![
            VmFindingKind::StateBeforeMetering,
            VmFindingKind::ReentrantStateCorruption,
        ];
        for kind in &kinds {
            assert!(!kind.description().is_empty());
        }
    }
}
