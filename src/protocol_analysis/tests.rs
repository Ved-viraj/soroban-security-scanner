//! Tests for protocol-level invariant verification.

#[cfg(test)]
mod protocol_analysis_tests {
    use crate::protocol_analysis::manifest::{ContractRole, ContractSpec, ProtocolManifest};
    use crate::protocol_analysis::{
        InvariantKind, ProtocolInvariant, VerificationStatus,
    };

    fn make_test_manifest() -> ProtocolManifest {
        ProtocolManifest {
            name: "TestDEX".into(),
            description: "A simple test DEX protocol".into(),
            contracts: vec![
                ContractSpec {
                    name: "token_a".into(),
                    address: "CAAAA...".into(),
                    wasm_path: "token_a.wasm".into(),
                    role: ContractRole::Token,
                },
                ContractSpec {
                    name: "pool".into(),
                    address: "CBBBB...".into(),
                    wasm_path: "pool.wasm".into(),
                    role: ContractRole::AMMPool,
                },
            ],
            interactions: vec![InteractionSpec {
                    from_contract: "token_a".into(),
                    from_function: "transfer".into(),
                    to_contract: "pool".into(),
                    to_function: "swap".into(),
                },
            ],
            invariants: Vec::new(),
        }
    }

    #[test]
    fn test_manifest_validation_passes() {
        let manifest = make_test_manifest();
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_manifest_validation_fails_on_bad_interaction() {
        let mut manifest = make_test_manifest();
        manifest.interactions.push(
            crate::protocol_analysis::manifest::InteractionSpec {
                from_contract: "nonexistent".into(),
                from_function: "foo".into(),
                to_contract: "token_a".into(),
                to_function: "bar".into(),
            },
        );
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_auto_inference_adds_invariants() {
        let mut manifest = make_test_manifest();
        crate::protocol_analysis::auto_inference::augment_with_auto_inferred_invariants(
            &mut manifest,
        )
        .unwrap();

        // Should have inferred invariants for AMMPool and Token
        assert!(!manifest.invariants.is_empty());
        let names: Vec<&str> = manifest.invariants.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"pool__constant_product"));
        assert!(names.contains(&"token_a__supply_equals_balances"));
    }

    #[test]
    fn test_bounded_model_check_verified() {
        let inv = ProtocolInvariant {
            name: "test".into(),
            description: "test".into(),
            expression: "balance[a] == balance[b]".into(),
            kind: InvariantKind::Structural,
            spans_contracts: vec!["pool".into()],
            status: VerificationStatus::Unknown,
            auto_inferred: false,
        };
        let status = super::bounded_model_check(&make_test_manifest(), &inv).unwrap();
        assert_eq!(status, VerificationStatus::Verified);
    }

    #[test]
    fn test_bounded_model_check_unknown() {
        let inv = ProtocolInvariant {
            name: "complex".into(),
            description: "complex".into(),
            expression: "something_difficult".into(),
            kind: InvariantKind::Structural,
            spans_contracts: vec!["pool".into()],
            status: VerificationStatus::Unknown,
            auto_inferred: false,
        };
        let status = super::bounded_model_check(&make_test_manifest(), &inv).unwrap();
        assert_eq!(status, VerificationStatus::Unknown);
    }

    #[test]
    fn test_call_graph_builds() {
        let manifest = make_test_manifest();
        let graph = crate::protocol_analysis::call_graph::build_protocol_call_graph(&manifest)
            .unwrap();
        // Should have nodes for each contract × phase
        assert!(graph.nodes.len() >= 2 * 8); // 2 contracts × 8 phases
        assert!(!graph.edges.is_empty());
        // Should have at least one critical section for AMM pool
        assert!(!graph.critical_sections.is_empty());
    }

    #[test]
    fn test_simulation_basic() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let manifest = make_test_manifest();
        let report = rt.block_on(
            crate::protocol_analysis::simulation::run_protocol_simulation(&manifest, 100),
        )
        .unwrap();

        assert_eq!(report.total_steps, 100);
        // Coverage heatmap should have entries for our contracts
        assert!(report.coverage_heatmap.contains_key("token_a"));
        assert!(report.coverage_heatmap.contains_key("pool"));
    }

    #[test]
    fn test_dashboard_renders() {
        let manifest = make_test_manifest();
        let graph =
            crate::protocol_analysis::call_graph::build_protocol_call_graph(&manifest).unwrap();
        let coverage = std::collections::HashMap::from([
            ("token_a".to_string(), 0.5),
            ("pool".to_string(), 0.25),
        ]);
        let dashboard = crate::protocol_analysis::dashboard::ProtocolHealth::new(
            "TestDEX",
            &[],
            &graph,
            coverage,
            &[],
        );
        let rendered = dashboard.render();
        assert!(rendered.contains("TestDEX"));
        assert!(rendered.contains("INVARIANTS"));
        assert!(rendered.contains("CALL GRAPH"));
    }

    #[test]
    fn test_verification_report_json() {
        let report = crate::protocol_analysis::ProtocolVerificationReport {
            protocol_name: "Test".into(),
            invariants: vec![],
            simulation_results: crate::protocol_analysis::simulation::SimulationReport {
                total_steps: 10,
                violations: vec![],
                coverage_heatmap: std::collections::HashMap::new(),
            },
            protocol_call_graph: crate::protocol_analysis::call_graph::ProtocolCallGraph {
                nodes: vec![],
                edges: vec![],
                critical_sections: vec![],
            },
            adversarial_report: crate::protocol_analysis::adversarial::AdversarialReport {
                total_rounds: 0,
                exploits_found: vec![],
                profit_by_exploit: std::collections::HashMap::new(),
            },
            health: crate::protocol_analysis::dashboard::ProtocolHealth::new(
                "Test",
                &[],
                &crate::protocol_analysis::call_graph::ProtocolCallGraph {
                    nodes: vec![],
                    edges: vec![],
                    critical_sections: vec![],
                },
                std::collections::HashMap::new(),
                &[],
            ),
            exit_code: 0,
        };
        let json = report.to_json().unwrap();
        assert!(json.contains("\"protocol_name\""));
    }

    #[test]
    fn test_compute_exit_code_all_verified() {
        let invs = vec![
            ProtocolInvariant {
                name: "a".into(),
                description: "a".into(),
                expression: "x".into(),
                kind: InvariantKind::Structural,
                spans_contracts: vec![],
                status: VerificationStatus::Verified,
                auto_inferred: false,
            },
        ];
        assert_eq!(super::compute_exit_code(&invs), 0);
    }

    #[test]
    fn test_compute_exit_code_violated() {
        let invs = vec![
            ProtocolInvariant {
                name: "a".into(),
                description: "a".into(),
                expression: "x".into(),
                kind: InvariantKind::Structural,
                spans_contracts: vec![],
                status: VerificationStatus::Violated,
                auto_inferred: false,
            },
        ];
        assert_eq!(super::compute_exit_code(&invs), 1);
    }

    #[test]
    fn test_compute_exit_code_unknown() {
        let invs = vec![
            ProtocolInvariant {
                name: "a".into(),
                description: "a".into(),
                expression: "x".into(),
                kind: InvariantKind::Structural,
                spans_contracts: vec![],
                status: VerificationStatus::Unknown,
                auto_inferred: false,
            },
        ];
        assert_eq!(super::compute_exit_code(&invs), 2);
    }

    #[test]
    fn test_contract_role_display() {
        assert_eq!(format!("{}", ContractRole::Token), "Token");
        assert_eq!(format!("{}", ContractRole::Bridge), "Bridge");
        assert_eq!(format!("{}", ContractRole::Other("Custom".into())), "Custom");
    }

    #[test]
    fn test_verification_status_emoji() {
        assert_eq!(VerificationStatus::Verified.as_emoji(), "✓");
        assert_eq!(VerificationStatus::Unknown.as_emoji(), "⚠");
        assert_eq!(VerificationStatus::Violated.as_emoji(), "✗");
    }

    #[test]
    fn test_print_console_does_not_panic() {
        let report = crate::protocol_analysis::ProtocolVerificationReport {
            protocol_name: "TestProtocol".into(),
            invariants: vec![ProtocolInvariant {
                name: "test_invariant".into(),
                description: "a test".into(),
                expression: "1 == 1".into(),
                kind: InvariantKind::Structural,
                spans_contracts: vec!["c1".into()],
                status: VerificationStatus::Verified,
                auto_inferred: false,
            }],
            simulation_results: crate::protocol_analysis::simulation::SimulationReport {
                total_steps: 50,
                violations: vec![],
                coverage_heatmap: std::collections::HashMap::new(),
            },
            protocol_call_graph: crate::protocol_analysis::call_graph::ProtocolCallGraph {
                nodes: vec![crate::protocol_analysis::call_graph::ProtocolCallNode {
                    id: "n1".into(),
                    contract: "c1".into(),
                    function: "f1".into(),
                    phase: crate::protocol_analysis::call_graph::ProtocolPhase::CoreLogic,
                    invariants_at_entry: vec![],
                    invariants_at_exit: vec![],
                }],
                edges: vec![],
                critical_sections: vec![],
            },
            adversarial_report: crate::protocol_analysis::adversarial::AdversarialReport {
                total_rounds: 0,
                exploits_found: vec![],
                profit_by_exploit: std::collections::HashMap::new(),
            },
            health: crate::protocol_analysis::dashboard::ProtocolHealth::new(
                "TestProtocol",
                &[],
                &crate::protocol_analysis::call_graph::ProtocolCallGraph {
                    nodes: vec![],
                    edges: vec![],
                    critical_sections: vec![],
                },
                std::collections::HashMap::new(),
                &[],
            ),
            exit_code: 0,
        };
        report.print_console(); // should not panic
    }

    #[tokio::test]
    async fn test_run_protocol_verification_smoke() {
        let manifest = make_test_manifest();
        // Serialize to temp file
        let tmp = std::env::temp_dir().join("test_manifest.yaml");
        let yaml = serde_yaml::to_string(&manifest).unwrap();
        std::fs::write(&tmp, yaml).unwrap();

        let report = crate::protocol_analysis::run_protocol_verification(&tmp, Some(10))
            .await
            .unwrap();

        assert_eq!(report.protocol_name, "TestDEX");
        assert_eq!(report.exit_code, 0); // all invariants should hold with seed data

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_auto_inference_lending_pool() {
        let mut manifest = ProtocolManifest {
            name: "LendingTest".into(),
            description: "".into(),
            contracts: vec![ContractSpec {
                name: "lending".into(),
                address: "C...".into(),
                wasm_path: "lending.wasm".into(),
                role: ContractRole::LendingPool,
            }],
            interactions: vec![],
            invariants: vec![],
        };
        crate::protocol_analysis::auto_inference::augment_with_auto_inferred_invariants(
            &mut manifest,
        )
        .unwrap();
        assert!(manifest
            .invariants
            .iter()
            .any(|i| i.name == "lending__deposits_gte_loans"));
    }

    #[test]
    fn test_auto_inference_bridge() {
        let mut manifest = ProtocolManifest {
            name: "BridgeTest".into(),
            description: "".into(),
            contracts: vec![ContractSpec {
                name: "bridge".into(),
                address: "C...".into(),
                wasm_path: "bridge.wasm".into(),
                role: ContractRole::Bridge,
            }],
            interactions: vec![],
            invariants: vec![],
        };
        crate::protocol_analysis::auto_inference::augment_with_auto_inferred_invariants(
            &mut manifest,
        )
        .unwrap();
        assert!(manifest
            .invariants
            .iter()
            .any(|i| i.name == "bridge__locked_equals_minted"));
    }

    #[test]
    fn test_auto_inference_governance() {
        let mut manifest = ProtocolManifest {
            name: "GovTest".into(),
            description: "".into(),
            contracts: vec![ContractSpec {
                name: "gov".into(),
                address: "C...".into(),
                wasm_path: "gov.wasm".into(),
                role: ContractRole::Governance,
            }],
            interactions: vec![],
            invariants: vec![],
        };
        crate::protocol_analysis::auto_inference::augment_with_auto_inferred_invariants(
            &mut manifest,
        )
        .unwrap();
        assert!(manifest
            .invariants
            .iter()
            .any(|i| i.name == "gov__voting_power_equals_delegated"));
    }

    #[test]
    fn test_auto_inference_vault() {
        let mut manifest = ProtocolManifest {
            name: "VaultTest".into(),
            description: "".into(),
            contracts: vec![ContractSpec {
                name: "vault".into(),
                address: "C...".into(),
                wasm_path: "vault.wasm".into(),
                role: ContractRole::Vault,
            }],
            interactions: vec![],
            invariants: vec![],
        };
        crate::protocol_analysis::auto_inference::augment_with_auto_inferred_invariants(
            &mut manifest,
        )
        .unwrap();
        assert!(manifest
            .invariants
            .iter()
            .any(|i| i.name == "vault__collateral_sufficient"));
    }

    #[test]
    fn test_auto_inference_staking_pool() {
        let mut manifest = ProtocolManifest {
            name: "StakeTest".into(),
            description: "".into(),
            contracts: vec![ContractSpec {
                name: "staking".into(),
                address: "C...".into(),
                wasm_path: "staking.wasm".into(),
                role: ContractRole::StakingPool,
            }],
            interactions: vec![],
            invariants: vec![],
        };
        crate::protocol_analysis::auto_inference::augment_with_auto_inferred_invariants(
            &mut manifest,
        )
        .unwrap();
        assert!(manifest
            .invariants
            .iter()
            .any(|i| i.name == "staking__staked_equals_balance"));
    }

    #[test]
    fn test_auto_inference_no_duplicates() {
        let mut manifest = make_test_manifest();
        crate::protocol_analysis::auto_inference::augment_with_auto_inferred_invariants(
            &mut manifest,
        )
        .unwrap();
        let count_before = manifest.invariants.len();
        // Running again should not add duplicates
        crate::protocol_analysis::auto_inference::augment_with_auto_inferred_invariants(
            &mut manifest,
        )
        .unwrap();
        assert_eq!(manifest.invariants.len(), count_before);
    }
}
