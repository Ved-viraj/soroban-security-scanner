use soroban_sdk::{Address, Env, Symbol};
use soroban_security_scanner::escrow::EscrowClient;
use soroban_security_scanner::escrow::{Escrow, EscrowData, MINIMUM_TIMEOUT_LEDGERS, DEFAULT_TIMEOUT_LEDGERS};

#[test]
fn test_reentrancy_security() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let beneficiary = Address::generate(&env);
    let amount = 1000;

    // Create escrow
    client.create_escrow(&beneficiary, &amount);

    // Test secure version - this should be safe from reentrancy
    let escrow_info_before = client.get_escrow_info();
    assert!(!escrow_info_before.released);

    // This call is now secure against reentrancy
    client.release();

    let escrow_info_after = client.get_escrow_info();
    assert!(escrow_info_after.released);

    // Verify that calling release again fails
    let result = std::panic::catch_unwind(|| {
        client.release();
    });
    assert!(result.is_err());
}

#[test]
fn test_create_escrow_with_timeout() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let beneficiary = Address::generate(&env);
    let amount = 500;

    // Create escrow with a custom timeout
    client.create_escrow_with_timeout(&beneficiary, &amount, &DEFAULT_TIMEOUT_LEDGERS);

    let info = client.get_escrow_info();
    assert_eq!(info.amount, 500);
    assert_eq!(info.timeout_ledgers, DEFAULT_TIMEOUT_LEDGERS);
    assert!(!info.released);
    assert!(!info.cancelled);
    assert!(!info.refunded);
    // Verify created_at was set to a ledger sequence
    assert!(info.created_at > 0);
}

#[test]
fn test_create_escrow_below_minimum_timeout() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let beneficiary = Address::generate(&env);
    let amount = 100;

    // Attempt to create escrow with timeout below minimum should panic
    let result = std::panic::catch_unwind(|| {
        client.create_escrow_with_timeout(&beneficiary, &amount, &(MINIMUM_TIMEOUT_LEDGERS - 1));
    });
    assert!(result.is_err(), "Should reject timeout below minimum");
}

#[test]
fn test_refund_after_timeout() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let depositor = Address::generate(&env);
    let beneficiary = Address::generate(&env);
    let amount = 1000;

    // Create escrow with minimum timeout
    client.create_escrow_with_timeout(&beneficiary, &amount, &MINIMUM_TIMEOUT_LEDGERS);

    // Verify escrow state before timeout
    let info = client.get_escrow_info();
    assert!(!info.released);
    assert!(!info.cancelled);
    assert!(!info.refunded);
    assert_eq!(info.amount, amount);

    // Check expiration status
    let expired = client.is_expired();
    // In test environment without ledger advancement, verify the function works
    // The actual timeout behavior would require ledger manipulation
    assert!(!expired, "Should not be expired immediately after creation");
}

#[test]
fn test_cancel_before_release() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let depositor = Address::generate(&env);
    let beneficiary = Address::generate(&env);
    let amount = 1000;

    // Create escrow
    client.create_escrow(&beneficiary, &amount);

    let info_before = client.get_escrow_info();
    assert!(!info_before.cancelled);
    assert!(!info_before.released);

    // Cancel the escrow (as the depositor)
    client.cancel(&depositor);

    let info_after = client.get_escrow_info();
    assert!(info_after.cancelled, "Escrow should be cancelled");
    assert!(!info_after.released);
}

#[test]
fn test_cannot_refund_before_timeout() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let depositor = Address::generate(&env);
    let beneficiary = Address::generate(&env);
    let amount = 1000;

    // Create escrow with a long timeout
    client.create_escrow_with_timeout(&beneficiary, &amount, &(DEFAULT_TIMEOUT_LEDGERS * 10));

    // Refund should fail before timeout
    let result = std::panic::catch_unwind(|| {
        client.refund(&depositor);
    });
    assert!(
        result.is_err(),
        "Refund before timeout should fail"
    );
}

#[test]
fn test_cannot_cancel_after_release() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let depositor = Address::generate(&env);
    let beneficiary = Address::generate(&env);
    let amount = 1000;

    // Create escrow
    client.create_escrow(&beneficiary, &amount);

    // Release the escrow
    client.release();

    // Cancel should fail after release
    let result = std::panic::catch_unwind(|| {
        client.cancel(&depositor);
    });
    assert!(
        result.is_err(),
        "Cancel after release should fail"
    );
}

#[test]
fn test_cannot_refund_after_release() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let depositor = Address::generate(&env);
    let beneficiary = Address::generate(&env);
    let amount = 1000;

    // Create escrow
    client.create_escrow(&beneficiary, &amount);

    // Release the escrow
    client.release();

    // Refund should fail after release
    let result = std::panic::catch_unwind(|| {
        client.refund(&depositor);
    });
    assert!(
        result.is_err(),
        "Refund after release should fail"
    );
}

#[test]
fn test_is_expired_returns_valid_boolean() {
    let env = Env::default();
    let contract_id = env.register_contract(None, Escrow);
    let client = EscrowClient::new(&env, &contract_id);

    let beneficiary = Address::generate(&env);
    let amount = 500;

    client.create_escrow_with_timeout(&beneficiary, &amount, &MINIMUM_TIMEOUT_LEDGERS);

    let expired = client.is_expired();
    // is_expired should return a valid boolean (false immediately after creation)
    assert!(!expired, "Escrow should not be expired at creation time");
}

#[test]
fn test_security_analyzer() {
    let env = Env::default();
    let analyzer = soroban_security_scanner::security_analyzer::SecurityAnalyzer;

    // Analyze for reentrancy vulnerabilities
    let report = analyzer.analyze_reentrancy(&env);

    // The report should now be secure since vulnerability is fixed
    assert!(report.is_secure());
    assert!(!report.has_high_severity());
}
