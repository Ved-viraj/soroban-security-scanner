use soroban_sdk::{contract, contractclient, contractimpl, Address, Env, Symbol};

/// Minimum timeout for escrow in ledger closes (5 minutes at ~5s per ledger = 60 ledgers)
pub const MINIMUM_TIMEOUT_LEDGERS: u64 = 60;

/// Default timeout for escrow in ledger closes (1 hour = ~720 ledgers at 5s each)
pub const DEFAULT_TIMEOUT_LEDGERS: u64 = 720;

#[contract]
pub struct Escrow;

#[contractclient(name = "EscrowClient")]
pub trait EscrowTrait {
    fn create_escrow(env: Env, beneficiary: Address, amount: i128);
    fn create_escrow_with_timeout(
        env: Env,
        beneficiary: Address,
        amount: i128,
        timeout_ledgers: u64,
    );
    fn release(env: Env);
    fn refund(env: Env, depositor: Address);
    fn cancel(env: Env, depositor: Address);
    fn get_escrow_info(env: Env) -> EscrowData;
    fn is_expired(env: Env) -> bool;
}

#[derive(Clone)]
pub struct EscrowData {
    pub depositor: Address,
    pub beneficiary: Address,
    pub amount: i128,
    pub released: bool,
    pub cancelled: bool,
    pub refunded: bool,
    pub created_at: u64,
    pub timeout_ledgers: u64,
}

#[contractimpl]
impl Escrow {
    /// Create a new escrow with the specified beneficiary and amount.
    /// Uses the default timeout of 1 hour (720 ledger closes).
    pub fn create_escrow(env: Env, beneficiary: Address, amount: i128) {
        Self::create_escrow_with_timeout(env, beneficiary, amount, DEFAULT_TIMEOUT_LEDGERS);
    }

    /// Create a new escrow with a configurable timeout.
    /// The timeout must be at least MINIMUM_TIMEOUT_LEDGERS to prevent accidental
    /// zero-timeout escrows that could be exploited.
    pub fn create_escrow_with_timeout(
        env: Env,
        beneficiary: Address,
        amount: i128,
        timeout_ledgers: u64,
    ) {
        // Validate minimum timeout
        if timeout_ledgers < MINIMUM_TIMEOUT_LEDGERS {
            panic!(
                "Timeout must be at least {} ledgers",
                MINIMUM_TIMEOUT_LEDGERS
            );
        }

        let depositor = env.current_contract_address();
        let created_at = env.ledger().sequence();

        let escrow_data = EscrowData {
            depositor: depositor.clone(),
            beneficiary,
            amount,
            released: false,
            cancelled: false,
            refunded: false,
            created_at,
            timeout_ledgers,
        };

        // Store escrow data
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "escrow"), &escrow_data);

        // Transfer funds to contract
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "balance"), &amount);
    }

    /// SECURE: Release funds to beneficiary - updates state BEFORE external call
    pub fn release(env: Env) {
        let escrow_key = Symbol::new(&env, "escrow");
        let escrow_data: EscrowData = env
            .storage()
            .instance()
            .get(&escrow_key)
            .expect("Escrow not found");

        if escrow_data.released {
            panic!("Escrow already released");
        }

        if escrow_data.cancelled {
            panic!("Escrow has been cancelled");
        }

        if escrow_data.refunded {
            panic!("Escrow has been refunded");
        }

        let balance_key = Symbol::new(&env, "balance");
        let balance: i128 = env
            .storage()
            .instance()
            .get(&balance_key)
            .expect("No balance found");

        // SECURITY: Update state BEFORE external call to prevent reentrancy
        let mut updated_escrow = escrow_data.clone();
        updated_escrow.released = true;
        env.storage().instance().set(&escrow_key, &updated_escrow);

        // Clear balance immediately
        env.storage().instance().remove(&balance_key);

        // External calls AFTER state update - secure from reentrancy
        env.current_contract_address()
            .require_auth_for_args((&escrow_data.beneficiary, balance));

        // Transfer funds to beneficiary (external call simulation)
        self::transfer_funds(&env, &escrow_data.beneficiary, balance);
    }

    /// Refund the escrow to the depositor after the timeout has elapsed.
    /// Can only be called by the depositor and only after `timeout_ledgers`
    /// have passed since the escrow was created.
    ///
    /// # Security
    /// The `depositor` parameter must be authenticated via `require_auth()`.
    pub fn refund(env: Env, depositor: Address) {
        // Verify caller authorization
        depositor.require_auth();

        let escrow_key = Symbol::new(&env, "escrow");
        let escrow_data: EscrowData = env
            .storage()
            .instance()
            .get(&escrow_key)
            .expect("Escrow not found");

        if escrow_data.depositor != depositor {
            panic!("Only the depositor can request a refund");
        }

        if escrow_data.released {
            panic!("Escrow has already been released");
        }

        if escrow_data.cancelled {
            panic!("Escrow has been cancelled");
        }

        if escrow_data.refunded {
            panic!("Escrow has already been refunded");
        }

        // Check that the timeout has elapsed
        let current_ledger = env.ledger().sequence();
        let expires_at = escrow_data.created_at + escrow_data.timeout_ledgers;

        if current_ledger < expires_at {
            panic!(
                "Timeout has not elapsed. Expires at ledger {}, current ledger is {}",
                expires_at, current_ledger
            );
        }

        let balance_key = Symbol::new(&env, "balance");
        let balance: i128 = env
            .storage()
            .instance()
            .get(&balance_key)
            .expect("No balance found");

        // SECURITY: Update state BEFORE external call
        let mut updated_escrow = escrow_data.clone();
        updated_escrow.refunded = true;
        env.storage().instance().set(&escrow_key, &updated_escrow);

        // Clear balance immediately
        env.storage().instance().remove(&balance_key);

        // Emit refund event for audit trail
        env.storage().instance().set(
            &Symbol::new(&env, "EscrowRefunded"),
            &(
                escrow_data.depositor.clone(),
                escrow_data.beneficiary,
                balance,
                current_ledger,
            ),
        );

        // Transfer funds back to depositor
        self::transfer_funds(&env, &escrow_data.depositor, balance);
    }

    /// Cancel the escrow before it has been released.
    /// Can only be called by the depositor. Unlike `refund()`, this does not
    /// require the timeout to have elapsed. Once released, it cannot be cancelled.
    ///
    /// # Security
    /// The `depositor` parameter must be authenticated via `require_auth()`.
    pub fn cancel(env: Env, depositor: Address) {
        // Verify caller authorization
        depositor.require_auth();

        let escrow_key = Symbol::new(&env, "escrow");
        let escrow_data: EscrowData = env
            .storage()
            .instance()
            .get(&escrow_key)
            .expect("Escrow not found");

        if escrow_data.depositor != depositor {
            panic!("Only the depositor can cancel the escrow");
        }

        if escrow_data.released {
            panic!("Cannot cancel: escrow has already been released");
        }

        if escrow_data.cancelled {
            panic!("Escrow has already been cancelled");
        }

        if escrow_data.refunded {
            panic!("Escrow has already been refunded");
        }

        let balance_key = Symbol::new(&env, "balance");
        let balance: i128 = env
            .storage()
            .instance()
            .get(&balance_key)
            .expect("No balance found");

        // SECURITY: Update state BEFORE external call
        let mut updated_escrow = escrow_data.clone();
        updated_escrow.cancelled = true;
        env.storage().instance().set(&escrow_key, &updated_escrow);

        // Clear balance immediately
        env.storage().instance().remove(&balance_key);

        // Emit cancel event for audit trail
        let current_ledger = env.ledger().sequence();
        env.storage().instance().set(
            &Symbol::new(&env, "EscrowCancelled"),
            &(
                escrow_data.depositor.clone(),
                escrow_data.beneficiary,
                balance,
                current_ledger,
            ),
        );

        // Transfer funds back to depositor
        self::transfer_funds(&env, &escrow_data.depositor, balance);
    }

    /// Check if the escrow has passed its timeout
    pub fn is_expired(env: Env) -> bool {
        let escrow_key = Symbol::new(&env, "escrow");
        let escrow_data: EscrowData = env
            .storage()
            .instance()
            .get(&escrow_key)
            .expect("Escrow not found");

        let current_ledger = env.ledger().sequence();
        let expires_at = escrow_data.created_at + escrow_data.timeout_ledgers;

        current_ledger >= expires_at
    }

    /// Helper function to simulate external fund transfer
    fn transfer_funds(env: &Env, recipient: &Address, amount: i128) {
        // In a real implementation, this would call a token contract
        // For demonstration, we'll just log the transfer
        env.storage().instance().set(
            &Symbol::new(env, "last_transfer"),
            &(recipient.clone(), amount),
        );
    }

    /// Get escrow information
    pub fn get_escrow_info(env: Env) -> EscrowData {
        let escrow_key = Symbol::new(&env, "escrow");
        env.storage()
            .instance()
            .get(&escrow_key)
            .expect("Escrow not found")
    }
}
