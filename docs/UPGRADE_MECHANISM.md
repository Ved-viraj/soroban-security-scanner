# Contract Upgrade Mechanism Documentation

## Overview

The Soroban Security Scanner contract includes a comprehensive upgrade mechanism that allows for secure contract upgrades while maintaining state integrity and providing governance controls.

## Features

### 1. Version Control
- Contract version tracking
- Upgrade history logging
- Migration status monitoring

### 2. Security Controls
- Admin authorization checks
- Upgrade authority management
- Timelock delays for non-emergency upgrades
- Emergency upgrade capability for critical security patches

### 3. Governance
- Multi-signature upgrade proposals
- Configurable signature requirements
- Proposal lifecycle management

### 4. State Migration
- Automatic state snapshot creation
- Migration status tracking
- Rollback capabilities

## Architecture

### Storage Keys

```rust
const CONTRACT_VERSION: Symbol = Symbol::short("VERSION");
const UPGRADE_AUTHORITY: Symbol = Symbol::short("UPGRADE");
const UPGRADE_DELAY: Symbol = Symbol::short("UP_DELAY");
const PENDING_UPGRADE: Symbol = Symbol::short("PENDING");
const UPGRADE_HISTORY: Symbol = Symbol::short("UP_HISTORY");
```

### Data Structures

#### UpgradeRequest
```rust
pub struct UpgradeRequest {
    pub new_contract_address: Address,
    pub proposed_by: Address,
    pub timestamp: u64,
    pub ready_at: u64,
    pub reason: String,
    pub version: String,
}
```

#### UpgradeHistory
```rust
pub struct UpgradeHistory {
    pub from_version: String,
    pub to_version: String,
    pub timestamp: u64,
    pub upgraded_by: Address,
    pub old_contract: Address,
    pub new_contract: Address,
}
```

#### GovernanceUpgradeProposal
```rust
pub struct GovernanceUpgradeProposal {
    pub proposal_id: u64,
    pub new_contract_address: Address,
    pub proposed_by: Address,
    pub timestamp: u64,
    pub ready_at: u64,
    pub reason: String,
    pub version: String,
    pub required_signatures: u32,
    pub collected_signatures: Vec<Address>,
    pub status: String,
}
```

## Upgrade Process

### Standard Upgrade Flow

1. **Proposal Phase**
   - Upgrade authority proposes new contract
   - Sets timelock delay (default: 7 days)
   - Reason and version information recorded

2. **Waiting Period**
   - Timelock delay must pass
   - Community review and audit period
   - Opportunity for objections

3. **Execution Phase**
   - Upgrade authority executes upgrade
   - State migration occurs
   - History is updated
   - Old contract remains for reference

### Emergency Upgrade Flow

1. **Immediate Proposal**
   - Admin proposes emergency upgrade
   - No timelock delay
   - "EMERGENCY" prefix added to reason

2. **Immediate Execution**
   - Upgrade executed immediately
   - State migration occurs
   - Full audit trail maintained

### Governance Upgrade Flow

1. **Multi-Sig Proposal**
   - Upgrade authority creates proposal
   - Sets required signature threshold
   - Proposal ID generated

2. **Signature Collection**
   - Authorized signers review and sign
   - Signatures tracked in proposal
   - Progress visible to all

3. **Execution**
   - After sufficient signatures and delay
   - Upgrade authority executes
   - Multi-sig verification completed

## Security Features

### Access Controls

- **Admin**: Can initialize contract, set upgrade authority, perform emergency upgrades
- **Upgrade Authority**: Can propose and execute standard upgrades
- **Signers**: Can participate in governance upgrades

### Timelock Protection

- Default delay: 7 days (604,800 seconds)
- Minimum delay: 24 hours (86,400 seconds)
- Configurable by admin
- Bypassed for emergency upgrades

### State Integrity

- Complete state snapshot before migration
- Migration status tracking
- Verification of successful migration
- Rollback capability if migration fails

## API Reference

### Core Functions

#### `get_version(env: Env) -> String`
Returns current contract version.

#### `propose_upgrade(env, proposer, new_contract, new_version, reason) -> Result<(), ContractError>`
Proposes a standard upgrade with timelock delay.

#### `execute_upgrade(env, executor) -> Result<(), ContractError>`
Executes a pending upgrade after delay period.

#### `emergency_upgrade(env, admin, new_contract, new_version, reason) -> Result<(), ContractError>`
Executes immediate emergency upgrade.

#### `cancel_upgrade(env, canceler) -> Result<(), ContractError>`
Cancels a pending upgrade proposal.

### Governance Functions

#### `create_upgrade_proposal(env, proposer, new_contract, new_version, reason, required_signatures) -> Result<u64, ContractError>`
Creates multi-signature upgrade proposal.

#### `sign_upgrade_proposal(env, signer, proposal_id) -> Result<(), ContractError>`
Adds signature to governance proposal.

#### `execute_governance_upgrade(env, executor, proposal_id) -> Result<(), ContractError>`
Executes governance upgrade after sufficient signatures.

### Configuration Functions

#### `set_upgrade_authority(env, admin, new_authority) -> Result<(), ContractError>`
Sets the upgrade authority address.

#### `set_upgrade_delay(env, admin, delay_seconds) -> Result<(), ContractError>`
Configures timelock delay period.

### Query Functions

#### `get_pending_upgrade(env: Env) -> Result<UpgradeRequest, ContractError>`
Returns pending upgrade information.

#### `get_upgrade_history(env: Env) -> Vec<UpgradeHistory>`
Returns complete upgrade history.

#### `get_migration_status(env: Env) -> Option<(Address, u64)>`
Returns migration status and timestamp.

## Error Codes

| Error | Description |
|-------|-------------|
| Unauthorized | Caller lacks required permissions |
| UpgradeInProgress | Another upgrade is already pending |
| UpgradeNotReady | Timelock delay has not passed |
| InvalidUpgrade | Upgrade parameters invalid |
| NotFound | Upgrade proposal not found |

## Best Practices

### Upgrade Planning

1. **Thorough Testing**: Test new contract extensively
2. **Security Audit**: Conduct professional security audit
3. **Community Review**: Allow community review period
4. **Backup Plan**: Prepare rollback procedures

### Emergency Procedures

1. **Severity Assessment**: Confirm emergency severity
2. **Stakeholder Notification**: Inform all stakeholders
3. **Documentation**: Document emergency reasoning
4. **Post-Mortem**: Conduct post-upgrade analysis

### Governance Setup

1. **Diverse Signers**: Include multiple trusted parties
2. **Clear Thresholds**: Set appropriate signature requirements
3. **Regular Reviews**: Periodically review governance setup
4. **Succession Planning**: Plan for signer changes

## Migration Process

### State Snapshot

The contract creates a comprehensive snapshot including:
- Admin address
- Contract version
- Bounty pools
- Supported tokens
- Emergency reward configuration
- Upgrade authority and delay
- Complete upgrade history

### Migration Steps

1. **Snapshot Creation**: Capture current state
2. **New Contract Deployment**: Deploy upgraded contract
3. **State Transfer**: Migrate snapshot to new contract
4. **Verification**: Confirm successful migration
5. **Cleanup**: Remove temporary migration data

### Verification

- Compare state before and after migration
- Verify all critical data integrity
- Test new contract functionality
- Confirm upgrade history accuracy

## Testing

The upgrade mechanism includes comprehensive test coverage:

- Standard upgrade flow
- Emergency upgrade procedures
- Governance upgrade process
- Access control validation
- Error condition handling
- State migration verification

Run tests with:
```bash
cargo test --package soroban-security-scanner-contracts
```

## Security Considerations

### Attack Vectors Mitigated

1. **Unauthorized Upgrades**: Strict access controls
2. **Rushed Upgrades**: Timelock delays
3. **State Loss**: Comprehensive migration
4. **Hidden Changes**: Transparent history
5. **Single Point Failure**: Multi-signature governance

### Ongoing Security

- Regular security audits
- Monitoring upgrade patterns
- Reviewing authority assignments
- Updating governance procedures

## Future Enhancements

Planned improvements to the upgrade mechanism:

1. **Automated Auditing**: Integration with external audit tools
2. **Cross-Chain Upgrades**: Support for multi-chain deployments
3. **Upgrade Templates**: Reusable upgrade patterns
4. **Enhanced Governance**: More sophisticated voting mechanisms
5. **Migration Optimization**: More efficient state transfer methods

---

# Incremental Scanning

## Overview

The Soroban Security Scanner supports incremental scanning, which only re-scans files that have changed since the last scan. This significantly reduces scan time for large projects during development and CI/CD pipelines.

## How It Works

### Scan Manifest

The scanner maintains a `ScanManifest` stored in `.stellar-scanner/manifest.json`. This manifest records:

- **File path**: Relative path from the project root
- **SHA-256 hash**: Cryptographic hash of file contents for change detection
- **Last scan timestamp**: When the file was last scanned
- **Dependencies**: Modules imported by the file (for dependency-aware rescanning)

```json
{
  "version": 1,
  "last_scan_timestamp": 1721234567,
  "total_files": 50,
  "files": {
    "src/config.rs": {
      "hash": "abc123def456...",
      "dependencies": ["crate::analysis::AnalysisResult"],
      "last_scan_timestamp": 1721234567
    }
  }
}
```

### Dependency Graph

When a file changes, the scanner:
1. Identifies directly changed files via hash comparison
2. Builds an import dependency graph from the manifest
3. Transitively traces all files that depend (directly or indirectly) on changed files
4. Scans only the affected subset

For example, if `src/config.rs` changes:
- `src/scanners.rs` (imports config) → re-scanned
- `src/main.rs` (imports scanners) → re-scanned (transitive dependency)

### Scan Time Savings

For a typical project with 50+ contracts, incremental scanning reduces median scan time by **80-95%** for typical pull requests that only touch a few files.

## CLI Usage

### Enable Incremental Scanning

```bash
# First scan creates the manifest
stellar-scanner scan --incremental

# Subsequent scans only check changed files
stellar-scanner scan --incremental
```

### Force Full Scan

When you want to override incremental mode (e.g., after dependency updates):

```bash
stellar-scanner scan --incremental --force-full
```

This deletes the existing manifest and performs a complete re-scan, creating a fresh manifest.

### Scan Time Reporting

After an incremental scan, the CLI reports time savings:

```
Scanned 3/50 files (incremental) in 12.4s — full scan would have taken ~180s
```

### Available Flags

| Flag | Description |
|------|-------------|
| `--incremental` | Enable incremental scanning mode |
| `--force-full` | Override incremental mode and force a full scan |

Both flags are available on the `scan`, `security`, and `invariants` subcommands.

## Storage

The scan manifest is stored in the project's `.stellar-scanner/` directory (similar to `.git`). The directory is created automatically on first use.

**Note:** Add `.stellar-scanner/` to your `.gitignore` to avoid committing scan state.

## Manifest Versioning

The manifest includes a `version` field (currently `1`) for forward/backward compatibility. Future versions may add new fields without breaking existing manifests.

## Testing

Incremental scanning includes comprehensive test coverage:

- Scan a 3-file project, change 1 file, verify only changed files + dependents are re-scanned
- Verify unchanged files are skipped
- Verify `--force-full` scans all files regardless of changes
- Transitive dependency resolution (A → B → C, change A → scan A, B, C)
- Manifest save/load round-trip
- File hash computation
- Dependency extraction from Rust source

Run tests with:
```bash
cargo test incremental_scan
```
