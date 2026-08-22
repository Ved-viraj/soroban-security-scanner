//! Token Revocation List for JWT force-invalidation
//!
//! When a user changes their password or an account compromise is detected,
//! all existing JWTs issued to that user must be invalidated immediately.
//! Since JWTs are stateless (validated by signature, not server-side lookup),
//! we maintain a revocation list of JWT IDs (jti claims) that should be
//! rejected even if their signature is valid and they haven't expired yet.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("Token is revoked: {0}")]
    Revoked(String),
    #[error("Storage error: {0}")]
    Storage(String),
}

/// A revoked JWT token entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedToken {
    /// The JWT ID (jti claim) of the revoked token
    pub jti: String,
    /// The user ID who owned this token
    pub user_id: String,
    /// When the token was revoked
    pub revoked_at: DateTime<Utc>,
    /// When the original token expires (for cleanup)
    pub original_expiry: DateTime<Utc>,
}

/// Index of the tokens we've seen for each user: `user_id -> (jti -> original expiry)`.
/// Kept separate from the revoked set so `revoke_all_user_tokens` can enumerate a
/// user's active tokens and the expiry is available for pruning.
type UserTokenIndex = HashMap<String, HashMap<String, DateTime<Utc>>>;

/// Token Revocation List — stores revoked JWT IDs
///
/// This implementation uses an in-memory store with RwLock for thread safety.
/// In production, this should be backed by Redis or a database for persistence
/// across server restarts and multi-instance deployments.
pub struct TokenRevocationList {
    /// Map of jti -> RevokedToken
    revoked_tokens: Arc<RwLock<HashMap<String, RevokedToken>>>,
    /// Map of user_id -> (jti -> original expiry) for every token we've seen
    /// issued to the user. This is what lets `revoke_all_user_tokens` find the
    /// user's *active* tokens; without it there is nothing to revoke in bulk.
    user_tokens: Arc<RwLock<UserTokenIndex>>,
}

impl TokenRevocationList {
    /// Create a new empty TokenRevocationList
    pub fn new() -> Self {
        Self {
            revoked_tokens: Arc::new(RwLock::new(HashMap::new())),
            user_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a token that has just been issued to a user.
    ///
    /// The revocation list is a deny-list, so it can only force-invalidate a
    /// token whose jti it knows about. Callers (e.g. `JwtService::generate_token`)
    /// register every issued token here so that a later `revoke_all_user_tokens`
    /// can actually reach the tokens that are still active. This does *not*
    /// revoke the token — it only remembers that it exists.
    pub fn track_issued_token(&self, jti: &str, user_id: &str, original_expiry: DateTime<Utc>) {
        self.user_tokens
            .write()
            .unwrap()
            .entry(user_id.to_string())
            .or_default()
            .insert(jti.to_string(), original_expiry);
    }

    /// Revoke a single token by its jti
    pub fn revoke_token(&self, jti: &str, user_id: &str, original_expiry: DateTime<Utc>) {
        let revoked = RevokedToken {
            jti: jti.to_string(),
            user_id: user_id.to_string(),
            revoked_at: Utc::now(),
            original_expiry,
        };

        self.revoked_tokens
            .write()
            .unwrap()
            .insert(jti.to_string(), revoked);

        self.user_tokens
            .write()
            .unwrap()
            .entry(user_id.to_string())
            .or_default()
            .insert(jti.to_string(), original_expiry);
    }

    /// Revoke ALL tokens for a specific user
    ///
    /// This is called when a user changes their password or when an account
    /// compromise is detected. Every token we've tracked for the user is added
    /// to the revoked set so it is rejected by `validate_token` from now on,
    /// even though its signature is still cryptographically valid.
    ///
    /// The operation is idempotent: tokens that are already revoked are left in
    /// place, and the user's token index is preserved so tokens issued after the
    /// revocation are still tracked. Entries are cleaned up by `prune_expired`
    /// once the underlying tokens pass their natural expiry.
    pub fn revoke_all_user_tokens(&self, user_id: &str) -> Result<usize, RevocationError> {
        let tokens = self
            .user_tokens
            .read()
            .unwrap()
            .get(user_id)
            .cloned()
            .unwrap_or_default();

        let now = Utc::now();
        let mut revoked = self.revoked_tokens.write().unwrap();
        for (jti, original_expiry) in &tokens {
            revoked.entry(jti.clone()).or_insert_with(|| RevokedToken {
                jti: jti.clone(),
                user_id: user_id.to_string(),
                revoked_at: now,
                original_expiry: *original_expiry,
            });
        }

        Ok(tokens.len())
    }

    /// Check if a token is revoked by its jti
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked_tokens.read().unwrap().contains_key(jti)
    }

    /// Prune expired entries from the revocation list
    ///
    /// Entries whose original token has expired (past its `exp` claim) are
    /// safe to remove — the token would be rejected by normal expiry validation
    /// anyway. This should be called periodically by a background job. Expired
    /// jtis are dropped from both the revoked set and the per-user index so
    /// neither map grows without bound.
    ///
    /// Returns the number of revoked entries removed.
    pub fn prune_expired(&self) -> usize {
        let now = Utc::now();
        let mut revoked = self.revoked_tokens.write().unwrap();
        let mut user_tokens = self.user_tokens.write().unwrap();

        let to_remove: Vec<String> = revoked
            .iter()
            .filter(|(_, token)| token.original_expiry < now)
            .map(|(jti, _)| jti.clone())
            .collect();

        let count = to_remove.len();
        for jti in &to_remove {
            revoked.remove(jti);
        }

        // Drop expired jtis from the per-user index and remove users left empty.
        user_tokens.retain(|_, jtis| {
            jtis.retain(|_, expiry| *expiry >= now);
            !jtis.is_empty()
        });

        count
    }

    /// Get the count of revoked tokens
    pub fn count(&self) -> usize {
        self.revoked_tokens.read().unwrap().len()
    }

    /// Get all revoked tokens for a user (for debugging/admin)
    pub fn get_user_revoked_tokens(&self, user_id: &str) -> Vec<RevokedToken> {
        let user_tokens = self.user_tokens.read().unwrap();
        let jtis: Vec<String> = user_tokens
            .get(user_id)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        drop(user_tokens);

        let revoked = self.revoked_tokens.read().unwrap();
        jtis.iter()
            .filter_map(|jti| revoked.get(jti).cloned())
            .collect()
    }
}

impl Default for TokenRevocationList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use uuid::Uuid;

    #[test]
    fn test_revoke_single_token() {
        let list = TokenRevocationList::new();
        let jti = Uuid::new_v4().to_string();
        let expiry = Utc::now() + Duration::hours(1);

        list.revoke_token(&jti, "user123", expiry);
        assert!(list.is_revoked(&jti));
        assert_eq!(list.count(), 1);
    }

    #[test]
    fn test_revoke_all_user_tokens() {
        let list = TokenRevocationList::new();
        let expiry = Utc::now() + Duration::hours(1);

        // Revoke 3 tokens for user1
        for _ in 0..3 {
            let jti = Uuid::new_v4().to_string();
            list.revoke_token(&jti, "user1", expiry);
        }
        // Revoke 1 token for user2
        list.revoke_token(&Uuid::new_v4().to_string(), "user2", expiry);

        assert_eq!(list.count(), 4);

        // Bulk-revoking user1 reports the 3 tokens it acted on. It is
        // non-destructive: already-revoked tokens stay revoked and user2 is
        // untouched, so the total revoked count is unchanged.
        let revoked = list.revoke_all_user_tokens("user1").unwrap();
        assert_eq!(revoked, 3);
        assert_eq!(list.count(), 4);
    }

    #[test]
    fn test_revoke_all_revokes_active_issued_tokens() {
        let list = TokenRevocationList::new();
        let expiry = Utc::now() + Duration::hours(1);

        // Three active tokens issued to the user, none revoked yet.
        let jtis: Vec<String> = (0..3).map(|_| Uuid::new_v4().to_string()).collect();
        for jti in &jtis {
            list.track_issued_token(jti, "user1", expiry);
            assert!(!list.is_revoked(jti));
        }
        assert_eq!(list.count(), 0);

        // Password change / compromise -> every active token is now revoked.
        let revoked = list.revoke_all_user_tokens("user1").unwrap();
        assert_eq!(revoked, 3);
        for jti in &jtis {
            assert!(list.is_revoked(jti));
        }
        assert_eq!(list.count(), 3);
    }

    #[test]
    fn test_prune_expired() {
        let list = TokenRevocationList::new();
        let past_expiry = Utc::now() - Duration::hours(1);
        let future_expiry = Utc::now() + Duration::hours(1);

        list.revoke_token(&Uuid::new_v4().to_string(), "user1", past_expiry);
        list.revoke_token(&Uuid::new_v4().to_string(), "user1", future_expiry);

        assert_eq!(list.count(), 2);
        let pruned = list.prune_expired();
        assert_eq!(pruned, 1);
        assert_eq!(list.count(), 1);
    }

    #[test]
    fn test_is_not_revoked() {
        let list = TokenRevocationList::new();
        assert!(!list.is_revoked("nonexistent-jti"));
    }

    #[test]
    fn test_password_change_scenario() {
        let list = TokenRevocationList::new();
        let expiry = Utc::now() + Duration::hours(24);

        // User logs in on 3 devices — each issued token is tracked.
        let jti1 = Uuid::new_v4().to_string();
        let jti2 = Uuid::new_v4().to_string();
        let jti3 = Uuid::new_v4().to_string();
        list.track_issued_token(&jti1, "user1", expiry);
        list.track_issued_token(&jti2, "user1", expiry);
        list.track_issued_token(&jti3, "user1", expiry);

        // Nothing is revoked while the tokens are in normal use.
        assert!(!list.is_revoked(&jti1));
        assert!(!list.is_revoked(&jti2));
        assert!(!list.is_revoked(&jti3));

        // User changes password — all tokens revoked
        let count = list.revoke_all_user_tokens("user1").unwrap();
        assert_eq!(count, 3);

        // All 3 tokens are now rejected
        assert!(list.is_revoked(&jti1));
        assert!(list.is_revoked(&jti2));
        assert!(list.is_revoked(&jti3));
    }
}
