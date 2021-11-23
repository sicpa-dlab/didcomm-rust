use std::sync::Arc;

use crate::{
    common::ErrorCode,
    secrets_resolver_adapter::{OnFindSecretsResult, OnGetSecretResult},
};

/// Interface for secrets resolver.
/// Resolves secrets such as private keys to be used for signing and encryption.
pub trait FFISecretsResolver: Sync + Send {
    /// Finds secret (usually private key) identified by the given key ID.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    /// - `cb` a callback with a result
    ///
    /// # Returns
    /// A secret (usually private key) or None of there is no secret for the given ID
    ///
    fn get_secret(&self, secret_id: String, cb: Arc<OnGetSecretResult>) -> ErrorCode;

    /// Find all secrets that have one of the given IDs.
    /// Return secrets only for key IDs for which a secret is present.
    ///
    /// # Parameters
    /// - `secret_ids` the IDs find secrets for
    /// - `cb` a callback with a result
    ///
    /// # Returns
    /// A secret (usually private key) or None of there is no secret for the given ID
    ///
    fn find_secrets(&self, secret_ids: Vec<String>, cb: Arc<OnFindSecretsResult>) -> ErrorCode;
}
