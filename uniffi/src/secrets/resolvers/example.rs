use std::sync::Arc;

use async_trait::async_trait;
use didcomm_core::secrets::Secret;

use crate::{
    common::ErrorCode, secrets::FFISecretsResolver, OnFindSecretsResult, OnGetSecretResult,
};

/// Allows resolve pre-defined did's for `example` and other methods.
pub struct ExampleFFISecretsResolver {
    known_secrets: Vec<Secret>,
}

impl ExampleFFISecretsResolver {
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        ExampleFFISecretsResolver { known_secrets }
    }
}

#[async_trait]
impl FFISecretsResolver for ExampleFFISecretsResolver {
    fn get_secret(&self, secret_id: String, cb: Arc<OnGetSecretResult>) -> ErrorCode {
        let secret = self
            .known_secrets
            .iter()
            .find(|s| s.id == secret_id)
            .map(|s| s.clone());

        match cb.success(secret) {
            Ok(_) => ErrorCode::Success,
            Err(_) => ErrorCode::Error,
        }
    }

    fn find_secrets(&self, secret_ids: Vec<String>, cb: Arc<OnFindSecretsResult>) -> ErrorCode {
        let res = secret_ids
            .iter()
            .filter(|sid| self.known_secrets.iter().find(|s| s.id == **sid).is_some())
            .map(|sid| sid.clone())
            .collect();

        match cb.success(res) {
            Ok(_) => ErrorCode::Success,
            Err(_) => ErrorCode::Error,
        }
    }
}
