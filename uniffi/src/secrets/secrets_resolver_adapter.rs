use std::sync::Arc;

use async_trait::async_trait;
use didcomm_core::error::{ErrorKind, Result, ResultExt};
use didcomm_core::secrets::{Secret, SecretsResolver as _SecretsResolver};

use crate::secrets_resolver::{OnFindSecretsResult, OnGetSecretResult};

use super::SecretsResolver;

pub struct SecretsResolverAdapter {
    secrets_resolver: Arc<Box<dyn SecretsResolver>>,
}

impl SecretsResolverAdapter {
    pub fn new(secrets_resolver: Arc<Box<dyn SecretsResolver>>) -> Self {
        SecretsResolverAdapter { secrets_resolver }
    }
}

#[async_trait]
impl _SecretsResolver for SecretsResolverAdapter {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        let (cb, receiver) = OnGetSecretResult::new();

        self.secrets_resolver
            .get_secret(String::from(secret_id), cb);

        let res = OnGetSecretResult::get_result(receiver)
            .await
            .kind(ErrorKind::InvalidState, "can not get secret")?;
        Ok(res)
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        let (cb, receiver) = OnFindSecretsResult::new();

        self.secrets_resolver
            .find_secrets(secret_ids.iter().map(|&s| String::from(s)).collect(), cb);

        let res = OnFindSecretsResult::get_result(receiver)
            .await
            .kind(ErrorKind::InvalidState, "can not get secret")?;

        Ok(secret_ids
            .iter()
            .filter(|&&sid| res.iter().find(|&s| s == sid).is_some())
            .map(|sid| *sid)
            .collect())
    }
}
