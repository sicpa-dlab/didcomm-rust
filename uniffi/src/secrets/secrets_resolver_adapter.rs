use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use didcomm_core::error::{ErrorKind, Result, ResultExt};
use didcomm_core::secrets::{Secret, SecretsResolver};
use futures::channel::oneshot;

use crate::secrets_resolver::{OnFindSecretsResult, OnGetSecretResult};

use super::FFISecretsResolver;

pub struct FFISecretsResolverAdapter {
    secrets_resolver: Arc<Box<dyn FFISecretsResolver>>,
}

impl FFISecretsResolverAdapter {
    pub fn new(secrets_resolver: Arc<Box<dyn FFISecretsResolver>>) -> Self {
        FFISecretsResolverAdapter { secrets_resolver }
    }
}

#[async_trait]
impl SecretsResolver for FFISecretsResolverAdapter {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        let (sender, receiver) = oneshot::channel::<Result<Option<Secret>>>();

        let cb = Arc::new(OnGetSecretResult::new(Mutex::new(RefCell::new(Some(
            sender,
        )))));

        self.secrets_resolver
            .get_secret(String::from(secret_id), cb);

        let res = receiver
            .await
            .kind(ErrorKind::InvalidState, "can not get secret")?
            .kind(ErrorKind::InvalidState, "can not get secret")?;

        Ok(res)
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        let (sender, receiver) = oneshot::channel::<Result<Vec<String>>>();

        let cb = Arc::new(OnFindSecretsResult::new(Mutex::new(RefCell::new(Some(
            sender,
        )))));

        self.secrets_resolver
            .find_secrets(secret_ids.iter().map(|&s| String::from(s)).collect(), cb);

        let res = receiver
            .await
            .kind(ErrorKind::InvalidState, "can not get secret")?
            .kind(ErrorKind::InvalidState, "can not get secret")?;

        Ok(secret_ids
            .iter()
            .filter(|&&sid| res.iter().find(|&s| s == sid).is_some())
            .map(|sid| *sid)
            .collect())
    }
}
