use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use didcomm::error::{err_msg, ErrorKind, Result, ResultExt, ResultExtNoContext};
use didcomm::secrets::{Secret, SecretsResolver};
use futures::channel::oneshot;

use lazy_static::lazy_static;

use crate::common::get_next_id;

use super::FFISecretsResolver;

lazy_static! {
    static ref CALLBACK_SENDERS_GET_SECRETS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<Option<Secret>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref CALLBACK_SENDERS_FIND_SECRETS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<Vec<String>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

pub struct FFISecretsResolverAdapter {
    secrets_resolver: Box<dyn FFISecretsResolver>,
}

impl FFISecretsResolverAdapter {
    pub fn new(secrets_resolver: Box<dyn FFISecretsResolver>) -> Self {
        FFISecretsResolverAdapter { secrets_resolver }
    }
}

#[async_trait]
impl SecretsResolver for FFISecretsResolverAdapter {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        let (sender, receiver) = oneshot::channel::<Result<Option<Secret>>>();

        let cb_id = get_next_id();
        CALLBACK_SENDERS_GET_SECRETS
            .lock()
            .kind_no_context(ErrorKind::InvalidState, "can not get secret")?
            .insert(cb_id, sender);
        let cb = Arc::new(OnGetSecretResult { cb_id: cb_id });

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

        let cb_id = get_next_id();
        CALLBACK_SENDERS_FIND_SECRETS
            .lock()
            .kind_no_context(ErrorKind::InvalidState, "can not get secret")?
            .insert(cb_id, sender);
        let cb = Arc::new(OnFindSecretsResult { cb_id: cb_id });

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

pub struct OnGetSecretResult {
    pub cb_id: i32,
}

impl OnGetSecretResult {
    pub fn new(cb_id: i32) -> Self {
        OnGetSecretResult { cb_id }
    }

    pub fn success(&self, result: Option<Secret>) -> std::result::Result<(), ErrorKind> {
        let sender = CALLBACK_SENDERS_GET_SECRETS
            .lock()
            .to_error_kind(ErrorKind::InvalidState)?
            .remove(&self.cb_id);
        match sender {
            Some(sender) => sender
                .send(Ok(result))
                .to_error_kind(ErrorKind::InvalidState)?,
            None => Err(ErrorKind::InvalidState)?,
        };
        Ok(())
    }

    pub fn error(&self, err: ErrorKind, msg: String) -> std::result::Result<(), ErrorKind> {
        let sender = CALLBACK_SENDERS_GET_SECRETS
            .lock()
            .to_error_kind(ErrorKind::InvalidState)?
            .remove(&self.cb_id);
        match sender {
            Some(sender) => sender
                .send(Err(err_msg(err, msg)))
                .to_error_kind(ErrorKind::InvalidState)?,
            None => Err(ErrorKind::InvalidState)?,
        };
        Ok(())
    }
}

pub struct OnFindSecretsResult {
    pub cb_id: i32,
}

impl OnFindSecretsResult {
    pub fn new(cb_id: i32) -> Self {
        OnFindSecretsResult { cb_id }
    }

    pub fn success(&self, result: Vec<String>) -> std::result::Result<(), ErrorKind> {
        let sender = CALLBACK_SENDERS_FIND_SECRETS
            .lock()
            .to_error_kind(ErrorKind::InvalidState)?
            .remove(&self.cb_id);
        match sender {
            Some(sender) => sender
                .send(Ok(result))
                .to_error_kind(ErrorKind::InvalidState)?,
            None => Err(ErrorKind::InvalidState)?,
        };
        Ok(())
    }

    pub fn error(&self, err: ErrorKind, msg: String) -> std::result::Result<(), ErrorKind> {
        let sender = CALLBACK_SENDERS_FIND_SECRETS
            .lock()
            .to_error_kind(ErrorKind::InvalidState)?
            .remove(&self.cb_id);
        match sender {
            Some(sender) => sender
                .send(Err(err_msg(err, msg)))
                .to_error_kind(ErrorKind::InvalidState)?,
            None => Err(ErrorKind::InvalidState)?,
        };
        Ok(())
    }
}
