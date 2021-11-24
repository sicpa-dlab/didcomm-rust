use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use didcomm::error::{err_msg, ErrorKind, Result, ResultExt, ResultExtNoContext};
use didcomm::secrets::{Secret, SecretsResolver};
use futures::channel::oneshot;

use super::FFISecretsResolver;

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

pub struct OnGetSecretResult {
    sender: Mutex<RefCell<Option<oneshot::Sender<Result<Option<Secret>>>>>>,
}

impl OnGetSecretResult {
    pub fn new(sender: Mutex<RefCell<Option<oneshot::Sender<Result<Option<Secret>>>>>>) -> Self {
        OnGetSecretResult { sender }
    }

    pub fn success(&self, result: Option<Secret>) -> std::result::Result<(), ErrorKind> {
        let sender = self
            .sender
            .lock()
            .to_error_kind(ErrorKind::InvalidState)?
            .replace(None);
        match sender {
            Some(sender) => sender
                .send(Ok(result))
                .to_error_kind(ErrorKind::InvalidState)?,
            None => Err(ErrorKind::InvalidState)?,
        };
        Ok(())
    }

    pub fn error(&self, err: ErrorKind, msg: String) -> std::result::Result<(), ErrorKind> {
        let sender = self
            .sender
            .lock()
            .to_error_kind(ErrorKind::InvalidState)?
            .replace(None);
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
    sender: Mutex<RefCell<Option<oneshot::Sender<Result<Vec<String>>>>>>,
}

impl OnFindSecretsResult {
    pub fn new(sender: Mutex<RefCell<Option<oneshot::Sender<Result<Vec<String>>>>>>) -> Self {
        OnFindSecretsResult { sender }
    }

    pub fn success(&self, result: Vec<String>) -> std::result::Result<(), ErrorKind> {
        let sender = self
            .sender
            .lock()
            .to_error_kind(ErrorKind::InvalidState)?
            .replace(None);
        match sender {
            Some(sender) => sender
                .send(Ok(result))
                .to_error_kind(ErrorKind::InvalidState)?,
            None => Err(ErrorKind::InvalidState)?,
        };
        Ok(())
    }

    pub fn error(&self, err: ErrorKind, msg: String) -> std::result::Result<(), ErrorKind> {
        let sender = self
            .sender
            .lock()
            .to_error_kind(ErrorKind::InvalidState)?
            .replace(None);
        match sender {
            Some(sender) => sender
                .send(Err(err_msg(err, msg)))
                .to_error_kind(ErrorKind::InvalidState)?,
            None => Err(ErrorKind::InvalidState)?,
        };
        Ok(())
    }
}
