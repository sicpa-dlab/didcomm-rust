use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use didcomm::error::{err_msg, ErrorKind, Result, ResultExt, ToResult};
use didcomm::secrets::{Secret, SecretsResolver};
use futures::channel::oneshot;

use lazy_static::lazy_static;

use crate::common::get_next_id;

use super::secrets_resolver::{OnFindSecretsResult, OnGetSecretResult};
use super::FFISecretsResolver;

pub struct FFISecretsResolverAdapter {
    secrets_resolver: Box<dyn FFISecretsResolver>,
}

impl FFISecretsResolverAdapter {
    pub fn new(secrets_resolver: Box<dyn FFISecretsResolver>) -> Self {
        FFISecretsResolverAdapter { secrets_resolver }
    }
}

lazy_static! {
    static ref CALLBACK_SENDERS_GET_SECRETS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<Option<String>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref CALLBACK_SENDERS_FIND_SECRETS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<Vec<String>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[async_trait]
impl SecretsResolver for FFISecretsResolverAdapter {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        let (sender, receiver) = oneshot::channel::<Result<Option<String>>>();

        let cb_id = get_next_id();
        CALLBACK_SENDERS_GET_SECRETS
            .lock()
            .unwrap()
            .insert(cb_id, sender);
        let cb = Box::new(OnGetSecretResultAdapter { cb_id: cb_id });

        self.secrets_resolver
            .get_secret(String::from(secret_id), cb);

        let res = receiver
            .await
            .kind(ErrorKind::InvalidState, "can not get secret")?
            .kind(ErrorKind::InvalidState, "can not get secret")?;

        match res {
            Some(res) => serde_json::from_str(&res).to_didcomm("can not get secret"),
            None => Ok(None),
        }
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        let (sender, receiver) = oneshot::channel::<Result<Vec<String>>>();

        let cb_id = get_next_id();
        CALLBACK_SENDERS_FIND_SECRETS
            .lock()
            .unwrap()
            .insert(cb_id, sender);
        let cb = Box::new(OnFindSecretsResultAdapter { cb_id: cb_id });

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

pub struct OnGetSecretResultAdapter {
    pub cb_id: i32,
}

impl OnGetSecretResult for OnGetSecretResultAdapter {
    fn success(&self, result: Option<String>) {
        CALLBACK_SENDERS_GET_SECRETS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Ok(result))
            .unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_SENDERS_GET_SECRETS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Err(err_msg(err, msg)))
            .unwrap();
    }
}

pub struct OnFindSecretsResultAdapter {
    pub cb_id: i32,
}

impl OnFindSecretsResult for OnFindSecretsResultAdapter {
    fn success(&self, result: Vec<String>) {
        CALLBACK_SENDERS_FIND_SECRETS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Ok(result))
            .unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_SENDERS_FIND_SECRETS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Err(err_msg(err, msg)))
            .unwrap();
    }
}
