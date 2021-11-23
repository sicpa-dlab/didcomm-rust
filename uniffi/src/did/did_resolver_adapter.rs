use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use didcomm::{
    did::{DIDDoc, DIDResolver},
    error::{err_msg, ErrorKind, Result, ResultExt, ResultExtNoContext},
};
use futures::channel::oneshot;

use crate::FFIDIDResolver;

use async_trait::async_trait;
use lazy_static::lazy_static;

use crate::common::get_next_id;

lazy_static! {
    static ref CALLBACK_SENDERS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<Option<DIDDoc>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

pub(crate) struct FFIDIDResolverAdapter {
    did_resolver: Box<dyn FFIDIDResolver>,
}

impl FFIDIDResolverAdapter {
    pub fn new(did_resolver: Box<dyn FFIDIDResolver>) -> Self {
        FFIDIDResolverAdapter { did_resolver }
    }
}

#[async_trait]
impl DIDResolver for FFIDIDResolverAdapter {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        let (sender, receiver) = oneshot::channel::<Result<Option<DIDDoc>>>();

        let cb_id = get_next_id();
        CALLBACK_SENDERS
            .lock()
            .kind_no_context(ErrorKind::InvalidState, "can not resolve DID Doc")?
            .insert(cb_id, sender);
        let cb = Arc::new(OnDIDResolverResult { cb_id: cb_id });

        self.did_resolver.resolve(String::from(did), cb);

        let res = receiver
            .await
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?;

        Ok(res)
    }
}

pub struct OnDIDResolverResult {
    pub cb_id: i32,
}

impl OnDIDResolverResult {
    pub fn new(cb_id: i32) -> Self {
        OnDIDResolverResult { cb_id }
    }

    pub fn success(&self, result: Option<DIDDoc>) -> std::result::Result<(), ErrorKind> {
        let sender = CALLBACK_SENDERS
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
        let sender = CALLBACK_SENDERS
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