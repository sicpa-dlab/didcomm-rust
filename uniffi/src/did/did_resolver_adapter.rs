use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

use didcomm::{
    did::{DIDDoc, DIDResolver},
    error::{err_msg, ErrorKind, Result, ResultExt, ResultExtNoContext},
};
use futures::channel::oneshot;

use crate::FFIDIDResolver;

use async_trait::async_trait;

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

        let cb = Arc::new(OnDIDResolverResult::new(Mutex::new(RefCell::new(Some(
            sender,
        )))));

        self.did_resolver.resolve(String::from(did), cb);

        let res = receiver
            .await
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?;

        Ok(res)
    }
}

pub struct OnDIDResolverResult {
    sender: Mutex<RefCell<Option<oneshot::Sender<Result<Option<DIDDoc>>>>>>,
}

impl OnDIDResolverResult {
    pub fn new(sender: Mutex<RefCell<Option<oneshot::Sender<Result<Option<DIDDoc>>>>>>) -> Self {
        OnDIDResolverResult { sender }
    }

    pub fn success(&self, result: Option<DIDDoc>) -> std::result::Result<(), ErrorKind> {
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
