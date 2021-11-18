use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use didcomm::did::{DIDDoc, DIDResolver};
use didcomm::error::{ErrorKind, Result, ResultExt, ToResult, err_msg};
use futures::channel::oneshot;

use lazy_static::lazy_static;

use crate::common::get_next_id;

use super::FFIDIDResolver;
use super::did_resolver::OnDIDResolverResult;

pub struct FFIDIDResolverAdapter {
    did_resolver: Box<dyn FFIDIDResolver>
}

impl FFIDIDResolverAdapter {
    pub fn new(did_resolver: Box<dyn FFIDIDResolver>) -> Self {
        FFIDIDResolverAdapter { did_resolver }
    }
}


lazy_static! {
    static ref CALLBACK_SENDERS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<Option<String>>>>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[async_trait]
impl DIDResolver for FFIDIDResolverAdapter{

    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        let (sender, receiver) = oneshot::channel::<Result<Option<String>>>();

        let cb_id = get_next_id();
        CALLBACK_SENDERS.lock().unwrap().insert(cb_id, sender);
        let cb = Box::new(OnDIDResolverResultAdapter{cb_id: cb_id});

        self.did_resolver.resolve(String::from(did), cb);
        
        let res = receiver.await
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?
            .kind(ErrorKind::InvalidState, "can not resolve DID Doc")?;

        match res {
            Some(res) => serde_json::from_str(&res).to_didcomm("can not resolve DID Doc"),
            None => Ok(None),
        }
    }

}


pub struct OnDIDResolverResultAdapter {
    pub cb_id: i32
}


impl OnDIDResolverResult for OnDIDResolverResultAdapter {
    // TODO: better error handling
    fn success(&self, result: Option<String>) {
        CALLBACK_SENDERS.lock().unwrap().remove(&self.cb_id).unwrap().send(
            Ok(result)
        ).unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_SENDERS.lock().unwrap().remove(&self.cb_id).unwrap().send(
            Err(err_msg(err, msg))
        ).unwrap();
    }
}



