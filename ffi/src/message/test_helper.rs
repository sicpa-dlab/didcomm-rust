use std::{collections::HashMap, sync::{Arc, Mutex}};
use didcomm::{PackEncryptedMetadata, PackSignedMetadata, error::{ErrorKind, Result, err_msg}};

use futures::channel::oneshot;
use lazy_static::lazy_static;

use crate::{OnPackEncryptedResult, OnPackSignedResult, common::get_next_id};

lazy_static! {
    static ref CALLBACK_SENDERS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<Option<String>>>>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref CALLBACK_RECEIVER: Arc<Mutex<HashMap<i32, oneshot::Receiver<Result<Option<String>>>>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub struct TestOnPackResult {
    pub cb_id: i32
}

impl OnPackEncryptedResult for TestOnPackResult {
    fn success(&self, result: String, _metadata: PackEncryptedMetadata) {
        CALLBACK_SENDERS.lock().unwrap().remove(&self.cb_id).unwrap().send(
            Ok(Some(result))
        ).unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_SENDERS.lock().unwrap().remove(&self.cb_id).unwrap().send(
            Err(err_msg(err, msg))
        ).unwrap();
    }
}


impl OnPackSignedResult for TestOnPackResult {
    fn success(&self, result: String, _metadata: PackSignedMetadata) {
        CALLBACK_SENDERS.lock().unwrap().remove(&self.cb_id).unwrap().send(
            Ok(Some(result))
        ).unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_SENDERS.lock().unwrap().remove(&self.cb_id).unwrap().send(
            Err(err_msg(err, msg))
        ).unwrap();
    }
}

pub(crate) struct TestCallbackCreator<T> 
    where T: OnPackEncryptedResult + OnPackSignedResult
{
    pub cb: Box<T>,
}

impl TestCallbackCreator<TestOnPackResult> {
    pub fn new() -> Self {
        let (sender, receiver) = oneshot::channel::<Result<Option<String>>>();

        let cb_id = get_next_id();
        CALLBACK_SENDERS.lock().unwrap().insert(cb_id, sender);
        CALLBACK_RECEIVER.lock().unwrap().insert(cb_id, receiver);
    
        TestCallbackCreator{cb: Box::new(TestOnPackResult{cb_id})}
    }
}

pub(crate) async fn get_result(cb_id: i32) -> Option<String> {
    let receiver = CALLBACK_RECEIVER.lock().unwrap().remove(&cb_id).unwrap();
    receiver.await.unwrap().unwrap()
}

