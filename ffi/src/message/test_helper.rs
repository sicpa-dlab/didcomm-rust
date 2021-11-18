use didcomm::{
    error::{err_msg, ErrorKind, Result},
    Message, PackEncryptedMetadata, PackSignedMetadata, UnpackMetadata,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures::channel::oneshot;
use lazy_static::lazy_static;

use crate::{
    common::get_next_id, OnPackEncryptedResult, OnPackPlaintextResult, OnPackSignedResult,
    OnUnpackResult,
};

lazy_static! {
    static ref CALLBACK_PACK_SENDERS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<String>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref CALLBACK_PACK_RECEIVER: Arc<Mutex<HashMap<i32, oneshot::Receiver<Result<String>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref CALLBACK_UNPACK_SENDERS: Arc<Mutex<HashMap<i32, oneshot::Sender<Result<Message>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref CALLBACK_UNPACK_RECEIVER: Arc<Mutex<HashMap<i32, oneshot::Receiver<Result<Message>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

pub struct PackCallback {
    pub cb_id: i32,
}

impl OnPackEncryptedResult for PackCallback {
    fn success(&self, result: String, _metadata: PackEncryptedMetadata) {
        CALLBACK_PACK_SENDERS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Ok(result))
            .unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_PACK_SENDERS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Err(err_msg(err, msg)))
            .unwrap();
    }
}

impl OnPackSignedResult for PackCallback {
    fn success(&self, result: String, _metadata: PackSignedMetadata) {
        CALLBACK_PACK_SENDERS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Ok(result))
            .unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_PACK_SENDERS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Err(err_msg(err, msg)))
            .unwrap();
    }
}

impl OnPackPlaintextResult for PackCallback {
    fn success(&self, result: String) {
        CALLBACK_PACK_SENDERS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Ok(result))
            .unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_PACK_SENDERS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Err(err_msg(err, msg)))
            .unwrap();
    }
}

pub(crate) struct PackCallbackCreator<T>
where
    T: OnPackEncryptedResult + OnPackSignedResult + OnPackPlaintextResult,
{
    pub cb: Box<T>,
}

impl PackCallbackCreator<PackCallback> {
    pub fn new() -> Self {
        let (sender, receiver) = oneshot::channel::<Result<String>>();

        let cb_id = get_next_id();
        CALLBACK_PACK_SENDERS.lock().unwrap().insert(cb_id, sender);
        CALLBACK_PACK_RECEIVER
            .lock()
            .unwrap()
            .insert(cb_id, receiver);

        PackCallbackCreator {
            cb: Box::new(PackCallback { cb_id }),
        }
    }
}

pub(crate) async fn get_pack_result(cb_id: i32) -> String {
    let receiver = CALLBACK_PACK_RECEIVER
        .lock()
        .unwrap()
        .remove(&cb_id)
        .unwrap();
    receiver.await.unwrap().unwrap()
}

pub struct UnpackCallback {
    pub cb_id: i32,
}

impl OnUnpackResult for UnpackCallback {
    fn success(&self, result: Message, _metadata: UnpackMetadata) {
        CALLBACK_UNPACK_SENDERS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Ok(result))
            .unwrap();
    }

    fn error(&self, err: ErrorKind, msg: String) {
        CALLBACK_UNPACK_SENDERS
            .lock()
            .unwrap()
            .remove(&self.cb_id)
            .unwrap()
            .send(Err(err_msg(err, msg)))
            .unwrap();
    }
}

pub(crate) fn create_unpack_cb() -> Box<UnpackCallback> {
    let (sender, receiver) = oneshot::channel::<Result<Message>>();

    let cb_id = get_next_id();
    CALLBACK_UNPACK_SENDERS
        .lock()
        .unwrap()
        .insert(cb_id, sender);
    CALLBACK_UNPACK_RECEIVER
        .lock()
        .unwrap()
        .insert(cb_id, receiver);

    Box::new(UnpackCallback { cb_id })
}

pub(crate) async fn get_unpack_result(cb_id: i32) -> Message {
    let receiver = CALLBACK_UNPACK_RECEIVER
        .lock()
        .unwrap()
        .remove(&cb_id)
        .unwrap();
    receiver.await.unwrap().unwrap()
}
