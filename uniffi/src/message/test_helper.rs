use didcomm::{
    error::{err_msg, Error, ErrorKind, Result},
    Message, PackEncryptedMetadata, PackSignedMetadata, UnpackMetadata,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures::channel::oneshot;
use lazy_static::lazy_static;

use crate::test_vectors::{ALICE_DID_DOC, ALICE_SECRETS, BOB_DID_DOC, BOB_SECRETS};
use crate::{
    common::get_next_id, ExampleFFIDIDResolver, ExampleFFISecretsResolver, FFIDIDResolver,
    FFISecretsResolver, OnPackEncryptedResult, OnPackPlaintextResult, OnPackSignedResult,
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

pub(crate) async fn get_pack_error(cb_id: i32) -> Error {
    let receiver = CALLBACK_PACK_RECEIVER
        .lock()
        .unwrap()
        .remove(&cb_id)
        .unwrap();
    receiver.await.unwrap().err().unwrap()
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

pub(crate) async fn get_unpack_result(cb_id: i32) -> Message {
    let receiver = CALLBACK_UNPACK_RECEIVER
        .lock()
        .unwrap()
        .remove(&cb_id)
        .unwrap();
    receiver.await.unwrap().unwrap()
}

pub(crate) async fn get_unpack_error(cb_id: i32) -> Error {
    let receiver = CALLBACK_UNPACK_RECEIVER
        .lock()
        .unwrap()
        .remove(&cb_id)
        .unwrap();
    receiver.await.unwrap().err().unwrap()
}

pub(crate) fn create_secrets_resolver() -> Box<dyn FFISecretsResolver> {
    Box::new(ExampleFFISecretsResolver::new(
        ALICE_SECRETS
            .clone()
            .into_iter()
            .chain(BOB_SECRETS.clone().into_iter())
            .collect(),
    ))
}

pub(crate) fn create_did_resolver() -> Box<dyn FFIDIDResolver> {
    Box::new(ExampleFFIDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
    ]))
}

pub(crate) fn create_pack_callback() -> (Box<PackCallback>, i32) {
    let test_cb = PackCallbackCreator::new().cb;
    let cb_id = test_cb.cb_id;
    (test_cb, cb_id)
}

pub(crate) fn create_unpack_cb() -> (Box<UnpackCallback>, i32) {
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

    (Box::new(UnpackCallback { cb_id }), cb_id)
}
