use std::cell::RefCell;
use std::sync::Mutex;

use didcomm::error::{err_msg, Error, ErrorKind, Result};
use didcomm::{Message, PackEncryptedMetadata, PackSignedMetadata, UnpackMetadata};
use futures::channel::oneshot::{self, Receiver};

use crate::test_vectors::{ALICE_DID_DOC, ALICE_SECRETS, BOB_DID_DOC, BOB_SECRETS};
use crate::{
    ExampleFFIDIDResolver, ExampleFFISecretsResolver, FFIDIDResolver, FFISecretsResolver,
    OnPackEncryptedResult, OnPackPlaintextResult, OnPackSignedResult, OnUnpackResult,
};

pub(crate) async fn get_ok<T>(receiver: Receiver<Result<T>>) -> T {
    receiver
        .await
        .expect("unable receive result")
        .expect("result is error")
}

pub(crate) async fn get_error<T>(receiver: Receiver<Result<T>>) -> Error {
    receiver
        .await
        .expect("unable receive result")
        .err()
        .expect("result is ok")
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

pub(crate) struct PackResult {
    sender: Mutex<RefCell<Option<oneshot::Sender<Result<String>>>>>,
}

impl PackResult {
    pub(crate) fn new() -> (Box<Self>, Receiver<Result<String>>) {
        let (sender, receiver) = oneshot::channel::<Result<String>>();
        (
            Box::new(PackResult {
                sender: Mutex::new(RefCell::new(Some(sender))),
            }),
            receiver,
        )
    }
}

impl OnPackPlaintextResult for PackResult {
    fn success(&self, result: String) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Ok(result))
            .expect("Unable send");
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Err(err_msg(err, msg)))
            .expect("Unable send");
    }
}

impl OnPackSignedResult for PackResult {
    fn success(&self, result: String, _metadata: PackSignedMetadata) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Ok(result))
            .expect("Unable send");
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Err(err_msg(err, msg)))
            .expect("Unable send");
    }
}

impl OnPackEncryptedResult for PackResult {
    fn success(&self, result: String, _metadata: PackEncryptedMetadata) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Ok(result))
            .expect("Unable send");
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Err(err_msg(err, msg)))
            .expect("Unable send");
    }
}

pub(crate) struct UnpackResult {
    sender: Mutex<RefCell<Option<oneshot::Sender<Result<Message>>>>>,
}

impl UnpackResult {
    pub(crate) fn new() -> (Box<Self>, Receiver<Result<Message>>) {
        let (sender, receiver) = oneshot::channel::<Result<Message>>();
        (
            Box::new(UnpackResult {
                sender: Mutex::new(RefCell::new(Some(sender))),
            }),
            receiver,
        )
    }
}

impl OnUnpackResult for UnpackResult {
    fn success(&self, result: Message, _metadata: UnpackMetadata) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Ok(result))
            .expect("Unable send");
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Err(err_msg(err, msg)))
            .expect("Unable send");
    }
}
