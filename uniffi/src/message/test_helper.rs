use std::cell::RefCell;
use std::fmt;
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

pub(crate) struct TestResult<T>
where
    T: fmt::Debug + 'static,
{
    sender: Mutex<RefCell<Option<oneshot::Sender<Result<T>>>>>,
}

impl<T> TestResult<T>
where
    T: fmt::Debug + 'static,
{
    pub(crate) fn new() -> (Box<Self>, Receiver<Result<T>>) {
        let (sender, receiver) = oneshot::channel::<Result<T>>();
        (
            Box::new(TestResult {
                sender: Mutex::new(RefCell::new(Some(sender))),
            }),
            receiver,
        )
    }

    fn _success(&self, result: T) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Ok(result))
            .expect("Unable send");
    }

    fn _error(&self, err: ErrorKind, msg: String) {
        self.sender
            .lock()
            .expect("Unable lock")
            .replace(None)
            .expect("Callback has been already called")
            .send(Err(err_msg(err, msg)))
            .expect("Unable send");
    }
}

pub(crate) type PackResult = TestResult<String>;

impl OnPackPlaintextResult for PackResult {
    fn success(&self, result: String) {
        self._success(result);
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self._error(err, msg);
    }
}

impl OnPackSignedResult for PackResult {
    fn success(&self, result: String, _metadata: PackSignedMetadata) {
        self._success(result);
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self._error(err, msg);
    }
}

impl OnPackEncryptedResult for PackResult {
    fn success(&self, result: String, _metadata: PackEncryptedMetadata) {
        self._success(result);
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self._error(err, msg);
    }
}

pub(crate) type UnpackResult = TestResult<Message>;

impl OnUnpackResult for UnpackResult {
    fn success(&self, result: Message, _metadata: UnpackMetadata) {
        self._success(result);
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self._error(err, msg);
    }
}
