use std::cell::RefCell;
use std::fmt;
use std::sync::Mutex;

use didcomm::error::{err_msg, Error, ErrorKind, Result};
use didcomm::{FromPrior, Message, PackEncryptedMetadata, PackSignedMetadata, UnpackMetadata};
use futures::channel::oneshot::{self, Receiver};

use crate::test_vectors::{
    ALICE_DID_DOC_WITH_NO_SECRETS, ALICE_SECRETS, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID_DOC,
    CHARLIE_SECRETS, MEDIATOR1_DID_DOC, MEDIATOR1_SECRETS, MEDIATOR2_DID_DOC, MEDIATOR2_SECRETS,
    MEDIATOR3_DID_DOC, MEDIATOR3_SECRETS,
};
use crate::{
    ExampleFFIDIDResolver, ExampleFFISecretsResolver, FFIDIDResolver, FFISecretsResolver,
    OnFromPriorPackResult, OnFromPriorUnpackResult, OnPackEncryptedResult, OnPackPlaintextResult,
    OnPackSignedResult, OnUnpackResult, OnWrapInForwardResult,
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
            .chain(CHARLIE_SECRETS.clone().into_iter())
            .chain(MEDIATOR1_SECRETS.clone().into_iter())
            .chain(MEDIATOR2_SECRETS.clone().into_iter())
            .chain(MEDIATOR3_SECRETS.clone().into_iter())
            .collect(),
    ))
}

pub(crate) fn create_did_resolver() -> Box<dyn FFIDIDResolver> {
    Box::new(ExampleFFIDIDResolver::new(vec![
        ALICE_DID_DOC_WITH_NO_SECRETS.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
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

pub(crate) type FromPriorPackResult = TestResult<(String, String)>;

impl OnFromPriorPackResult for FromPriorPackResult {
    fn success(&self, from_prior_jwt: String, kid: String) {
        self._success((from_prior_jwt, kid));
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self._error(err, msg);
    }
}

pub(crate) type FromPriorUnpackResult = TestResult<(FromPrior, String)>;

impl OnFromPriorUnpackResult for FromPriorUnpackResult {
    fn success(&self, from_prior: FromPrior, kid: String) {
        self._success((from_prior, kid));
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self._error(err, msg);
    }
}

pub(crate) type WrapInForwardResult = TestResult<String>;

impl OnWrapInForwardResult for WrapInForwardResult {
    fn success(&self, result: String) {
        self._success(result);
    }

    fn error(&self, err: ErrorKind, msg: String) {
        self._error(err, msg);
    }
}
