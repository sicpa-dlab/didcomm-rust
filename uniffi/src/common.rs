use std::{
    cell::RefCell,
    cmp,
    sync::{Arc, Mutex},
};

use crate::UniffiCustomTypeWrapper;
use didcomm_core::error::{err_msg, ErrorKind, Result, ResultExt, ResultExtNoContext, ToResult};
use futures::{channel::oneshot, executor::ThreadPool};
use lazy_static::lazy_static;

pub enum ErrorCode {
    Success = 0,
    Error = 1,
}

lazy_static! {
    // Global (lazy inited) instance of future executor
    pub(crate) static ref EXECUTOR: ThreadPool = ThreadPool::builder()
        .pool_size(cmp::max(8, num_cpus::get()))
        .create()
        .unwrap();
}

// We use `JsonValue` in our UDL. It moves to and from Uniffi bindings via a string.
pub type JsonValue = serde_json::Value;

// We must implement the UniffiCustomTypeWrapper trait.
impl UniffiCustomTypeWrapper for JsonValue {
    type Wrapped = String;

    fn wrap(val: Self::Wrapped) -> uniffi::Result<Self> {
        Ok(serde_json::from_str(&val).to_didcomm("Invalid json value")?)
    }

    fn unwrap(obj: Self) -> Self::Wrapped {
        serde_json::to_string(&obj).expect("unable serialize json value")
    }
}

pub(crate) struct OnResultReceiver<T>(oneshot::Receiver<Result<T>>);

impl<T> OnResultReceiver<T> {
    pub(crate) async fn get(self) -> Result<T> {
        self.0
            .await
            .kind(ErrorKind::InvalidState, "unable receive callback result")?
    }
}

pub struct OnResult<T>(Mutex<RefCell<Option<oneshot::Sender<Result<T>>>>>);

impl<T> OnResult<T> {
    pub(crate) fn new() -> (Arc<Self>, OnResultReceiver<T>) {
        let (sender, receiver) = oneshot::channel::<Result<T>>();
        let on_result = Arc::new(OnResult(Mutex::new(RefCell::new(Some(sender)))));
        (on_result, OnResultReceiver(receiver))
    }

    pub fn success(&self, result: T) -> std::result::Result<(), ErrorKind> {
        let sender = self
            .0
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
            .0
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
