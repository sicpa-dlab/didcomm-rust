use std::{
    cmp,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::UniffiCustomTypeWrapper;
use didcomm::error::ToResult;
use futures::executor::ThreadPool;
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

    static ref IDS_COUNTER: AtomicUsize = AtomicUsize::new(1);
}

pub fn get_next_id() -> i32 {
    (IDS_COUNTER.fetch_add(1, Ordering::SeqCst) + 1) as i32
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
        obj.to_string()
    }
}
