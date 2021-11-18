use std::{cmp, sync::atomic::{AtomicUsize, Ordering}};

use futures::executor::ThreadPool;
use lazy_static::lazy_static;
use crate::UniffiCustomTypeWrapper;

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

// We use `JsonObject` in our UDL. It moves to and from Uniffi bindings via a string.
pub type JsonObject = serde_json::Value;

// We must implement the UniffiCustomTypeWrapper trait.
impl UniffiCustomTypeWrapper for JsonObject {
    type Wrapped = String;

    fn wrap(val: Self::Wrapped) -> uniffi::Result<Self> {
        Ok(serde_json::from_str(&val)?)
    }

    fn unwrap(obj: Self) -> Self::Wrapped {
        obj.to_string()
    }
}
