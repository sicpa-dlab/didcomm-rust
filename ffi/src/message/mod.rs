mod pack_signed;

use didcomm::Message as _Message;

use futures::executor::ThreadPool;
use lazy_static::lazy_static;
use std::cmp;

pub struct Message(pub(crate) _Message);

pub enum ErrorCode {
    Success = 0,
    Error = 1,
}

// Global (lazy inited) instance of Locator
lazy_static! {
    pub static ref EXECUTOR: ThreadPool = ThreadPool::builder()
        .pool_size(cmp::max(8, num_cpus::get()))
        .create()
        .unwrap();
}
