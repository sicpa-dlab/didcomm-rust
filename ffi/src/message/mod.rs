mod pack_signed;

use didcomm::Message as _Message;
use didcomm::error::ErrorKind;
use didcomm::PackSignedMetadata;

use futures::executor::ThreadPool;
use lazy_static::lazy_static;
use std::cmp;

pub struct Message(pub(crate) _Message);


pub enum ErrorCode
{
    Success = 0,
    Error = 1
}

pub trait OnResult: Sync + Send {
    fn success(&self, result: String, metadata: PackSignedMetadata);
    fn error(&self, err: ErrorKind, err_msg: String);

}

// Global (lazy inited) instance of Locator
lazy_static! {
    pub static ref EXECUTOR: ThreadPool = ThreadPool::builder().pool_size(cmp::max(8, num_cpus::get())).create().unwrap();
}

pub struct PrintCallback{}

impl OnResult for PrintCallback {

    fn success(&self, result: String, metadata: PackSignedMetadata) {
        println!("result: {}", result)
    }

    fn error(&self, err: ErrorKind, err_msg: String) {
        println!("error: {}", err_msg)
    }
}