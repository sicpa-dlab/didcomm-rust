use didcomm::error::{ErrorKind};

use crate::common::ErrorCode;

pub trait FFIDIDResolver: Sync + Send {
    fn resolve(&self, did: String, cb: Box<dyn OnDIDResolverResult>) -> ErrorCode;
}

pub trait OnDIDResolverResult: Sync + Send {
    fn success(&self, result: Option<String>);
    fn error(&self, err: ErrorKind, msg: String);
}



