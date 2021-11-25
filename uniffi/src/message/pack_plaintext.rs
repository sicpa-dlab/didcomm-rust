use didcomm::error::ErrorKind;
use didcomm::Message;

use crate::common::{ErrorCode, EXECUTOR};
use crate::did_resolver_adapter::FFIDIDResolverAdapter;
use crate::DIDComm;

pub trait OnPackPlaintextResult: Sync + Send {
    fn success(&self, result: String);
    fn error(&self, err: ErrorKind, err_msg: String);
}

impl DIDComm {
    pub fn pack_plaintext(&self, msg: &Message, cb: Box<dyn OnPackPlaintextResult>) -> ErrorCode {
        // TODO; avoid cloning
        let msg = msg.clone();
        let did_resolver = FFIDIDResolverAdapter::new(self.did_resolver.clone());

        let future = async move { msg.pack_plaintext(&did_resolver).await };

        EXECUTOR.spawn_ok(async move {
            match future.await {
                Ok(result) => cb.success(result),
                Err(err) => cb.error(err.kind(), err.to_string()),
            }
        });

        ErrorCode::Success
    }
}

#[cfg(test)]
mod tests {

    use crate::DIDComm;

    use crate::test_vectors::simple_message;
    use crate::test_vectors::test_helper::{
        create_did_resolver, create_secrets_resolver, get_ok, PackResult,
    };

    #[tokio::test]
    async fn pack_plaintext_works() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_secrets_resolver())
            .pack_plaintext(&simple_message(), cb);

        let res = get_ok(receiver).await;
        assert!(res.contains("body"));
    }
}
