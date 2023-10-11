use didcomm_core::error::ErrorKind;
use didcomm_core::Message;

use crate::common::{ErrorCode, EXECUTOR};
use crate::did_resolver_adapter::DIDResolverAdapter;
use crate::DIDComm;

pub trait OnPackPlaintextResult: Sync + Send {
    fn success(&self, result: String);
    fn error(&self, err: ErrorKind, err_msg: String);
}

impl DIDComm {
    pub fn pack_plaintext(&self, msg: &Message, cb: Box<dyn OnPackPlaintextResult>) -> ErrorCode {
        let msg = msg.clone();
        let did_resolver = DIDResolverAdapter::new(self.did_resolver.clone());

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

    use crate::test_helper::{create_did_resolver, create_kms, get_ok, PackResult};
    use didcomm_core::test_vectors::MESSAGE_SIMPLE;

    #[tokio::test]
    async fn pack_plaintext_works() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_kms()).pack_plaintext(&MESSAGE_SIMPLE, cb);

        let res = get_ok(receiver).await;
        assert!(res.contains("body"));
    }
}
