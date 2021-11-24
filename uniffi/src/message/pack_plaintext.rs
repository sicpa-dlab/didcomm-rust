use didcomm::error::ErrorKind;
use didcomm::Message;

use crate::common::{ErrorCode, EXECUTOR};
use crate::did::FFIDIDResolver;
use crate::did_resolver_adapter::FFIDIDResolverAdapter;

pub trait OnPackPlaintextResult: Sync + Send {
    fn success(&self, result: String);
    fn error(&self, err: ErrorKind, err_msg: String);
}

pub fn pack_plaintext(
    msg: &Message,
    did_resolver: Box<dyn FFIDIDResolver>,
    cb: Box<dyn OnPackPlaintextResult>,
) -> ErrorCode {
    let msg = msg.clone();
    let did_resolver = FFIDIDResolverAdapter::new(did_resolver);

    let future = async move { msg.pack_plaintext(&did_resolver).await };

    EXECUTOR.spawn_ok(async move {
        match future.await {
            Ok(result) => cb.success(result),
            Err(err) => cb.error(err.kind(), err.to_string()),
        }
    });

    ErrorCode::Success
}

#[cfg(test)]
mod tests {

    use crate::message::pack_plaintext;

    use crate::message::test_helper::{create_did_resolver, get_ok, PackResult};
    use crate::test_vectors::simple_message;

    #[tokio::test]
    async fn pack_plaintext_works() {
        let (cb, receiver) = PackResult::new();

        pack_plaintext(&simple_message(), create_did_resolver(), cb);

        let res = get_ok(receiver).await;
        assert!(res.contains("body"));
    }
}
