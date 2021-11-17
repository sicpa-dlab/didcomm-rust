use didcomm::{error::ErrorKind, PackSignedMetadata};

use crate::did::{FFIDIDResolver, did_resolver_adapter::FFIDIDResolverAdapter};
use crate::secrets::{FFISecretsResolver, secrets_resolver_adapter::FFISecretsResolverAdapter};

use super::{ErrorCode, Message, EXECUTOR};

pub trait OnPackSignedResult: Sync + Send {
    fn success(&self, result: String, metadata: PackSignedMetadata);
    fn error(&self, err: ErrorKind, err_msg: String);
}

impl Message {
    pub fn pack_signed<'dr, 'sr>(
        &self,
        sign_by: &str,
        did_resolver: Box<dyn FFIDIDResolver>,
        secret_resolver: Box<dyn FFISecretsResolver>,
        cb: Box<dyn OnPackSignedResult>,
    ) -> ErrorCode {
        let msg = self.0.clone();
        let sign_by = String::from(sign_by);
        let did_resolver = FFIDIDResolverAdapter::new(did_resolver);
        let secret_resolver = FFISecretsResolverAdapter::new(secret_resolver);

        let future = async move {
            msg.pack_signed(&sign_by, &did_resolver, &secret_resolver)
                .await
        };
        EXECUTOR.spawn_ok(async move {
            let res = future.await;
            match res {
                Ok(result) => cb.success(result.0, result.1),
                Err(err) => cb.error(err.kind(), err.to_string()),
            }
        });
        ErrorCode::Success
    }
}

#[cfg(test)]
mod tests {
    use crate::did::resolvers::ExampleFFIDIDResolver;
    use crate::message::Message as FFIMessage;
    use crate::secrets::resolvers::ExampleFFISecretsResolver;
    use didcomm::error::ErrorKind;
    use didcomm::{Message, PackSignedMetadata};
    use serde_json::json;

    use crate::test_vectors::{ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC};

    use super::OnPackSignedResult;

    pub struct PrintCallback {}

    impl OnPackSignedResult for PrintCallback {
        fn success(&self, result: String, metadata: PackSignedMetadata) {
            println!("result: {}", result)
        }

        fn error(&self, err: ErrorKind, err_msg: String) {
            println!("error: {}: {}", err.to_string(), err_msg)
        }
    }

    #[test]
    fn test_pack_signed_works() {
        let msg = FFIMessage(
            Message::build(
                "example-1".to_owned(),
                "example/v1".to_owned(),
                json!("example-body"),
            )
            .to(ALICE_DID.to_owned())
            .from(BOB_DID.to_owned())
            .finalize(),
        );

        let did_resolver =
            ExampleFFIDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleFFISecretsResolver::new(ALICE_SECRETS.clone());

        msg.pack_signed(
            ALICE_DID,
            Box::new(did_resolver),
            Box::new(secrets_resolver),
            Box::new(PrintCallback {}),
        );

        // FIXME
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}
