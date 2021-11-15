use didcomm::error::{ResultExt};
use futures::task::SpawnExt;

use crate::{did_resolver::{DIDResolverAdapter, FFIDIDResolver}, secrets_resolver::{FFISecretsResolver, SecretResolverAdapter}};

use super::{EXECUTOR, ErrorCode, Message, OnResult};


impl Message {
    pub fn pack_signed<'dr, 'sr>(
        &self,
        sign_by: &str,
        did_resolver:Box<dyn FFIDIDResolver>,
        secret_resolver: Box<dyn FFISecretsResolver>,
        cb: Box<dyn OnResult>
    ) -> ErrorCode {
        let msg = self.0.clone();
        let sign_by = String::from(sign_by);
        let did_resolver = DIDResolverAdapter::new(did_resolver);
        let secret_resolver = SecretResolverAdapter::new(secret_resolver);

        let future = async move {
            msg.pack_signed(&sign_by, &did_resolver, &secret_resolver).await
        };
        EXECUTOR.spawn_ok(
            async move {
                let res = future.await;
                match res {
                    Ok(result) => cb.success(result.0, result.1),
                    Err(err) => cb.error(err.kind(), err.to_string()),
                }
            }
        );
        ErrorCode::Success
    }
}

#[cfg(test)]
mod tests {
    use didcomm::Message;
    use serde_json::json;
    use crate::did_resolver::ExampleFFIDIDResolver;
    use crate::message::{Message as FFIMessage, OnResult, PrintCallback};

    use crate::secrets_resolver::ExampleFFISecretResolver;
    use crate::test_vectors::{ALICE_DID, ALICE_DID_DOC, BOB_DID, BOB_DID_DOC, ALICE_SECRETS};


    #[test]
    fn test_pack_signed_works() {
        let msg = Message::build(
            "example-1".to_owned(),
            "example/v1".to_owned(),
            json!("example-body"),
        )
        .to(ALICE_DID.to_owned())
        .from(BOB_DID.to_owned())
        .finalize();
        let m = FFIMessage(msg);

        let did_resolver = ExampleFFIDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleFFISecretResolver::new(ALICE_SECRETS.clone());

        m.pack_signed(
            ALICE_DID,
            Box::new(did_resolver),
            Box::new(secrets_resolver),
            Box::new(PrintCallback{})
            );

        ::std::thread::sleep(std::time::Duration::from_secs(5));
    }

}