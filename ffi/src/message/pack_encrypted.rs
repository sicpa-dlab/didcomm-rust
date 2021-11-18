use didcomm::{Message, PackEncryptedMetadata, PackEncryptedOptions};
use didcomm::{error::ErrorKind};

use crate::common::{ErrorCode, EXECUTOR};
use crate::did::{FFIDIDResolver, did_resolver_adapter::FFIDIDResolverAdapter};
use crate::secrets::{FFISecretsResolver, secrets_resolver_adapter::FFISecretsResolverAdapter};


pub trait OnPackEncryptedResult: Sync + Send {
    fn success(&self, result: String, metadata: PackEncryptedMetadata);
    fn error(&self, err: ErrorKind, err_msg: String);
}

pub fn pack_encrypted<'a, 'b>(
    msg: &'a Message,
    to: String,
    from: Option<String>,
    sign_by: Option<String>,
    did_resolver: Box<dyn FFIDIDResolver>,
    secret_resolver: Box<dyn FFISecretsResolver>,
    options: &'b PackEncryptedOptions,
    cb: Box<dyn OnPackEncryptedResult>,
) -> ErrorCode {

    let msg = msg.clone();
    let options = options.clone();
    let did_resolver = FFIDIDResolverAdapter::new(did_resolver);
    let secret_resolver = FFISecretsResolverAdapter::new(secret_resolver);

    let future = async move {
        msg.pack_encrypted(&to, from.as_deref(), sign_by.as_deref(), &did_resolver, &secret_resolver, &options)
            .await
    };
    EXECUTOR.spawn_ok(async move {
        match future.await {
            Ok((result, metadata)) => cb.success(result, metadata),
            Err(err) => cb.error(err.kind(), err.to_string()),
        }
    });

    ErrorCode::Success
}


#[cfg(test)]
mod tests {
    use crate::message::test_helper::{TestCallbackCreator, get_result};
    use crate::test_vectors::{ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC};
    use crate::{pack_encrypted};
    use crate::did::resolvers::ExampleFFIDIDResolver;
        use crate::secrets::resolvers::ExampleFFISecretsResolver;
    use didcomm::{Message, PackEncryptedOptions};
    use serde_json::json;
    
    #[tokio::test]
    async fn test_pack_encrypted_works() {
        let msg = Message::build(
                "example-1".to_owned(),
                "example/v1".to_owned(),
                json!("example-body"),
            )
            .to(BOB_DID.to_owned())
            .from(ALICE_DID.to_owned())
            .finalize();

        let did_resolver =
            ExampleFFIDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
        let secrets_resolver = ExampleFFISecretsResolver::new(ALICE_SECRETS.clone());
        let test_cb = TestCallbackCreator::new().cb;
        let cb_id = test_cb.cb_id;            

        pack_encrypted(
            &msg,
            String::from(BOB_DID),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            Box::new(did_resolver),
            Box::new(secrets_resolver),
            &PackEncryptedOptions{forward: false, ..PackEncryptedOptions::default()},
            test_cb,
        );

        let res = get_result(cb_id).await.unwrap();
        // print!("res: {}", res);
        assert!(res.contains("ciphertext"));
    }
}
