use didcomm::{error::ErrorKind, Message, UnpackMetadata, UnpackOptions};

use crate::common::EXECUTOR;
use crate::{
    did_resolver_adapter::FFIDIDResolverAdapter,
    secrets_resolver_adapter::FFISecretsResolverAdapter, ErrorCode, FFIDIDResolver,
    FFISecretsResolver,
};

pub trait OnUnpackResult: Sync + Send {
    fn success(&self, result: Message, metadata: UnpackMetadata);
    fn error(&self, err: ErrorKind, err_msg: String);
}

pub fn unpack<'a>(
    msg: String,
    did_resolver: Box<dyn FFIDIDResolver>,
    secret_resolver: Box<dyn FFISecretsResolver>,
    options: &'a UnpackOptions,
    cb: Box<dyn OnUnpackResult>,
) -> ErrorCode {
    let msg = msg.clone();
    let options = options.clone();
    let did_resolver = FFIDIDResolverAdapter::new(did_resolver);
    let secret_resolver = FFISecretsResolverAdapter::new(secret_resolver);

    let future =
        async move { Message::unpack(&msg, &did_resolver, &secret_resolver, &options).await };
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
    use crate::message::test_helper::{create_unpack_cb, get_pack_result, get_unpack_result};
    use crate::message::unpack::unpack;
    use crate::message::{pack_encrypted, pack_plaintext, pack_signed};
    use crate::secrets::resolvers::ExampleFFISecretsResolver;
    use crate::{did::resolvers::ExampleFFIDIDResolver, message::test_helper::PackCallbackCreator};
    use didcomm::{Message, PackEncryptedOptions, UnpackOptions};
    use serde_json::json;

    use crate::test_vectors::{ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, simple_message};

    #[tokio::test]
    async fn test_unpack_plaintext_works() {
        let msg = simple_message();

        let did_resolver = Box::new(ExampleFFIDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
        ]));
        let pack_cb = PackCallbackCreator::new().cb;
        let pack_cb_cb_id = pack_cb.cb_id;

        pack_plaintext(&msg, did_resolver, pack_cb);
        let res = get_pack_result(pack_cb_cb_id).await;

        let did_resolver = Box::new(ExampleFFIDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
        ]));
        let secrets_resolver = Box::new(ExampleFFISecretsResolver::new(ALICE_SECRETS.clone()));
        let unpack_cb = create_unpack_cb();
        let unpack_cb_cb_id = unpack_cb.cb_id;
        unpack(
            res,
            did_resolver,
            secrets_resolver,
            &UnpackOptions::default(),
            unpack_cb,
        );
        let res = get_unpack_result(unpack_cb_cb_id).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn test_unpack_signed_works() {
        let msg = simple_message();

        let did_resolver = Box::new(ExampleFFIDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
        ]));
        let secrets_resolver = Box::new(ExampleFFISecretsResolver::new(ALICE_SECRETS.clone()));
        let test_cb = PackCallbackCreator::new().cb;
        let cb_id = test_cb.cb_id;

        pack_signed(
            &msg,
            String::from(ALICE_DID),
            did_resolver,
            secrets_resolver,
            test_cb,
        );
        let res = get_pack_result(cb_id).await;

        let did_resolver = Box::new(ExampleFFIDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
        ]));
        let secrets_resolver = Box::new(ExampleFFISecretsResolver::new(ALICE_SECRETS.clone()));
        let unpack_cb = create_unpack_cb();
        let unpack_cb_cb_id = unpack_cb.cb_id;
        unpack(
            res,
            did_resolver,
            secrets_resolver,
            &UnpackOptions::default(),
            unpack_cb,
        );
        let res = get_unpack_result(unpack_cb_cb_id).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn test_unpack_encrypted_works() {
        let msg = simple_message();

        let did_resolver = Box::new(ExampleFFIDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
        ]));
        let secrets_resolver = Box::new(ExampleFFISecretsResolver::new(ALICE_SECRETS.clone()));
        let test_cb = PackCallbackCreator::new().cb;
        let cb_id = test_cb.cb_id;

        pack_encrypted(
            &msg,
            String::from(BOB_DID),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            did_resolver,
            secrets_resolver,
            &PackEncryptedOptions {
                forward: false,
                ..PackEncryptedOptions::default()
            },
            test_cb,
        );
        let res = get_pack_result(cb_id).await;

        let did_resolver = Box::new(ExampleFFIDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
        ]));
        let secrets_resolver = Box::new(ExampleFFISecretsResolver::new(BOB_SECRETS.clone()));
        let unpack_cb = create_unpack_cb();
        let unpack_cb_cb_id = unpack_cb.cb_id;
        unpack(
            res,
            did_resolver,
            secrets_resolver,
            &UnpackOptions::default(),
            unpack_cb,
        );
        let res = get_unpack_result(unpack_cb_cb_id).await;

        assert_eq!(res, msg);
    }
}
