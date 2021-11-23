use didcomm::{error::ErrorKind, Message, UnpackMetadata, UnpackOptions};

use crate::common::EXECUTOR;
use crate::did_resolver_adapter::FFIDIDResolverAdapter;
use crate::{
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
    use crate::message::test_helper::{
        create_did_resolver, create_pack_callback, create_secrets_resolver, create_unpack_cb,
        get_pack_result, get_unpack_error, get_unpack_result,
    };
    use crate::message::unpack::unpack;
    use crate::message::{pack_encrypted, pack_plaintext, pack_signed};
    use didcomm::error::ErrorKind;
    use didcomm::{PackEncryptedOptions, UnpackOptions};

    use crate::test_vectors::{simple_message, ALICE_DID, BOB_DID};

    #[tokio::test]
    async fn unpack_works_plaintext() {
        let msg = simple_message();

        let (pack_cb, pack_cb_cb_id) = create_pack_callback();
        pack_plaintext(&msg, create_did_resolver(), pack_cb);
        let res = get_pack_result(pack_cb_cb_id).await;

        let (unpack_cb, unpack_cb_cb_id) = create_unpack_cb();
        unpack(
            res,
            create_did_resolver(),
            create_secrets_resolver(),
            &UnpackOptions::default(),
            unpack_cb,
        );
        let res = get_unpack_result(unpack_cb_cb_id).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_signed() {
        let msg = simple_message();

        let (pack_cb, pack_cb_cb_id) = create_pack_callback();
        pack_signed(
            &msg,
            String::from(ALICE_DID),
            create_did_resolver(),
            create_secrets_resolver(),
            pack_cb,
        );
        let res = get_pack_result(pack_cb_cb_id).await;

        let (unpack_cb, unpack_cb_cb_id) = create_unpack_cb();
        unpack(
            res,
            create_did_resolver(),
            create_secrets_resolver(),
            &UnpackOptions::default(),
            unpack_cb,
        );
        let res = get_unpack_result(unpack_cb_cb_id).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_encrypted() {
        let msg = simple_message();

        let (pack_cb, pack_cb_cb_id) = create_pack_callback();
        pack_encrypted(
            &msg,
            String::from(BOB_DID),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            create_did_resolver(),
            create_secrets_resolver(),
            &PackEncryptedOptions {
                forward: false,
                ..PackEncryptedOptions::default()
            },
            pack_cb,
        );
        let res = get_pack_result(pack_cb_cb_id).await;

        let (unpack_cb, unpack_cb_cb_id) = create_unpack_cb();
        unpack(
            res,
            create_did_resolver(),
            create_secrets_resolver(),
            &UnpackOptions::default(),
            unpack_cb,
        );
        let res = get_unpack_result(unpack_cb_cb_id).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_malformed() {
        let (unpack_cb, unpack_cb_cb_id) = create_unpack_cb();
        unpack(
            String::from("invalid message"),
            create_did_resolver(),
            create_secrets_resolver(),
            &UnpackOptions::default(),
            unpack_cb,
        );
        let res = get_unpack_error(unpack_cb_cb_id).await;

        assert_eq!(res.kind(), ErrorKind::Malformed);
    }
}
