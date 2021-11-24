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
        create_did_resolver, create_secrets_resolver, get_error, get_ok, PackResult, UnpackResult,
    };
    use crate::message::unpack::unpack;
    use crate::message::{pack_encrypted, pack_plaintext, pack_signed};
    use didcomm::error::ErrorKind;
    use didcomm::{PackEncryptedOptions, UnpackOptions};

    use crate::test_vectors::{simple_message, ALICE_DID, BOB_DID};

    #[tokio::test]
    async fn unpack_works_plaintext() {
        let msg = simple_message();

        let (cb, receiver) = PackResult::new();
        pack_plaintext(&msg, create_did_resolver(), cb);
        let res = get_ok(receiver).await;

        let (cb, receiver) = UnpackResult::new();
        unpack(
            res,
            create_did_resolver(),
            create_secrets_resolver(),
            &UnpackOptions::default(),
            cb,
        );
        let res = get_ok(receiver).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_signed() {
        let msg = simple_message();

        let (cb, receiver) = PackResult::new();
        pack_signed(
            &msg,
            String::from(ALICE_DID),
            create_did_resolver(),
            create_secrets_resolver(),
            cb,
        );
        let res = get_ok(receiver).await;

        let (cb, receiver) = UnpackResult::new();
        unpack(
            res,
            create_did_resolver(),
            create_secrets_resolver(),
            &UnpackOptions::default(),
            cb,
        );
        let res = get_ok(receiver).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_encrypted() {
        let msg = simple_message();

        let (cb, receiver) = PackResult::new();
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
            cb,
        );
        let res = get_ok(receiver).await;

        let (cb, receiver) = UnpackResult::new();
        unpack(
            res,
            create_did_resolver(),
            create_secrets_resolver(),
            &UnpackOptions::default(),
            cb,
        );
        let res = get_ok(receiver).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_malformed() {
        let (cb, receiver) = UnpackResult::new();
        unpack(
            String::from("invalid message"),
            create_did_resolver(),
            create_secrets_resolver(),
            &UnpackOptions::default(),
            cb,
        );
        let res = get_error(receiver).await;

        assert_eq!(res.kind(), ErrorKind::Malformed);
    }
}
