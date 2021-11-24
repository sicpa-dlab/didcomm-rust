use didcomm::Message;
use didcomm::{error::ErrorKind, PackSignedMetadata};

use crate::common::{ErrorCode, EXECUTOR};
use crate::did::FFIDIDResolver;
use crate::did_resolver_adapter::FFIDIDResolverAdapter;
use crate::secrets::{secrets_resolver_adapter::FFISecretsResolverAdapter, FFISecretsResolver};

pub trait OnPackSignedResult: Sync + Send {
    fn success(&self, result: String, metadata: PackSignedMetadata);
    fn error(&self, err: ErrorKind, err_msg: String);
}

pub fn pack_signed(
    msg: &Message,
    sign_by: String,
    did_resolver: Box<dyn FFIDIDResolver>,
    secret_resolver: Box<dyn FFISecretsResolver>,
    cb: Box<dyn OnPackSignedResult>,
) -> ErrorCode {
    let msg = msg.clone();
    let did_resolver = FFIDIDResolverAdapter::new(did_resolver);
    let secret_resolver = FFISecretsResolverAdapter::new(secret_resolver);

    let future = async move {
        msg.pack_signed(&sign_by, &did_resolver, &secret_resolver)
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
    use didcomm::error::ErrorKind;
    use didcomm::Message;
    use serde_json::json;

    use crate::message::pack_signed::pack_signed;
    use crate::message::test_helper::{
        create_did_resolver, create_secrets_resolver, get_error, get_ok, PackResult,
    };

    use crate::test_vectors::{simple_message, ALICE_DID};

    #[tokio::test]
    async fn pack_signed_works() {
        let (cb, receiver) = PackResult::new();

        pack_signed(
            &simple_message(),
            String::from(ALICE_DID),
            create_did_resolver(),
            create_secrets_resolver(),
            cb,
        );

        let res = get_ok(receiver).await;
        assert!(res.contains("payload"));
    }

    #[tokio::test]
    async fn pack_signed_works_did_not_found() {
        let msg = Message::build(
            "example-1".to_owned(),
            "example/v1".to_owned(),
            json!("example-body"),
        )
        .to(String::from("did:unknown:bob"))
        .from(ALICE_DID.to_owned())
        .finalize();

        let (cb, receiver) = PackResult::new();

        pack_signed(
            &msg,
            String::from("did:unknown:alice"),
            create_did_resolver(),
            create_secrets_resolver(),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::DIDNotResolved);
    }

    #[tokio::test]
    async fn pack_signed_works_did_url_not_found() {
        let (cb, receiver) = PackResult::new();

        pack_signed(
            &simple_message(),
            String::from(format!("{}#unknown-fragment", ALICE_DID)),
            create_did_resolver(),
            create_secrets_resolver(),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::DIDUrlNotFound);
    }

    #[tokio::test]
    async fn pack_signed_works_secret_not_found() {
        let (cb, receiver) = PackResult::new();

        pack_signed(
            &simple_message(),
            String::from(format!("{}#key-not-in-secrets-1", ALICE_DID)),
            create_did_resolver(),
            create_secrets_resolver(),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::SecretNotFound);
    }

    #[tokio::test]
    async fn pack_signed_works_illegal_argument() {
        let (cb, receiver) = PackResult::new();

        pack_signed(
            &simple_message(),
            String::from("not-a-did"),
            create_did_resolver(),
            create_secrets_resolver(),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::IllegalArgument);
    }
}
