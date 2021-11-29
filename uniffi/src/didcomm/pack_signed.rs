use didcomm_core::Message;
use didcomm_core::{error::ErrorKind, PackSignedMetadata};

use crate::common::{ErrorCode, EXECUTOR};
use crate::did_resolver_adapter::DIDResolverAdapter;
use crate::secrets::secrets_resolver_adapter::SecretsResolverAdapter;
use crate::DIDComm;

pub trait OnPackSignedResult: Sync + Send {
    fn success(&self, result: String, metadata: PackSignedMetadata);
    fn error(&self, err: ErrorKind, err_msg: String);
}

impl DIDComm {
    pub fn pack_signed(
        &self,
        msg: &Message,
        sign_by: String,
        cb: Box<dyn OnPackSignedResult>,
    ) -> ErrorCode {
        let msg = msg.clone();
        let did_resolver = DIDResolverAdapter::new(self.did_resolver.clone());
        let secret_resolver = SecretsResolverAdapter::new(self.secret_resolver.clone());

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
}

#[cfg(test)]
mod tests {
    use didcomm_core::error::ErrorKind;
    use didcomm_core::Message;
    use serde_json::json;

    use crate::test_helper::{
        create_did_resolver, create_secrets_resolver, get_error, get_ok, PackResult,
    };
    use crate::DIDComm;

    use didcomm_core::test_vectors::{ALICE_DID, MESSAGE_SIMPLE};

    #[tokio::test]
    async fn pack_signed_works() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_secrets_resolver()).pack_signed(
            &MESSAGE_SIMPLE,
            String::from(ALICE_DID),
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

        DIDComm::new(create_did_resolver(), create_secrets_resolver()).pack_signed(
            &msg,
            String::from("did:unknown:alice"),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::DIDNotResolved);
    }

    #[tokio::test]
    async fn pack_signed_works_did_url_not_found() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_secrets_resolver()).pack_signed(
            &MESSAGE_SIMPLE,
            String::from(format!("{}#unknown-fragment", ALICE_DID)),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::DIDUrlNotFound);
    }

    #[tokio::test]
    async fn pack_signed_works_secret_not_found() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_secrets_resolver()).pack_signed(
            &MESSAGE_SIMPLE,
            String::from(format!("{}#key-not-in-secrets-1", ALICE_DID)),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::SecretNotFound);
    }

    #[tokio::test]
    async fn pack_signed_works_illegal_argument() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_secrets_resolver()).pack_signed(
            &MESSAGE_SIMPLE,
            String::from("not-a-did"),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::IllegalArgument);
    }
}
