use didcomm_core::error::ErrorKind;
use didcomm_core::{Message, PackEncryptedMetadata, PackEncryptedOptions};

use crate::common::{ErrorCode, EXECUTOR};
use crate::did_resolver_adapter::DIDResolverAdapter;
use crate::secrets::kms_adapter::KeyManagementServiceAdapter;
use crate::DIDComm;

pub trait OnPackEncryptedResult: Sync + Send {
    fn success(&self, result: String, metadata: PackEncryptedMetadata);
    fn error(&self, err: ErrorKind, err_msg: String);
}

impl DIDComm {
    pub fn pack_encrypted<'a, 'b>(
        &self,
        msg: &'a Message,
        to: String,
        from: Option<String>,
        sign_by: Option<String>,
        options: &'b PackEncryptedOptions,
        cb: Box<dyn OnPackEncryptedResult>,
    ) -> ErrorCode {
        let msg = msg.clone();
        let options = options.clone();
        let did_resolver = DIDResolverAdapter::new(self.did_resolver.clone());
        let kms = KeyManagementServiceAdapter::new(self.kms.clone());

        let future = async move {
            msg.pack_encrypted(
                &to,
                from.as_deref(),
                sign_by.as_deref(),
                &did_resolver,
                &kms,
                &options,
            )
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
    use crate::test_helper::{create_did_resolver, create_kms, get_error, get_ok, PackResult};
    use crate::DIDComm;
    use didcomm_core::error::ErrorKind;
    use didcomm_core::test_vectors::{ALICE_DID, BOB_DID, MESSAGE_SIMPLE};
    use didcomm_core::{Message, PackEncryptedOptions};
    use serde_json::json;

    #[tokio::test]
    async fn pack_encrypted_works() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_kms()).pack_encrypted(
            &MESSAGE_SIMPLE,
            String::from(BOB_DID),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions::default(),
            cb,
        );

        let res = get_ok(receiver).await;
        assert!(res.contains("ciphertext"));
    }

    #[tokio::test]
    async fn pack_encrypted_works_did_not_found() {
        let msg = Message::build(
            "example-1".to_owned(),
            "example/v1".to_owned(),
            json!("example-body"),
        )
        .to(String::from("did:unknown:bob"))
        .from(ALICE_DID.to_owned())
        .finalize();

        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_kms()).pack_encrypted(
            &msg,
            String::from("did:unknown:bob"),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions::default(),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::DIDNotResolved);
    }

    #[tokio::test]
    async fn pack_encrypted_works_did_url_not_found() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_kms()).pack_encrypted(
            &MESSAGE_SIMPLE,
            String::from(format!("{}#unknown-fragment", BOB_DID)),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions::default(),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::DIDUrlNotFound);
    }

    #[tokio::test]
    async fn pack_encrypted_works_secret_not_found() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_kms()).pack_encrypted(
            &MESSAGE_SIMPLE,
            String::from(BOB_DID),
            Some(String::from(format!(
                "{}#key-x25519-not-in-secrets-1",
                ALICE_DID
            ))),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions::default(),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::SecretNotFound);
    }

    #[tokio::test]
    async fn pack_encrypted_works_illegal_argument() {
        let (cb, receiver) = PackResult::new();

        DIDComm::new(create_did_resolver(), create_kms()).pack_encrypted(
            &MESSAGE_SIMPLE,
            String::from("not-a-did"),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions::default(),
            cb,
        );

        let res = get_error(receiver).await;
        assert_eq!(res.kind(), ErrorKind::IllegalArgument);
    }
}
