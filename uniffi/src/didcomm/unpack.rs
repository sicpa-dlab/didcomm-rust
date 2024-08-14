use didcomm_core::{error::ErrorKind, Message, UnpackMetadata, UnpackOptions};

use crate::common::EXECUTOR;
use crate::did_resolver_adapter::DIDResolverAdapter;
use crate::DIDComm;
use crate::{kms_adapter::KeyManagementServiceAdapter, ErrorCode};

pub trait OnUnpackResult: Sync + Send {
    fn success(&self, result: Message, metadata: UnpackMetadata);
    fn error(&self, err: ErrorKind, err_msg: String);
}

impl DIDComm {
    pub fn unpack<'a>(
        &self,
        msg: String,
        options: &'a UnpackOptions,
        cb: Box<dyn OnUnpackResult>,
    ) -> ErrorCode {
        let msg = msg.clone();
        let options = options.clone();
        let did_resolver = DIDResolverAdapter::new(self.did_resolver.clone());
        let kms = KeyManagementServiceAdapter::new(self.kms.clone());

        let future = async move { Message::unpack(&msg, &did_resolver, &kms, &options).await };
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
    use crate::test_helper::{
        create_did_resolver, create_kms, get_error, get_ok, PackResult, UnpackResult,
    };
    use crate::DIDComm;
    use didcomm_core::error::ErrorKind;
    use didcomm_core::{PackEncryptedOptions, UnpackOptions};

    use didcomm_core::test_vectors::{ALICE_DID, BOB_DID, MESSAGE_SIMPLE};

    #[tokio::test]
    async fn unpack_works_plaintext() {
        let msg = MESSAGE_SIMPLE.clone();
        let didcomm = DIDComm::new(create_did_resolver(), create_kms());

        let (cb, receiver) = PackResult::new();
        didcomm.pack_plaintext(&MESSAGE_SIMPLE, cb);
        let res = get_ok(receiver).await;

        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(res, &UnpackOptions::default(), cb);
        let res = get_ok(receiver).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_signed() {
        let msg = MESSAGE_SIMPLE.clone();
        let didcomm = DIDComm::new(create_did_resolver(), create_kms());

        let (cb, receiver) = PackResult::new();
        didcomm.pack_signed(&msg, String::from(ALICE_DID), cb);
        let res = get_ok(receiver).await;

        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(res, &UnpackOptions::default(), cb);
        let res = get_ok(receiver).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_encrypted() {
        let msg = MESSAGE_SIMPLE.clone();
        let didcomm = DIDComm::new(create_did_resolver(), create_kms());

        let (cb, receiver) = PackResult::new();
        didcomm.pack_encrypted(
            &msg,
            String::from(BOB_DID),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions {
                forward: false,
                ..PackEncryptedOptions::default()
            },
            cb,
        );
        let res = get_ok(receiver).await;

        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(res, &UnpackOptions::default(), cb);
        let res = get_ok(receiver).await;

        assert_eq!(res, msg);
    }

    #[tokio::test]
    async fn unpack_works_malformed() {
        let (cb, receiver) = UnpackResult::new();
        DIDComm::new(create_did_resolver(), create_kms()).unpack(
            String::from("invalid message"),
            &UnpackOptions::default(),
            cb,
        );
        let res = get_error(receiver).await;

        assert_eq!(res.kind(), ErrorKind::Malformed);
    }
}
