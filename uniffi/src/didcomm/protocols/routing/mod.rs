use std::collections::HashMap;

use didcomm_core::{
    algorithms::AnonCryptAlg, error::ErrorKind, protocols::routing::wrap_in_forward,
};
use serde_json::Value;

use crate::common::EXECUTOR;
use crate::{did_resolver_adapter::FFIDIDResolverAdapter, DIDComm, ErrorCode};

pub trait OnWrapInForwardResult: Sync + Send {
    fn success(&self, result: String);
    fn error(&self, err: ErrorKind, err_msg: String);
}

impl DIDComm {
    pub fn wrap_in_forward(
        &self,
        msg: String,
        headers: &HashMap<String, Value>,
        to: String,
        routing_keys: &Vec<String>,
        enc_alg_anon: &AnonCryptAlg,
        cb: Box<dyn OnWrapInForwardResult>,
    ) -> ErrorCode {
        let did_resolver = FFIDIDResolverAdapter::new(self.did_resolver.clone());
        let headers = headers.clone();
        let routing_keys = routing_keys.clone();
        let enc_alg_anon = enc_alg_anon.clone();

        let future = async move {
            wrap_in_forward(
                &msg,
                Some(&headers),
                &to,
                &routing_keys,
                &enc_alg_anon,
                &did_resolver,
            )
            .await
        };

        EXECUTOR.spawn_ok(async move {
            match future.await {
                Ok(result) => cb.success(result),
                Err(err) => cb.error(err.kind(), err.to_string()),
            }
        });

        ErrorCode::Success
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;
    use std::iter::FromIterator;

    use crate::test_vectors::test_helper::{
        create_did_resolver, create_secrets_resolver, get_ok, PackResult, UnpackResult,
        WrapInForwardResult,
    };
    use crate::test_vectors::{
        simple_message, ALICE_DID, BOB_DID, CHARLIE_DID,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
    };
    use crate::DIDComm;
    use didcomm_core::algorithms::AnonCryptAlg;
    use didcomm_core::protocols::routing::try_parse_forward;
    use didcomm_core::{Message, PackEncryptedOptions, UnpackOptions};
    use serde_json::json;

    #[tokio::test]
    async fn pack_encrypted_works_single_mediator() {
        let didcomm = DIDComm::new(create_did_resolver(), create_secrets_resolver());
        let msg = simple_message();

        // ALICE
        let (cb, receiver) = PackResult::new();
        didcomm.pack_encrypted(
            &msg,
            String::from(BOB_DID),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions::default(),
            cb,
        );
        let packed = get_ok(receiver).await;

        // MEDIATOR 1
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(
            packed,
            &UnpackOptions {
                expect_decrypt_by_all_keys: true,
                unwrap_re_wrapping_forward: false,
            },
            cb,
        );
        let unpacked_mediator1 = get_ok(receiver).await;
        let forward = try_parse_forward(&unpacked_mediator1).expect("Message is not Forward");
        let forwarded_msg = serde_json::to_string(&forward.forwarded_msg)
            .expect("Unable serialize forwarded message");

        // BOB
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(forwarded_msg, &UnpackOptions::default(), cb);
        let unpacked_msg = get_ok(receiver).await;

        assert_eq!(unpacked_msg, msg);
    }

    #[tokio::test]
    async fn pack_encrypted_works_multiple_mediators_alternative_endpoints() {
        let didcomm = DIDComm::new(create_did_resolver(), create_secrets_resolver());
        let msg = Message::build(
            "1234567890".to_owned(),
            "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
            json!({"messagespecificattribute": "and its value"}),
        )
        .from(ALICE_DID.to_owned())
        .to(CHARLIE_DID.to_owned())
        .finalize();

        // ALICE
        let (cb, receiver) = PackResult::new();
        didcomm.pack_encrypted(
            &msg,
            String::from(CHARLIE_DID),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions::default(),
            cb,
        );
        let packed = get_ok(receiver).await;

        // MEDIATOR 3
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(
            packed,
            &UnpackOptions {
                expect_decrypt_by_all_keys: true,
                unwrap_re_wrapping_forward: false,
            },
            cb,
        );
        let unpacked_msg_mediator3 = get_ok(receiver).await;
        let forward_at_mediator3 =
            try_parse_forward(&unpacked_msg_mediator3).expect("Message is not Forward");
        let forward_msg_at_mediator3 = serde_json::to_string(&forward_at_mediator3.forwarded_msg)
            .expect("Unable serialize forwarded message");

        // MEDIATOR 2
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(
            forward_msg_at_mediator3,
            &UnpackOptions {
                expect_decrypt_by_all_keys: true,
                unwrap_re_wrapping_forward: false,
            },
            cb,
        );
        let unpacked_msg_mediator2 = get_ok(receiver).await;
        let forward_at_mediator2 =
            try_parse_forward(&unpacked_msg_mediator2).expect("Message is not Forward");
        let forward_msg_at_mediator2 = serde_json::to_string(&forward_at_mediator2.forwarded_msg)
            .expect("Unable serialize forwarded message");

        // MEDIATOR 1
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(
            forward_msg_at_mediator2,
            &UnpackOptions {
                expect_decrypt_by_all_keys: true,
                unwrap_re_wrapping_forward: false,
            },
            cb,
        );
        let unpacked_msg_mediator1 = get_ok(receiver).await;
        let forward_at_mediator1 =
            try_parse_forward(&unpacked_msg_mediator1).expect("Message is not Forward");
        let forward_msg_at_mediator1 = serde_json::to_string(&forward_at_mediator1.forwarded_msg)
            .expect("Unable serialize forwarded message");

        // CHARLIE
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(forward_msg_at_mediator1, &UnpackOptions::default(), cb);
        let unpacked_msg = get_ok(receiver).await;

        assert_eq!(unpacked_msg, msg);
    }

    #[tokio::test]
    async fn wrap_in_forward_works_mediator_unknown_by_sender() {
        let didcomm = DIDComm::new(create_did_resolver(), create_secrets_resolver());
        let msg = simple_message();

        // ALICE
        let (cb, receiver) = PackResult::new();
        didcomm.pack_encrypted(
            &msg,
            String::from(BOB_DID),
            Some(String::from(ALICE_DID)),
            Some(String::from(ALICE_DID)),
            &PackEncryptedOptions::default(),
            cb,
        );
        let packed = get_ok(receiver).await;

        // MEDIATOR 1
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(
            packed,
            &UnpackOptions {
                expect_decrypt_by_all_keys: true,
                unwrap_re_wrapping_forward: false,
            },
            cb,
        );
        let unpacked_mediator1 = get_ok(receiver).await;
        let forward_at_mediator1 =
            try_parse_forward(&unpacked_mediator1).expect("Message is not Forward");
        let forwarded_msg_at_mediator1 = serde_json::to_string(&forward_at_mediator1.forwarded_msg)
            .expect("Unable serialize forwarded message");

        let (cb, receiver) = WrapInForwardResult::new();
        didcomm.wrap_in_forward(
            forwarded_msg_at_mediator1,
            &HashMap::from_iter([
                ("example-header-1".into(), json!("example-header-1-value")),
                ("example-header-2".into(), json!("example-header-2-value")),
            ]),
            forward_at_mediator1.next,
            &vec![MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1.id.clone()],
            &AnonCryptAlg::default(),
            cb,
        );
        let msg_for_mediator2 = get_ok(receiver).await;

        // MEDIATOR 2
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(
            msg_for_mediator2,
            &UnpackOptions {
                expect_decrypt_by_all_keys: true,
                unwrap_re_wrapping_forward: false,
            },
            cb,
        );
        let unpacked_msg_mediator2 = get_ok(receiver).await;
        let forward_at_mediator2 =
            try_parse_forward(&unpacked_msg_mediator2).expect("Message is not Forward");
        let forwarded_msg_at_mediator2 = serde_json::to_string(&forward_at_mediator2.forwarded_msg)
            .expect("Unable serialize forwarded message");

        // BOB
        let (cb, receiver) = UnpackResult::new();
        didcomm.unpack(forwarded_msg_at_mediator2, &UnpackOptions::default(), cb);
        let unpacked_msg = get_ok(receiver).await;

        assert_eq!(unpacked_msg, msg);
    }
}
