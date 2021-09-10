mod jwe;
mod jwk;
mod jws;
mod message;
mod pack_encrypted;
mod pack_plaintext;
mod pack_signed;
mod unpack;
mod utils;

pub mod algorithms;
pub mod did;
pub mod error;
pub mod secrets;

pub(crate) use askar_crypto as crypto;

pub use message::{
    Attachment, AttachmentBuilder, AttachmentData, Base64AttachmentData, JsonAttachmentData,
    LinksAttachmentData, Message, MessageBuilder,
};

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{
        did::resolvers::ExampleDIDResolver, pack_encrypted::PackEncryptedOptions,
        secrets::resolvers::ExampleSecretsResolver, unpack::UnpackOptions, Message,
    };

    #[tokio::test]
    #[ignore]
    // will be fixed after https://github.com/sicpa-dlab/didcomm-gemini/issues/71
    async fn demo_works() {
        // --- Build message ---

        let sender = "did:example:1";
        let recepient = "did:example:2";

        let msg = Message::build(
            "example-1".into(),
            "example/v1".into(),
            json!("example-body"),
        )
        .to(recepient.into())
        .from(sender.into())
        .finalize();

        // --- Packing message ---

        let sender_did_resolver = ExampleDIDResolver::new(vec![]);
        let sender_secrets_resolver = ExampleSecretsResolver::new(vec![]);

        let (packed_msg, metadata) = msg
            .pack_encrypted(
                recepient,
                Some(sender),
                None,
                &sender_did_resolver,
                &sender_secrets_resolver,
                &PackEncryptedOptions {
                    ..PackEncryptedOptions::default()
                },
            )
            .await
            .expect("pack is ok.");

        // --- Send message using service endpoint ---

        let service_endpoint = metadata
            .messaging_service
            .expect("messagin service present.")
            .service_endpoint;

        println!("Sending message {} throug {}", packed_msg, service_endpoint);

        // --- Unpacking message ---

        let recepient_did_resolver = ExampleDIDResolver::new(vec![]);
        let recepient_secrets_resolver = ExampleSecretsResolver::new(vec![]);

        let (msg, metadata) = Message::unpack(
            &packed_msg,
            &recepient_did_resolver,
            &recepient_secrets_resolver,
            &UnpackOptions {
                ..UnpackOptions::default()
            },
        )
        .await
        .expect("unpack is ok.");

        assert!(metadata.encrypted);
        assert!(metadata.authenticated);
        assert!(metadata.encrypted_from_kid.is_some());
        assert!(metadata.encrypted_from_kid.unwrap().starts_with(&recepient));

        assert_eq!(msg.from, Some(sender.into()));
        assert_eq!(msg.to, Some(vec![recepient.into()]));
        assert_eq!(msg.body, json!("example-body"));
    }
}
