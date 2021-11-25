#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// TODO: look for better solution
// Allows test vectors usage inside and outside crate
pub(crate) use didcomm;

use crate::didcomm::AttachmentData;
use didcomm::{
    did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver, Attachment,
    JsonAttachmentData, Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .attachment(Attachment {
        data: AttachmentData::Json {
            value: JsonAttachmentData {
                json: json!({"foo": "bar"}),
                jws: None,
            },
        },
        id: Some("123".to_string()),
        description: Some("example attachment".to_string()),
        filename: None,
        media_type: Some("application/didcomm-encrypted+json".to_string()),
        format: None,
        lastmod_time: None,
        byte_count: None,
    })
    .finalize();

    // --- Packing encrypted and authenticated message ---
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_encrypted(
            BOB_DID,
            Some(ALICE_DID),
            None,
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions {
                forward: false, // Forward wrapping is unsupported in current version
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .expect("Unable pack_encrypted");

    println!("Encryption metadata is\n{:?}\n", metadata);

    // --- Sending message ---
    println!("Sending message \n{}\n", msg);

    // --- Unpacking message ---
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions {
            ..UnpackOptions::default()
        },
    )
    .await
    .expect("Unable unpack");

    println!("Received message is \n{:?}\n", msg);
    println!("Received message unpack metadata is \n{:?}\n", metadata);
}
