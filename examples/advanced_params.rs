#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// TODO: look for better solution
// Allows test vectors usage inside and outside crate
pub(crate) use didcomm;

use didcomm::algorithms::AnonCryptAlg;
use didcomm::{
    did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver, Message,
    PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use std::collections::HashMap;
use test_vectors::{ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .from(ALICE_DID.to_owned())
    .to(BOB_DID.to_owned())
    .created_time(1516269022)
    .expires_time(1516385931)
    .finalize();

    // --- Packing encrypted and authenticated message ---
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    //TODO: messaging_service is always None
    let (msg, metadata) = msg
        .pack_encrypted(
            "did:example:bob#key-p256-1",
            "did:example:alice#key-p256-1".into(),
            "did:example:alice#key-2".into(),
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions {
                forward: false, // Forward wrapping is unsupported in current version
                protect_sender: true,
                enc_alg_anon: AnonCryptAlg::A256gcmEcdhEsA256kw,
                forward_headers: Some(HashMap::from([("expires_time".to_string(), json!(99999))])),
                messaging_service: Some("did:example:bob#didcomm-1".to_string()),
                enc_alg_auth: Default::default(),
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
