#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// TODO: look for better solution
// Allows test vectors usage inside and outside crate
pub(crate) use didcomm;

use didcomm::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::resolvers::ExampleDIDResolver,
    protocols::routing::try_parse_forward,
    secrets::resolvers::ExampleSecretsResolver,
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use std::collections::HashMap;
use std::iter::FromIterator;
use test_vectors::{
    ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, MEDIATOR1_DID_DOC,
    MEDIATOR1_SECRETS,
};

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
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_encrypted(
            "did:example:bob#key-p256-1",
            "did:example:alice#key-p256-1".into(),
            "did:example:alice#key-2".into(),
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions {
                protect_sender: true,
                forward: true,
                forward_headers: Some(HashMap::from_iter([(
                    "expires_time".to_string(),
                    json!(99999),
                )])),
                messaging_service: Some("did:example:bob#didcomm-1".to_string()),
                enc_alg_auth: AuthCryptAlg::A256cbcHs512Ecdh1puA256kw,
                enc_alg_anon: AnonCryptAlg::A256gcmEcdhEsA256kw,
            },
        )
        .await
        .expect("Unable pack_encrypted");

    println!("Encryption metadata is\n{:?}\n", metadata);

    // --- Sending message by Alice ---
    println!("Alice is sending message \n{}\n", msg);

    // --- Unpacking message by Mediator1 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(MEDIATOR1_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Mediator1 received message is \n{:?}\n", msg);

    println!(
        "Mediator1 received message unpack metadata is \n{:?}\n",
        metadata
    );

    // --- Forwarding message by Mediator1 ---
    let msg = serde_json::to_string(&try_parse_forward(&msg).unwrap().forwarded_msg).unwrap();

    println!("Mediator1 is forwarding message \n{}\n", msg);

    // --- Unpacking message by Bob ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Bob received message is \n{:?}\n", msg);
    println!("Bob received message unpack metadata is \n{:?}\n", metadata);
}
