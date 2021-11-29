#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// TODO: look for better solution
// Allows test vectors usage inside and outside crate
pub(crate) use didcomm;

use didcomm::{
    algorithms::AnonCryptAlg,
    did::resolvers::ExampleDIDResolver,
    protocols::routing::{try_parse_forward, wrap_in_forward},
    secrets::resolvers::ExampleSecretsResolver,
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{
    ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID,
    CHARLIE_DID_DOC, CHARLIE_SECRETS, MEDIATOR1_DID_DOC, MEDIATOR1_SECRETS, MEDIATOR2_DID_DOC,
    MEDIATOR2_SECRETS, MEDIATOR3_DID_DOC, MEDIATOR3_SECRETS,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=================== SINGLE MEDIATOR ===================");
    single_mediator().await;

    println!(
        "=================== MULTIPLE MEDIATORS WITH ALTERNATIVE ENDPOINTS ==================="
    );
    multiple_mediators_with_alternative_endpoints().await;

    println!("=================== REWRAPPING FOR FINAL RECIPIENT ===================");
    re_wrapping_for_final_recipient().await;

    println!("=================== REWRAPPING FOR MEDIATOR UNKNOWN TO SENDER ===================");
    re_wrapping_for_mediator_unknown_to_sender().await;
}

async fn single_mediator() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
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
            BOB_DID,
            Some(ALICE_DID),
            None,
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
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

async fn multiple_mediators_with_alternative_endpoints() {
    // --- Building message from ALICE to CHARLIE ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to(CHARLIE_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // --- Packing encrypted and authenticated message ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_encrypted(
            CHARLIE_DID,
            Some(ALICE_DID),
            None,
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Unable pack_encrypted");

    println!("Encryption metadata is\n{:?}\n", metadata);

    // --- Sending message by Alice ---
    println!("Alice is sending message \n{}\n", msg);

    // --- Unpacking message by Mediator3 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(MEDIATOR3_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Mediator3 received message is \n{:?}\n", msg);

    println!(
        "Mediator3 received message unpack metadata is \n{:?}\n",
        metadata
    );

    // --- Forwarding message by Mediator3 ---
    let msg = serde_json::to_string(&try_parse_forward(&msg).unwrap().forwarded_msg).unwrap();

    println!("Mediator3 is forwarding message \n{}\n", msg);

    // --- Unpacking message by Mediator2 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(MEDIATOR2_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Mediator2 received message is \n{:?}\n", msg);

    println!(
        "Mediator2 received message unpack metadata is \n{:?}\n",
        metadata
    );

    // --- Forwarding message by Mediator2 ---
    let msg = serde_json::to_string(&try_parse_forward(&msg).unwrap().forwarded_msg).unwrap();

    println!("Mediator2 is forwarding message \n{}\n", msg);

    // --- Unpacking message by Mediator1 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
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

    // --- Unpacking message by Charlie ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(CHARLIE_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Charlie received message is \n{:?}\n", msg);
    println!(
        "Charlie received message unpack metadata is \n{:?}\n",
        metadata
    );
}

async fn re_wrapping_for_final_recipient() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
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
            BOB_DID,
            Some(ALICE_DID),
            None,
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
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

    // --- Re-wrapping forwarded message for final recipient by Mediator1 ---
    let parsed_forward = try_parse_forward(&msg).unwrap();
    let msg = serde_json::to_string(&parsed_forward.forwarded_msg).unwrap();

    println!("Mediator1 retrieved forwarded message \n{}\n", msg);

    let msg = wrap_in_forward(
        &msg,
        None,
        &parsed_forward.next,
        &vec![parsed_forward.next.clone()],
        &AnonCryptAlg::default(),
        &did_resolver,
    )
    .await
    .expect("Unable wrap in forward");

    // --- Forwarding re-wrapped message by Mediator1 ---
    println!(
        "Mediator1 is forwarding re-wrapped message to final recipient \n{}\n",
        msg
    );

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

async fn re_wrapping_for_mediator_unknown_to_sender() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // --- Packing encrypted and authenticated message ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_encrypted(
            BOB_DID,
            Some(ALICE_DID),
            None,
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
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
        MEDIATOR2_DID_DOC.clone(),
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

    // --- Re-wrapping forwarded message for mediator unknown to sender by Mediator1 ---
    let parsed_forward = try_parse_forward(&msg).unwrap();
    let msg = serde_json::to_string(&parsed_forward.forwarded_msg).unwrap();

    println!("Mediator1 retrieved forwarded message \n{}\n", msg);

    let msg = wrap_in_forward(
        &msg,
        None,
        &parsed_forward.next,
        &vec!["did:example:mediator2#key-x25519-1".to_owned()],
        &AnonCryptAlg::default(),
        &did_resolver,
    )
    .await
    .expect("Unable wrap in forward");

    // --- Forwarding re-wrapped message by Mediator1 ---
    println!(
        "Mediator1 is forwarding re-wrapped message to mediator unknown to sender \n{}\n",
        msg
    );

    // --- Unpacking message by Mediator2 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(MEDIATOR2_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Mediator2 received message is \n{:?}\n", msg);
    println!(
        "Mediator2 received message unpack metadata is \n{:?}\n",
        metadata
    );

    // --- Forwarding message by Mediator2 ---
    let msg = serde_json::to_string(&try_parse_forward(&msg).unwrap().forwarded_msg).unwrap();

    println!("Mediator2 is forwarding message \n{}\n", msg);

    // --- Unpacking message by Bob ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
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
