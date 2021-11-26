#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// TODO: look for better solution
// Allows test vectors usage inside and outside crate
pub(crate) use didcomm;

use didcomm::{
    did::resolvers::ExampleDIDResolver, protocols::routing::try_parse_forward,
    secrets::resolvers::ExampleSecretsResolver, Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{
    ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID,
    CHARLIE_DID_DOC, CHARLIE_SECRETS, MEDIATOR1_DID_DOC, MEDIATOR1_SECRETS, MEDIATOR2_DID_DOC,
    MEDIATOR2_SECRETS, MEDIATOR3_DID_DOC, MEDIATOR3_SECRETS,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=================== NON REPUDIABLE ENCRYPTION ===================");
    non_repudiable_encryption().await;
    println!("=================== MULTI RECIPIENT ===================");
    multi_recipient().await;
    println!("=================== REPUDIABLE AUTHENTICATED ENCRYPTION ===================");
    repudiable_authenticated_encryption().await;
    println!("=================== REPUDIABLE NON AUTHENTICATED ENCRYPTION ===================");
    repudiable_non_authenticated_encryption().await;
    println!("=================== SIGNED UNENCRYPTED ===================");
    signed_unencrypted().await;
    println!("=================== PLAINTEXT UNENCRYPTED ===================");
    plaintext_unencrypted().await;
}

async fn non_repudiable_encryption() {
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
            Some(ALICE_DID),
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

async fn multi_recipient() {
    // --- Building message from ALICE to BOB and CHARLIE ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to_many(vec![BOB_DID.to_owned(), CHARLIE_DID.to_owned()])
    .from(ALICE_DID.to_owned())
    .finalize();

    // --- Packing encrypted and authenticated message for Bob ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg_bob, metadata_bob) = msg
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

    // --- Sending message by Alice to Bob ---
    println!("Alice is sending message to Bob \n{}\n", msg_bob);
    println!("Encryption metadata for Bob is\n{:?}\n", metadata_bob);

    // --- Packing encrypted and authenticated message for Charlie---

    let (msg_charlie, metadata_charlie) = msg
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

    // --- Sending message by Alice to Charlie ---
    println!("Alice is sending message to Charlie \n{}\n", msg_charlie);

    println!(
        "Encryption metadata for Charlie is\n{:?}\n",
        metadata_charlie
    );

    // --- Unpacking message for Bob by Mediator1 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(MEDIATOR1_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg_bob,
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
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
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

    // --- Unpacking message for Charlie by Mediator3 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(MEDIATOR3_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg_charlie,
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

    // --- Unpacking message for Charlie by Mediator2 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
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

    // --- Unpacking message for Charlie by Mediator1 ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
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
        BOB_DID_DOC.clone(),
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

async fn repudiable_authenticated_encryption() {
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

async fn repudiable_non_authenticated_encryption() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // --- Packing encrypted message ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_encrypted(
            BOB_DID,
            None,
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

async fn signed_unencrypted() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // --- Packing signed message ---
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_signed(ALICE_DID, &did_resolver, &secrets_resolver)
        .await
        .expect("Unable pack_signed");

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
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Received message is \n{:?}\n", msg);
    println!("Received message unpack metadata is \n{:?}\n", metadata);
}

async fn plaintext_unencrypted() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // --- Packing plaintext message ---
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

    let msg = msg
        .pack_plaintext(&did_resolver)
        .await
        .expect("Unable pack_plaintext");

    // --- Sending message ---
    println!("Sending message \n{}\n", msg);

    // --- Unpacking message ---
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Received message is \n{:?}\n", msg);
    println!("Received message unpack metadata is \n{:?}\n", metadata);
}
