#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// TODO: look for better solution
// Allows test vectors usage inside and outside crate
pub(crate) use didcomm;

use didcomm::{
    did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver, Message,
    PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{
    ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID,
    CHARLIE_DID_DOC, CHARLIE_SECRETS,
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
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_encrypted(
            BOB_DID,
            Some(ALICE_DID),
            Some(ALICE_DID),
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
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg_bob, metadata_bob) = msg
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

    // --- Sending message to Bob ---
    println!("Sending message to Bob \n{}\n", msg_bob);
    println!("Encryption metadata for Bob is\n{:?}\n", metadata_bob);

    // --- Packing encrypted and authenticated message for Charlie---

    let (msg_charlie, metadata_charlie) = msg
        .pack_encrypted(
            CHARLIE_DID,
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

    // --- Sending message to Charlie ---
    println!("Sending message to Charlie \n{}\n", msg_charlie);
    println!(
        "Encryption metadata for Charlie is\n{:?}\n",
        metadata_charlie
    );

    // --- Unpacking message for Bob ---
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg_bob,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions {
            ..UnpackOptions::default()
        },
    )
    .await
    .expect("Unable unpack");

    println!("Bob received message is \n{:?}\n", msg);
    println!("Bob received message unpack metadata is \n{:?}\n", metadata);

    // --- Unpacking message for Charlie ---
    let did_resolver =
        ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);

    let secrets_resolver = ExampleSecretsResolver::new(CHARLIE_SECRETS.clone());

    let (msg, metadata) = Message::unpack(
        &msg_charlie,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions {
            ..UnpackOptions::default()
        },
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
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);
    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_encrypted(
            BOB_DID,
            None,
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
