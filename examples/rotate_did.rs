#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// TODO: look for better solution
// Allows test vectors usage inside and outside crate
pub(crate) use didcomm;

use didcomm::{
    did::resolvers::ExampleDIDResolver, protocols::routing::try_parse_forward,
    secrets::resolvers::ExampleKMS, FromPrior, Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{
    ALICE_DID, ALICE_DID_DOC, BOB_DID, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID, CHARLIE_DID_DOC,
    CHARLIE_ROTATED_TO_ALICE_SECRETS, MEDIATOR1_DID_DOC, MEDIATOR1_SECRETS,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleKMS::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());

    // --- Building from_prior header
    let from_prior = FromPrior::build(CHARLIE_DID.into(), ALICE_DID.into())
        .aud("123".into())
        .exp(1234)
        .nbf(12345)
        .iat(123456)
        .jti("dfg".into())
        .finalize();

    println!("Original from_prior is\n{:?}\n", from_prior);

    let (from_prior, issuer_kid) = from_prior
        .pack(None, &did_resolver, &secrets_resolver)
        .await
        .expect("Unable pack from_prior");

    println!("Packed from_prior is\n{}\n", from_prior);
    println!("from_prior issuer kid is\n{}\n", issuer_kid);

    // --- Building message from ALICE (ex-CHARLIE) to BOB ---
    let msg = Message::build(
        "1234567890".to_owned(),
        "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
        json!({"messagespecificattribute": "and its value"}),
    )
    .from(ALICE_DID.to_owned())
    .to(BOB_DID.to_owned())
    .created_time(1516269022)
    .expires_time(1516385931)
    .from_prior(from_prior)
    .finalize();

    println!("Original message is\n{:?}\n", msg);

    // --- Packing encrypted and authenticated message ---
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
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleKMS::new(MEDIATOR1_SECRETS.clone());

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
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleKMS::new(BOB_SECRETS.clone());

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
