use didcomm::{Message, MessageBuilder};
use serde_json::json;

pub(crate) const ALICE_DID: &str = "did:example:alice";
pub(crate) const BOB_DID: &str = "did:example:bob";
pub(crate) const CHARLIE_DID: &str = "did:example:charlie";

pub(crate) fn simple_message() -> Message {
    _message().finalize()
}

fn _message() -> MessageBuilder {
    Message::build(
        "1234567890".to_owned(),
        "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
        json!({"messagespecificattribute": "and its value"}),
    )
    .from(ALICE_DID.to_owned())
    .to(BOB_DID.to_owned())
    .created_time(1516269022)
    .expires_time(1516385931)
}
