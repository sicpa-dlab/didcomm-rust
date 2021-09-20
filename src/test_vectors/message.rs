use serde_json::json;

use crate::{
    test_vectors::common::{ALICE_DID, BOB_DID},
    Attachment, Message, MessageBuilder,
};

pub(crate) fn message_simple() -> Message {
    _message().finalize()
}

pub(crate) fn message_minimal() -> Message {
    Message::build(
        "1234567890".to_owned(),
        "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
        json!({}),
    )
    .finalize()
}

pub(crate) fn message_attachment_base64() -> Message {
    _message()
        .attachement(
            Attachment::base64("qwerty".to_owned())
                .id("23".to_owned())
                .finalize(),
        )
        .finalize()
}

pub(crate) fn message_attachment_links() -> Message {
    _message()
        .attachement(
            Attachment::links(
                ["1".to_owned(), "2".to_owned(), "3".to_owned()].into(),
                "qwerty".into(),
            )
            .id("23".to_owned())
            .finalize(),
        )
        .finalize()
}

pub(crate) fn message_attachment_json() -> Message {
    _message()
        .attachement(
            Attachment::json(json!({"foo": "bar", "links": [2, 3]}))
                .id("23".to_owned())
                .finalize(),
        )
        .finalize()
}

pub(crate) fn message_attachment_multi_1() -> Message {
    _message()
        .attachements(
            [
                Attachment::json(json!({"foo": "bar", "links": [2, 3]}))
                    .id("23".to_owned())
                    .finalize(),
                Attachment::base64("qwerty".to_owned())
                    .id("24".to_owned())
                    .finalize(),
                Attachment::links(
                    ["1".to_owned(), "2".to_owned(), "3".to_owned()].into(),
                    "qwerty".into(),
                )
                .id("25".to_owned())
                .finalize(),
            ]
            .into(),
        )
        .finalize()
}

pub(crate) fn message_attachment_multi_2() -> Message {
    _message()
        .attachements(
            [
                Attachment::links(
                    ["1".to_owned(), "2".to_owned(), "3".to_owned()].into(),
                    "qwerty".into(),
                )
                .id("23".to_owned())
                .finalize(),
                Attachment::base64("qwerty".to_owned())
                    .id("24".to_owned())
                    .finalize(),
                Attachment::links(
                    [
                        "1".to_owned(),
                        "2".to_owned(),
                        "3".to_owned(),
                        "4".to_owned(),
                    ]
                    .into(),
                    "qwerty2".into(),
                )
                .id("25".to_owned())
                .finalize(),
            ]
            .into(),
        )
        .finalize()
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
