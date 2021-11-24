use lazy_static::lazy_static;
use serde_json::json;

use super::common::{ALICE_DID, BOB_DID};
use crate::didcomm::{Attachment, Message, MessageBuilder};

lazy_static! {
    pub(crate) static ref MESSAGE_SIMPLE: Message = _message().finalize();
}

lazy_static! {
    pub(crate) static ref MESSAGE_MINIMAL: Message = Message::build(
        "1234567890".to_owned(),
        "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
        json!({}),
    )
    .finalize();
}

lazy_static! {
    pub(crate) static ref MESSAGE_FROM_PRIOR_FULL: Message = _message()
        .from_prior("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOmNoYXJsaWUja2V5LTEifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpjaGFybGllIiwic3ViIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJhdWQiOiIxMjMiLCJleHAiOjEyMzQsIm5iZiI6MTIzNDUsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.ir0tegXiGJIZIMagO5P853KwhzGTEw0OpFFAyarUV-nQrtbI_ELbxT9l7jPBoPve_-60ifGJ9v3ArmFjELFlDA".into())
        .finalize();
}

lazy_static! {
    pub(crate) static ref MESSAGE_FROM_PRIOR_MISMATCHED_SUB_AND_FROM: Message =
        Message::build(
            "1234567890".to_owned(),
            "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
            json!({"messagespecificattribute": "and its value"}),
        )
        .from(BOB_DID.to_owned())
        .to(ALICE_DID.to_owned())
        .created_time(1516269022)
        .expires_time(1516385931)
        .from_prior("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOmNoYXJsaWUja2V5LTEifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpjaGFybGllIiwic3ViIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJhdWQiOiIxMjMiLCJleHAiOjEyMzQsIm5iZiI6MTIzNDUsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.ir0tegXiGJIZIMagO5P853KwhzGTEw0OpFFAyarUV-nQrtbI_ELbxT9l7jPBoPve_-60ifGJ9v3ArmFjELFlDA".into())
        .finalize();
}

lazy_static! {
    pub(crate) static ref MESSAGE_ATTACHMENT_BASE64: Message = _message()
        .attachement(
            Attachment::base64("qwerty".to_owned())
                .id("23".to_owned())
                .finalize(),
        )
        .finalize();
}

lazy_static! {
    pub(crate) static ref MESSAGE_ATTACHMENT_LINKS: Message = _message()
        .attachement(
            Attachment::links(
                ["1".to_owned(), "2".to_owned(), "3".to_owned()].into(),
                "qwerty".into(),
            )
            .id("23".to_owned())
            .finalize(),
        )
        .finalize();
}

lazy_static! {
    pub(crate) static ref MESSAGE_ATTACHMENT_JSON: Message = _message()
        .attachement(
            Attachment::json(json!({"foo": "bar", "links": [2, 3]}))
                .id("23".to_owned())
                .finalize(),
        )
        .finalize();
}

lazy_static! {
    pub(crate) static ref MESSAGE_ATTACHMENT_MULTI_1: Message = _message()
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
        .finalize();
}

lazy_static! {
    pub(crate) static ref MESSAGE_ATTACHMENT_MULTI_2: Message = _message()
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
        .finalize();
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
