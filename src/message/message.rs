use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::Attachment;
use crate::error::{err_msg, ErrorKind, Result, ToResult};

///  Wrapper for plain message. Provides helpers for message building and packing/unpacking.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Message {
    /// Message id. Must be unique to the sender.
    pub id: String,

    /// Must be "application/didcomm-plain+json"
    pub typ: String,

    /// Message type attribute value MUST be a valid Message Type URI,
    /// that when resolved gives human readable information about the message.
    /// The attribute’s value also informs the content of the message,
    /// or example the presence of other attributes and how they should be processed.
    #[serde(rename = "type")]
    pub type_: String,

    /// Message body.
    pub body: Value,

    /// Sender identifier. The from attribute MUST be a string that is a valid DID
    /// or DID URL (without the fragment component) which identifies the sender of the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    /// Identifier(s) for recipients. MUST be an array of strings where each element
    /// is a valid DID or DID URL (without the fragment component) that identifies a member
    /// of the message’s intended audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,

    /// Uniquely identifies the thread that the message belongs to.
    /// If not included the id property of the message MUST be treated as the value of the `thid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,

    /// If the message is a child of a thread the `pthid`
    /// will uniquely identify which thread is the parent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,

    /// Custom message headers.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra_headers: HashMap<String, Value>,

    /// The attribute is used for the sender
    /// to express when they created the message, expressed in
    /// UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
    /// This attribute is informative to the recipient, and may be relied on by protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<u64>,

    /// The expires_time attribute is used for the sender to express when they consider
    /// the message to be expired, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
    /// This attribute signals when the message is considered no longer valid by the sender.
    /// When omitted, the message is considered to have no expiration by the sender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<u64>,

    /// from_prior is a compactly serialized signed JWT containing FromPrior value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_prior: Option<String>,

    /// Message attachments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Attachment>>,
}

const PLAINTEXT_TYP: &str = "application/didcomm-plain+json";

impl Message {
    pub fn build(id: String, type_: String, body: Value) -> MessageBuilder {
        MessageBuilder::new(id, type_, body)
    }

    pub(crate) fn from_str(s: &str) -> Result<Message> {
        serde_json::from_str(s).to_didcomm("Unable deserialize jwm")
    }

    pub fn validate(self) -> Result<Self> {
        if self.typ != PLAINTEXT_TYP {
            Err(err_msg(
                ErrorKind::Malformed,
                format!("`typ` must be \"{}\"", PLAINTEXT_TYP),
            ))?;
        }
        Ok(self)
    }
}

pub struct MessageBuilder {
    id: String,
    type_: String,
    body: Value,
    from: Option<String>,
    to: Option<Vec<String>>,
    thid: Option<String>,
    pthid: Option<String>,
    extra_headers: HashMap<String, Value>,
    created_time: Option<u64>,
    expires_time: Option<u64>,
    from_prior: Option<String>,
    attachments: Option<Vec<Attachment>>,
}

impl MessageBuilder {
    fn new(id: String, type_: String, body: Value) -> Self {
        MessageBuilder {
            id,
            type_,
            body,
            from: None,
            to: None,
            thid: None,
            pthid: None,
            extra_headers: HashMap::new(),
            created_time: None,
            expires_time: None,
            from_prior: None,
            attachments: None,
        }
    }

    pub fn to(mut self, to: String) -> Self {
        if let Some(ref mut sto) = self.to {
            sto.push(to);
            self
        } else {
            self.to = Some(vec![to]);
            self
        }
    }

    pub fn to_many(mut self, to: Vec<String>) -> Self {
        if let Some(ref mut sto) = self.to {
            let mut to = to;
            sto.append(&mut to);
            self
        } else {
            self.to = Some(to);
            self
        }
    }

    pub fn from(mut self, from: String) -> Self {
        self.from = Some(from);
        self
    }

    pub fn thid(mut self, thid: String) -> Self {
        self.thid = Some(thid);
        self
    }

    pub fn pthid(mut self, pthid: String) -> Self {
        self.pthid = Some(pthid);
        self
    }

    pub fn header(mut self, key: String, value: Value) -> Self {
        self.extra_headers.insert(key, value);
        self
    }

    pub fn created_time(mut self, created_time: u64) -> Self {
        self.created_time = Some(created_time);
        self
    }

    pub fn expires_time(mut self, expires_time: u64) -> Self {
        self.expires_time = Some(expires_time);
        self
    }

    pub fn from_prior(mut self, from_prior: String) -> Self {
        self.from_prior = Some(from_prior);
        self
    }

    pub fn attachment(mut self, attachment: Attachment) -> Self {
        if let Some(ref mut attachments) = self.attachments {
            attachments.push(attachment);
            self
        } else {
            self.attachments = Some(vec![attachment]);
            self
        }
    }

    pub fn attachments(mut self, attachments: Vec<Attachment>) -> Self {
        if let Some(ref mut sattachments) = self.attachments {
            let mut attachments = attachments;
            sattachments.append(&mut attachments);
            self
        } else {
            self.attachments = Some(attachments);
            self
        }
    }

    pub fn finalize(self) -> Message {
        Message {
            id: self.id,
            typ: PLAINTEXT_TYP.to_owned(),
            type_: self.type_,
            body: self.body,
            to: self.to,
            thid: self.thid,
            pthid: self.pthid,
            from: self.from,
            extra_headers: self.extra_headers,
            created_time: self.created_time,
            expires_time: self.expires_time,
            from_prior: self.from_prior,
            attachments: self.attachments,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn message_build_works() {
        let message = Message::build(
            "example-1".into(),
            "example/v1".into(),
            json!("example-body"),
        )
        .to("did:example:1".into())
        .to_many(vec!["did:example:2".into(), "did:example:3".into()])
        .from("did:example:4".into())
        .thid("example-thread-1".into())
        .pthid("example-parent-thread-1".into())
        .header("example-header-1".into(), json!("example-header-1-value"))
        .header("example-header-2".into(), json!("example-header-2-value"))
        .created_time(10000)
        .expires_time(20000)
        .attachment(
            Attachment::base64("ZXhhbXBsZQ==".into())
                .id("attachment1".into())
                .finalize(),
        )
        .attachments(vec![
            Attachment::json(json!("example"))
                .id("attachment2".into())
                .finalize(),
            Attachment::json(json!("example"))
                .id("attachment3".into())
                .finalize(),
        ])
        .finalize();

        assert_eq!(message.id, "example-1");
        assert_eq!(message.typ, "application/didcomm-plain+json");
        assert_eq!(message.type_, "example/v1");
        assert_eq!(message.body, json!("example-body"));
        assert_eq!(message.from, Some("did:example:4".into()));
        assert_eq!(message.thid, Some("example-thread-1".into()));
        assert_eq!(message.pthid, Some("example-parent-thread-1".into()));
        assert_eq!(message.created_time, Some(10000));
        assert_eq!(message.expires_time, Some(20000));

        assert_eq!(
            message.to,
            Some(vec![
                "did:example:1".into(),
                "did:example:2".into(),
                "did:example:3".into()
            ])
        );

        let extra_headers = message.extra_headers;
        assert_eq!(extra_headers.len(), 2);

        assert!(extra_headers.contains_key(&"example-header-1".to_owned()));

        assert_eq!(
            extra_headers[&"example-header-1".to_owned()],
            "example-header-1-value"
        );

        assert!(extra_headers.contains_key(&"example-header-2".to_owned()));

        assert_eq!(
            extra_headers[&"example-header-2".to_owned()],
            "example-header-2-value"
        );

        let attachments = message.attachments.expect("attachments is some.");
        assert_eq!(attachments.len(), 3);
        assert_eq!(attachments[0].id, Some("attachment1".into()));
        assert_eq!(attachments[1].id, Some("attachment2".into()));
        assert_eq!(attachments[2].id, Some("attachment3".into()));
    }
}
