use crate::{
    error::{ErrorKind, Result, ResultExt},
    Message,
};

impl Message {
    /// Produces `DIDComm Plaintext Messages`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages.
    ///
    /// A DIDComm message in its plaintext form, not packaged into any protective envelope,
    /// is known as a DIDComm plaintext message. Plaintext messages lack confidentiality and integrity
    /// guarantees, and are repudiable. They are therefore not normally transported across security boundaries.
    /// However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
    /// and it is the format used in this spec to give examples of headers and other internals.
    /// Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.
    ///
    /// # Returns
    /// - a DIDComm plaintext message s JSON string
    ///
    /// # Errors
    /// - InvalidState
    pub fn pack_plaintext(&self) -> Result<String> {
        serde_json::to_string(self).kind(ErrorKind::InvalidState, "Unable serialize message")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{
        test_vectors::{
            message::{
                message_attachment_base64, message_attachment_json, message_attachment_links,
                message_attachment_multi_1, message_attachment_multi_2, message_minimal,
                message_simple,
            },
            plaintext::{
                PLAINTEXT_MSG_ATTACHMENT_BASE64, PLAINTEXT_MSG_ATTACHMENT_JSON,
                PLAINTEXT_MSG_ATTACHMENT_LINKS, PLAINTEXT_MSG_ATTACHMENT_MULTI_1,
                PLAINTEXT_MSG_ATTACHMENT_MULTI_2, PLAINTEXT_MSG_MINIMAL, PLAINTEXT_MSG_SIMPLE,
            },
        },
        Message,
    };

    #[test]
    fn pack_plaintext_works() {
        _pack_plaintext_works(&message_simple(), PLAINTEXT_MSG_SIMPLE);
        _pack_plaintext_works(&message_minimal(), PLAINTEXT_MSG_MINIMAL);

        _pack_plaintext_works(
            &message_attachment_base64(),
            PLAINTEXT_MSG_ATTACHMENT_BASE64,
        );

        _pack_plaintext_works(&message_attachment_json(), PLAINTEXT_MSG_ATTACHMENT_JSON);
        _pack_plaintext_works(&message_attachment_links(), PLAINTEXT_MSG_ATTACHMENT_LINKS);

        _pack_plaintext_works(
            &message_attachment_multi_1(),
            PLAINTEXT_MSG_ATTACHMENT_MULTI_1,
        );

        _pack_plaintext_works(
            &message_attachment_multi_2(),
            PLAINTEXT_MSG_ATTACHMENT_MULTI_2,
        );

        fn _pack_plaintext_works(msg: &Message, exp_msg: &str) {
            let msg = msg.pack_plaintext().expect("Unable pack_plaintext");

            let msg: Value = serde_json::from_str(&msg).expect("Unable from_str");
            let exp_msg: Value = serde_json::from_str(exp_msg).expect("Unable from_str");
            assert_eq!(msg, exp_msg)
        }
    }
}
