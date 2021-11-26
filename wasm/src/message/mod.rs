mod from_prior;
mod pack_encrypted;
mod pack_plaintext;
mod pack_signed;
mod unpack;
mod protocols;

use didcomm::error::{ErrorKind, ResultExt};
use std::rc::Rc;
use wasm_bindgen::prelude::*;

use crate::{error::JsResult, utils::set_panic_hook};
pub use from_prior::FromPrior;

#[wasm_bindgen]
/// Wrapper for plain message. Provides helpers for message building and packing/unpacking.
pub struct Message(pub(crate) Rc<didcomm::Message>);

#[wasm_bindgen]
impl Message {
    #[wasm_bindgen(constructor)]
    /// Instantiates message from plain object
    pub fn new(value: IMessage) -> Result<Message, JsValue> {
        // TODO: Better place?
        set_panic_hook();

        let msg = value
            .into_serde()
            .kind(ErrorKind::Malformed, "Unable deserialize Message")
            .as_js()?;

        Ok(Message(Rc::new(msg)))
    }

    #[wasm_bindgen(skip_typescript)]
    pub fn as_value(&self) -> Result<JsValue, JsValue> {
        let msg = JsValue::from_serde(&*self.0)
            .kind(ErrorKind::Malformed, "Unable serialize Message")
            .as_js()?;

        Ok(msg)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_AS_VALUE_TS: &'static str = r#"
interface Message {
    /**
     * @returns message representation as plain object
     */
    as_value(): IMessage;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IMessage")]
    pub type IMessage;
}

#[wasm_bindgen(typescript_custom_section)]
const IMESSAGE_TS: &'static str = r#"
type IMessage = {
    /**
     * Message id. Must be unique to the sender.
     */
    id: string,

    /**
     * Must be "application/didcomm-plain+json"
     */
    typ: string,

    /**
     * Message type attribute value MUST be a valid Message Type URI,
     * that when resolved gives human readable information about the message.
     * The attribute’s value also informs the content of the message,
     * or example the presence of other attributes and how they should be processed.
     */
    type: string,

    /**
     * Message body.
     */
    body: any,

    /**
     * Sender identifier. The from attribute MUST be a string that is a valid DID
     * or DID URL (without the fragment component) which identifies the sender of the message.
     */
    from?: string,

    /**
     * Identifier(s) for recipients. MUST be an array of strings where each element
     * is a valid DID or DID URL (without the fragment component) that identifies a member
     * of the message’s intended audience.
     */
    to?: Array<string>,

    /**
     * Uniquely identifies the thread that the message belongs to.
     * If not included the id property of the message MUST be treated as the value of the `thid`.
     */
    thid?: string,

    /**
     * If the message is a child of a thread the `pthid`
     * will uniquely identify which thread is the parent.
     */
    pthid?: string,

    /**
     * Custom message headers.
     */
    [extra_header: string]: any

    /**
     * The attribute is used for the sender
     * to express when they created the message, expressed in
     * UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
     * This attribute is informative to the recipient, and may be relied on by protocols.
     */
    created_time?: number,

    /**
     * The expires_time attribute is used for the sender to express when they consider
     * the message to be expired, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
     * This attribute signals when the message is considered no longer valid by the sender.
     * When omitted, the message is considered to have no expiration by the sender.
     */
    expires_time?: number,

    /**
     * from_prior is a compactly serialized signed JWT containing FromPrior value
     */
   from_prior?: string,

    /**
     * Message attachments
     */
    attachments?: Array<Attachment>,
};
"#;

#[wasm_bindgen(typescript_custom_section)]
const ATTACHMENT_TS: &'static str = r#"
type Attachment = {
    /**
     * A JSON object that gives access to the actual content of the attachment.
     * Can be based on base64, json or external links.
     */
    data: AttachmentData,

    /**
     * Identifies attached content within the scope of a given message.
     * Recommended on appended attachment descriptors. Possible but generally unused
     * on embedded attachment descriptors. Never required if no references to the attachment
     * exist; if omitted, then there is no way to refer to the attachment later in the thread,
     * in error messages, and so forth. Because id is used to compose URIs, it is recommended
     * that this name be brief and avoid spaces and other characters that require URI escaping.
     */
    id?: string,

    /**
     * A human-readable description of the content.
     */
    description?: string,

    /**
     * A hint about the name that might be used if this attachment is persisted as a file.
     * It is not required, and need not be unique. If this field is present and mime-type is not,
     * the extension on the filename may be used to infer a MIME type.
     */
    filename?: string,

    /**
     * Describes the MIME type of the attached content.
     */
    media_type?: string,

    /**
     * Describes the format of the attachment if the mime_type is not sufficient.
     */
    format?: string,

    /**
     * A hint about when the content in this attachment was last modified
     * in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
     */
    lastmod_time?: number,

    /**
     * Mostly relevant when content is included by reference instead of by value.
     * Lets the receiver guess how expensive it will be, in time, bandwidth, and storage,
     * to fully fetch the attachment.
     */
    byte_count?: number,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const ATTACHMENT_DATA_TS: &'static str = r#"
type AttachmentData = Base64AttachmentData | JsonAttachmentData | LinksAttachmentData
"#;

#[wasm_bindgen(typescript_custom_section)]
const BASE64_ATTACHMENT_DATA_TS: &'static str = r#"
type Base64AttachmentData = {
    /**
     * Base64-encoded data, when representing arbitrary content inline.
     */
    base64: string,

    /**
     * A JSON Web Signature over the content of the attachment.
     */
    jws?: string,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const JSON_ATTACHMENT_DATA_TS: &'static str = r#"
type JsonAttachmentData = {
    /**
     * Directly embedded JSON data.
     */
    json: any,

    /**
     * A JSON Web Signature over the content of the attachment.
     */
    jws?: string,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const LINKS_ATTACHMENT_DATA_TS: &'static str = r#"
type LinksAttachmentData = {
    /**
     * A list of one or more locations at which the content may be fetched.
     */
    links: Array<string>,

    /**
     * The hash of the content encoded in multi-hash format. Used as an integrity check for the attachment.
     */
    hash: string,

    /**
     * A JSON Web Signature over the content of the attachment.
     */
    jws?: string,
}
"#;
