use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Attachment {
    /// A JSON object that gives access to the actual content of the attachment.
    /// Can be based on base64, json or external links.
    pub data: AttachmentData,

    /// Identifies attached content within the scope of a given message.
    ///  Recommended on appended attachment descriptors. Possible but generally unused
    ///  on embedded attachment descriptors. Never required if no references to the attachment
    ///  exist; if omitted, then there is no way to refer to the attachment later in the thread,
    ///  in error messages, and so forth. Because id is used to compose URIs, it is recommended
    ///  that this name be brief and avoid spaces and other characters that require URI escaping.
    pub id: Option<String>,

    /// A human-readable description of the content.
    pub description: Option<String>,

    /// A hint about the name that might be used if this attachment is persisted as a file.
    /// It is not required, and need not be unique. If this field is present and mime-type is not,
    /// the extension on the filename may be used to infer a MIME type.
    pub filename: Option<String>,

    /// Describes the MIME type of the attached content.
    pub media_type: Option<String>,

    /// Describes the format of the attachment if the mime_type is not sufficient.
    pub format: Option<String>,

    /// A hint about when the content in this attachment was last modified
    /// in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
    pub lastmod_time: Option<u64>,

    /// Mostly relevant when content is included by reference instead of by value.
    /// Lets the receiver guess how expensive it will be, in time, bandwidth, and storage,
    /// to fully fetch the attachment.
    pub byte_count: Option<u64>,
}

impl Attachment {
    pub fn base64(base64: String) -> AttachmentBuilder {
        AttachmentBuilder::new(AttachmentData::Base64(Base64AttachmentData {
            base64,
            jws: None,
        }))
    }

    pub fn json(json: Value) -> AttachmentBuilder {
        AttachmentBuilder::new(AttachmentData::Json(JsonAttachmentData { json, jws: None }))
    }

    pub fn links(links: Vec<String>, hash: String) -> AttachmentBuilder {
        AttachmentBuilder::new(AttachmentData::Links(LinksAttachmentData {
            links,
            hash,
            jws: None,
        }))
    }
}

pub struct AttachmentBuilder {
    data: AttachmentData,
    id: Option<String>,
    description: Option<String>,
    filename: Option<String>,
    media_type: Option<String>,
    format: Option<String>,
    lastmod_time: Option<u64>,
    byte_count: Option<u64>,
}

impl AttachmentBuilder {
    fn new(data: AttachmentData) -> Self {
        AttachmentBuilder {
            data,
            id: None,
            description: None,
            filename: None,
            media_type: None,
            format: None,
            lastmod_time: None,
            byte_count: None,
        }
    }

    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn filename(mut self, filename: String) -> Self {
        self.filename = Some(filename);
        self
    }

    pub fn media_type(mut self, media_type: String) -> Self {
        self.media_type = Some(media_type);
        self
    }

    pub fn format(mut self, format: String) -> Self {
        self.format = Some(format);
        self
    }

    pub fn lastmod_time(mut self, lastmod_time: u64) -> Self {
        self.lastmod_time = Some(lastmod_time);
        self
    }

    pub fn byte_count(mut self, byte_count: u64) -> Self {
        self.byte_count = Some(byte_count);
        self
    }

    pub fn jws(mut self, jws: String) -> Self {
        match self.data {
            AttachmentData::Base64(ref mut data) => data.jws = Some(jws),
            AttachmentData::Json(ref mut data) => data.jws = Some(jws),
            AttachmentData::Links(ref mut data) => data.jws = Some(jws),
        }

        self
    }

    pub fn finalize(self) -> Attachment {
        Attachment {
            data: self.data,
            id: self.id,
            description: self.description,
            filename: self.filename,
            media_type: self.media_type,
            format: self.format,
            lastmod_time: self.lastmod_time,
            byte_count: self.byte_count,
        }
    }
}

// Attention: we are using untagged enum serialization variant.
// Serde will try to match the data against each variant in order and the
// first one that deserializes successfully is the one returned.
// It should work as we always have discrimination here.

/// Represents attachment data in Base64, embedded Json or Links form.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttachmentData {
    Base64(Base64AttachmentData),
    Json(JsonAttachmentData),
    Links(LinksAttachmentData),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Base64AttachmentData {
    /// Base64-encoded data, when representing arbitrary content inline.
    pub base64: String,

    /// A JSON Web Signature over the content of the attachment.
    pub jws: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonAttachmentData {
    /// Directly embedded JSON data.
    pub json: Value,

    /// A JSON Web Signature over the content of the attachment.
    pub jws: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinksAttachmentData {
    /// A list of one or more locations at which the content may be fetched.
    pub links: Vec<String>,

    /// The hash of the content encoded in multi-hash format. Used as an integrity check for the attachment.
    pub hash: String,

    /// A JSON Web Signature over the content of the attachment.
    pub jws: Option<String>,
}

#[cfg(test)]
mod tests {
    use core::panic;

    use serde_json::json;

    use super::*;

    #[test]
    fn attachment_base64_works() {
        let attachment = Attachment::base64("ZXhhbXBsZQ==".to_owned())
            .id("example-1".to_owned())
            .description("example-1-description".to_owned())
            .filename("attachment-1".to_owned())
            .media_type("message/example".to_owned())
            .format("json".to_owned())
            .lastmod_time(10000)
            .byte_count(200)
            .jws("jws".to_owned())
            .finalize();

        let data = match attachment.data {
            AttachmentData::Base64(ref data) => data,
            _ => panic!("data isn't base64."),
        };

        assert_eq!(data.base64, "ZXhhbXBsZQ==");
        assert_eq!(data.jws, Some("jws".to_owned()));
        assert_eq!(attachment.id, Some("example-1".to_owned()));

        assert_eq!(
            attachment.description,
            Some("example-1-description".to_owned())
        );

        assert_eq!(attachment.filename, Some("attachment-1".to_owned()));
        assert_eq!(attachment.media_type, Some("message/example".to_owned()));
        assert_eq!(attachment.format, Some("json".to_owned()));
        assert_eq!(attachment.lastmod_time, Some(10000));
        assert_eq!(attachment.byte_count, Some(200));
    }

    #[test]
    fn attachment_json_works() {
        let attachment = Attachment::json(json!("example"))
            .id("example-1".to_owned())
            .description("example-1-description".to_owned())
            .filename("attachment-1".to_owned())
            .media_type("message/example".to_owned())
            .format("json".to_owned())
            .lastmod_time(10000)
            .byte_count(200)
            .jws("jws".to_owned())
            .finalize();

        let data = match attachment.data {
            AttachmentData::Json(ref data) => data,
            _ => panic!("data isn't json."),
        };

        assert_eq!(data.json, json!("example"));
        assert_eq!(data.jws, Some("jws".to_owned()));
        assert_eq!(attachment.id, Some("example-1".to_owned()));

        assert_eq!(
            attachment.description,
            Some("example-1-description".to_owned())
        );

        assert_eq!(attachment.filename, Some("attachment-1".to_owned()));
        assert_eq!(attachment.media_type, Some("message/example".to_owned()));
        assert_eq!(attachment.format, Some("json".to_owned()));
        assert_eq!(attachment.lastmod_time, Some(10000));
        assert_eq!(attachment.byte_count, Some(200));
    }

    #[test]
    fn attachment_links_works() {
        let attachment = Attachment::links(
            vec!["http://example1".to_owned(), "https://example2".to_owned()],
            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c".to_owned(),
        )
        .id("example-1".to_owned())
        .description("example-1-description".to_owned())
        .filename("attachment-1".to_owned())
        .media_type("message/example".to_owned())
        .format("json".to_owned())
        .lastmod_time(10000)
        .byte_count(200)
        .jws("jws".to_owned())
        .finalize();

        let data = match attachment.data {
            AttachmentData::Links(ref data) => data,
            _ => panic!("data isn't links."),
        };

        assert_eq!(
            data.links,
            vec!["http://example1".to_owned(), "https://example2".to_owned()]
        );

        assert_eq!(
            data.hash,
            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c".to_owned()
        );

        assert_eq!(data.jws, Some("jws".to_owned()));
        assert_eq!(attachment.id, Some("example-1".to_owned()));

        assert_eq!(
            attachment.description,
            Some("example-1-description".to_owned())
        );

        assert_eq!(attachment.filename, Some("attachment-1".to_owned()));
        assert_eq!(attachment.media_type, Some("message/example".to_owned()));
        assert_eq!(attachment.format, Some("json".to_owned()));
        assert_eq!(attachment.lastmod_time, Some(10000));
        assert_eq!(attachment.byte_count, Some(200));
    }
}
