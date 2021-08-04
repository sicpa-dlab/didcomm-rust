pub(crate) mod did;
pub(crate) mod message;
pub(crate) mod secrets;

pub mod error;

pub use message::{
    Attachment, AttachmentBuilder, AttachmentData, Base64AttachmentData, JsonAttachmentData,
    LinksAttachmentData, Message, MessageBuilder,
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
