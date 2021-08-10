mod message;

pub mod algorithms;
pub mod did;
pub mod error;
pub mod pack;
pub mod unpack;
pub mod secrets;

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
