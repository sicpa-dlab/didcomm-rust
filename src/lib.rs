mod message;
mod pack;
mod sign;
mod unpack;

pub mod algorithms;
pub mod did;
pub mod error;

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
