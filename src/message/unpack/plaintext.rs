use crate::did::DIDResolver;
use crate::error::{ErrorKind, Result, ResultExt};
use crate::{FromPrior, Message, UnpackMetadata};

pub(crate) async fn unpack_plaintext<'dr, 'sr>(
    msg: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    metadata: &mut UnpackMetadata,
) -> Result<Message> {
    let msg: Message =
        serde_json::from_str(msg).kind(ErrorKind::Malformed, "Unable deserialize jwm")?;

    if let Some(from_prior) = &msg.from_prior {
        let (unpacked_from_prior, from_prior_issuer_kid) =
            FromPrior::unpack(from_prior, did_resolver).await?;

        // Add validation of FromPrior and Message fields consistency

        metadata.from_prior = Some(unpacked_from_prior);
        metadata.from_prior_issuer_kid = Some(from_prior_issuer_kid);
    };

    Ok(msg)
}
