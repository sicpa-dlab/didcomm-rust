use crate::did::DIDResolver;
use crate::error::{ErrorKind, Result};
use crate::{FromPrior, Message, UnpackMetadata};

pub(crate) async fn _try_unpack_plaintext<'dr, 'sr>(
    msg: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    metadata: &mut UnpackMetadata,
) -> Result<Option<Message>> {
    let msg = match Message::from_str(msg) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::Malformed => return Ok(None),
        Err(e) => Err(e)?,
    }
    .validate()?;

    if let Some(from_prior) = &msg.from_prior {
        let (unpacked_from_prior, from_prior_issuer_kid) =
            FromPrior::unpack(from_prior, did_resolver).await?;

        // TODO: Add validation of FromPrior and Message fields consistency

        metadata.from_prior = Some(unpacked_from_prior);
        metadata.from_prior_issuer_kid = Some(from_prior_issuer_kid);
    };

    Ok(Some(msg))
}
