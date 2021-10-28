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

    let msg = match &msg.from_prior_jwt {
        Some(from_prior_jwt) => {
            let (from_prior, from_prior_issuer_kid) =
                FromPrior::unpack(from_prior_jwt, did_resolver).await?;
            let msg = Message {
                from_prior: Some(from_prior),
                from_prior_jwt: None,
                ..msg
            };

            metadata.from_prior_jwt = Some(from_prior_jwt.clone());
            metadata.from_prior_issuer_kid = Some(from_prior_issuer_kid);

            msg
        }

        None => msg,
    };

    Ok(msg)
}
