use askar_crypto::sign::KeySigVerify;

use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jws::ParsedJWS,
};

impl<'a, 'b> ParsedJWS<'a, 'b> {
    pub(crate) fn verify<Key: KeySigVerify>(&self, signer: (&str, &Key)) -> Result<bool> {
        let (kid, key) = signer;

        let (i, signature) = self
            .jws
            .signatures
            .iter()
            .enumerate()
            .find(|(_, sig)| sig.header.kid == kid)
            .ok_or_else(|| err_msg(ErrorKind::InvalidState, "kid not found."))?;

        let protected = self
            .protected
            .get(i)
            .ok_or_else(|| err_msg(ErrorKind::InvalidState, "invalid protected header index."))?;

        if kid != signature.header.kid {
            Err(err_msg(ErrorKind::InvalidState, "kid doesn't match."))?;
        }

        let sig_type = protected.alg.sig_type()?;
        let sign_input = format!("{}.{}", signature.protected, self.jws.payload);

        let signature = base64::decode_config(&signature.signature, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "unable decode signature.")?;

        let valid = key
            .verify_signature(sign_input.as_bytes(), &signature, Some(sig_type))
            .kind(ErrorKind::Malformed, "unable verify signature.")?;

        Ok(valid)
    }
}
