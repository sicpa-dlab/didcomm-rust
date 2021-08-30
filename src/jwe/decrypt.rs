use askar_crypto::{
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    jwk::{FromJwk, ToJwk},
    kdf::{FromKeyDerivation, KeyExchange},
    repr::{KeyGen, KeySecretBytes},
};

use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe::parse::ParsedJWE,
    utils::crypto::{JoseKDF, KeyWrap},
};

impl<'a, 'b> ParsedJWE<'a, 'b> {
    pub(crate) fn decrypt<CE, KDF, KE, KW>(
        &self,
        sender: Option<(&str, &KE)>,
        recepient: (&str, &KE),
    ) -> Result<Vec<u8>>
    where
        CE: KeyAeadInPlace + KeySecretBytes,
        KDF: JoseKDF<KE, KW>,
        KE: KeyExchange + KeyGen + ToJwk + FromJwk + ?Sized,
        KW: KeyWrap + FromKeyDerivation,
    {
        let (skid, skey) = match sender {
            Some((skid, skey)) => (Some(skid), Some(skey)),
            None => (None, None),
        };

        let (kid, key) = recepient;

        if skid != self.skid.as_deref() {
            Err(err_msg(ErrorKind::InvalidState, "wrong skid used"))?
        }

        let encrypted_key = {
            let encrypted_key = self
                .jwe
                .recipients
                .iter()
                .find(|r| r.header.kid == kid)
                .ok_or_else(|| err_msg(ErrorKind::InvalidState, "recepient not found."))?
                .encrypted_key;

            base64::decode_config(encrypted_key, base64::URL_SAFE_NO_PAD)
                .kind(ErrorKind::Malformed, "unable decode encrypted_key.")?
        };

        let epk = {
            // TODO: better serialization after fix https://github.com/hyperledger/aries-askar/issues/22
            // or at least provide helper for this.
            let epk = serde_json::to_string(&self.protected.epk)
                .kind(ErrorKind::InvalidState, "unable produce jwk for epk.")?;

            KE::from_jwk(&epk).kind(ErrorKind::Malformed, "unable produce jwk for epk.")?
        };

        let kw = KDF::derive_key(
            &epk,
            skey,
            &key,
            self.protected.apu.map(|apu| apu.as_bytes()),
            self.protected.apv.as_bytes(),
            true,
        )
        .kind(ErrorKind::InvalidState, "unable derive kw.")?;

        let cek: CE = kw
            .unwrap_key(&encrypted_key)
            .kind(ErrorKind::Malformed, "unable unwrap cek.")?;

        let cyphertext = base64::decode_config(self.jwe.ciphertext, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "unable decode cyphertext.")?;

        let iv = base64::decode_config(self.jwe.iv, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "unable decode iv.")?;

        let tag = base64::decode_config(self.jwe.tag, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "unable decode tag.")?;

        let plaintext = {
            let mut buf = SecretBytes::with_capacity(cyphertext.len() + tag.len());
            buf.extend_from_slice(&cyphertext);
            buf.extend_from_slice(&tag);

            cek.decrypt_in_place(&mut buf, &iv, self.jwe.protected.as_bytes())
                .kind(ErrorKind::Malformed, "unable decrypt content.")?;

            buf.to_vec()
        };

        Ok(plaintext)
    }
}
