use askar_crypto::{
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    jwk::{FromJwk, ToJwk},
    kdf::{ecdh_1pu::Ecdh1PU, FromKeyDerivation, KeyExchange},
    repr::{KeyGen, KeySecretBytes},
};

use crate::{
    authcrypt::parse::ParsedJWE,
    error::{err_msg, ErrorKind, Result, ResultExt},
    utils::crypto::KeyWrap,
};

impl<'a, 'b> ParsedJWE<'a, 'b> {
    pub(crate) fn decrypt<KE, KW, CE>(
        &self,
        sender: (&str, &KE),
        recepient: (&str, &KE),
    ) -> Result<Vec<u8>>
    where
        KE: KeyExchange + KeyGen + ToJwk + FromJwk + ?Sized,
        KW: KeyWrap + FromKeyDerivation,
        CE: KeyAeadInPlace + KeySecretBytes,
    {
        let (skid, skey) = sender;
        let (kid, key) = recepient;

        if skid != self.skid {
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

        let kw = {
            let deriviation = Ecdh1PU::new(
                &epk,
                &skey,
                &key,
                b"A256GCM",
                self.protected.apu.as_bytes(),
                self.protected.apv.as_bytes(),
                &[],
                false,
            );

            KW::from_key_derivation(deriviation)
                .kind(ErrorKind::InvalidState, "unable derive kw.")?
        };

        let cek: CE = kw
            .unwrap_key(&encrypted_key)
            .kind(ErrorKind::Malformed, "unable unwrap cek.")?;

        let cyphertext = base64::decode_config(self.jwe.ciphertext, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "unable decode cyphertext.")?;

        let iv = base64::decode_config(self.jwe.iv, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "unable decode iv.")?;

        let plaintext = {
            let mut buf = SecretBytes::from_slice(&cyphertext);

            cek.decrypt_in_place(&mut buf, self.jwe.protected.as_bytes(), &iv)
                .kind(ErrorKind::Malformed, "unable decrypt content.")?;

            buf.to_vec()
        };

        Ok(plaintext)
    }
}
