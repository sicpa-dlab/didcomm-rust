use askar_crypto::{
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    jwk::{FromJwk, ToJwk},
    kdf::{FromKeyDerivation, KeyExchange},
    repr::{KeyGen, KeySecretBytes},
};

use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe::ParsedJWE,
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
        KE: KeyExchange + KeyGen + ToJwk + FromJwk,
        KW: KeyWrap + FromKeyDerivation,
    {
        let (skid, skey) = match sender {
            Some((skid, skey)) => (Some(skid), Some(skey)),
            None => (None, None),
        };

        let (kid, key) = recepient;

        if skid != self.apu.as_deref() {
            Err(err_msg(ErrorKind::InvalidState, "Wrong skid used"))?
        }

        let encrypted_key = {
            let encrypted_key = self
                .jwe
                .recipients
                .iter()
                .find(|r| r.header.kid == kid)
                .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Recepient not found"))?
                .encrypted_key;

            base64::decode_config(encrypted_key, base64::URL_SAFE_NO_PAD)
                .kind(ErrorKind::Malformed, "Unable decode encrypted_key")?
        };

        let epk = {
            // TODO: better serialization after fix https://github.com/hyperledger/aries-askar/issues/22
            // or at least provide helper for this.
            let epk = serde_json::to_string(&self.protected.epk)
                .kind(ErrorKind::InvalidState, "Unable produce jwk for epk")?;

            KE::from_jwk(&epk).kind(ErrorKind::Malformed, "Unable produce jwk for epk")?
        };

        let kw = KDF::derive_key(
            &epk,
            skey,
            &key,
            self.protected.alg.as_str().as_bytes(),
            self.apu.as_ref().map(|apu| apu.as_bytes()).unwrap_or(&[]),
            &self.apv,
            true,
        )
        .kind(ErrorKind::InvalidState, "Unable derive kw")?;

        let cek: CE = kw
            .unwrap_key(&encrypted_key)
            .kind(ErrorKind::Malformed, "Unable unwrap cek")?;

        let cyphertext = base64::decode_config(self.jwe.ciphertext, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode cyphertext")?;

        let iv = base64::decode_config(self.jwe.iv, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode iv")?;

        let tag = base64::decode_config(self.jwe.tag, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode tag")?;

        let plaintext = {
            let mut buf = SecretBytes::with_capacity(cyphertext.len() + tag.len());
            buf.extend_from_slice(&cyphertext);
            buf.extend_from_slice(&tag);

            cek.decrypt_in_place(&mut buf, &iv, self.jwe.protected.as_bytes())
                .kind(ErrorKind::Malformed, "Unable decrypt content")?;

            buf.to_vec()
        };

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{
            aes::{A256Kw, AesKey},
            chacha20::{Chacha20Key, XC20P},
            x25519::X25519KeyPair,
        },
        encrypt::KeyAeadInPlace,
        jwk::{FromJwk, ToJwk},
        kdf::{ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
        repr::{KeyGen, KeySecretBytes},
    };

    use crate::{
        error::Error,
        jwe::{self, test_support::*},
        utils::crypto::{JoseKDF, KeyWrap},
    };

    #[test]
    fn decrypt_works() {
        let msg = r#"
        {
            "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
            "recipients":[
               {
                  "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
                  "header":{
                     "kid":"did:example:bob#key-x25519-1"
                  }
               },
               {
                  "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
                  "header":{
                     "kid":"did:example:bob#key-x25519-2"
                  }
               },
               {
                  "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
                  "header":{
                     "kid":"did:example:bob#key-x25519-3"
                  }
               }
            ],
            "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
            "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
         }
        "#;

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(None, (BOB_KID_X25519_1, BOB_KEY_X25519_1), msg);

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(None, (BOB_KID_X25519_2, BOB_KEY_X25519_2), msg);

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(None, (BOB_KID_X25519_3, BOB_KEY_X25519_3), msg);

        fn _decrypt_works<CE, KDF, KE, KW>(
            sender: Option<(&str, &str)>,
            recepient: (&str, &str),
            msg: &str,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwk + FromJwk,
            KW: KeyWrap + FromKeyDerivation,
        {
            let res = _decrypt::<CE, KDF, KE, KW>(sender, recepient, msg);
            let _res = res.expect("res is err");
            //assert_eq!(res, true);
        }
    }

    fn _decrypt<CE, KDF, KE, KW>(
        sender: Option<(&str, &str)>,
        recepient: (&str, &str),
        msg: &str,
    ) -> Result<Vec<u8>, Error>
    where
        CE: KeyAeadInPlace + KeySecretBytes,
        KDF: JoseKDF<KE, KW>,
        KE: KeyExchange + KeyGen + ToJwk + FromJwk,
        KW: KeyWrap + FromKeyDerivation,
    {
        let _sender = sender.map(|(kid, k)| (kid, KE::from_jwk(k).expect("Unable from_jwk")));
        let sender = _sender.as_ref().map(|(kid, k)| (*kid, k));

        let recepient = (
            recepient.0,
            &KE::from_jwk(recepient.1).expect("Unable from_jwk"),
        );

        let mut buf = vec![];
        let msg = jwe::parse(&msg, &mut buf).expect("Unable parse");

        msg.decrypt::<CE, KDF, KE, KW>(sender, recepient)
    }
}
