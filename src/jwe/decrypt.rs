use askar_crypto::{
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    kdf::{FromKeyDerivation, KeyExchange},
    repr::{KeyGen, KeySecretBytes},
};

use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe::ParsedJWE,
    jwk::{FromJwkValue, ToJwkValue},
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
        KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
        KW: KeyWrap + FromKeyDerivation,
    {
        let (skid, skey) = match sender {
            Some((skid, skey)) => (Some(skid), Some(skey)),
            None => (None, None),
        };

        let (kid, key) = recepient;

        if skid.map(str::as_bytes) != self.apu.as_deref() {
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

        let epk = KE::from_jwk_value(&self.protected.epk)?;

        let tag = base64::decode_config(self.jwe.tag, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode tag")?;

        let kw = KDF::derive_key(
            &epk,
            skey,
            &key,
            self.protected.alg.as_str().as_bytes(),
            self.apu.as_deref().unwrap_or(&[]),
            &self.apv,
            &tag,
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
            aes::{A128Kw, A256CbcHs512, A256Kw, AesKey},
            chacha20::{Chacha20Key, XC20P},
            x25519::X25519KeyPair,
        },
        encrypt::KeyAeadInPlace,
        kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
        repr::{KeyGen, KeySecretBytes},
    };

    use crate::{
        error::Error,
        jwe::{self, test_support::*},
        jwk::{FromJwkValue, ToJwkValue},
        utils::crypto::{JoseKDF, KeyWrap},
    };

    #[test]
    fn decrypt_works() {
        // from RFC: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04#appendix-B
        _decrypt_works::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A128Kw>,
        >(
            Some(("Alice", ALICE_ECDH_1PU_APP_B)),
            ("bob-key-2", BOB_ECDH_1PU_APP_B),
            MSG_ECDH_1PU_APP_B,
        );

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_ANONCRYPT_X25519_XC20P,
        );

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_2, BOB_KEY_X25519_2),
            MSG_ANONCRYPT_X25519_XC20P,
        );

        _decrypt_works::<
            Chacha20Key<XC20P>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (BOB_KID_X25519_3, BOB_KEY_X25519_3),
            MSG_ANONCRYPT_X25519_XC20P,
        );

        _decrypt_works::<
            AesKey<A256CbcHs512>,
            Ecdh1PU<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            Some((ALICE_KID_X25519_1, ALICE_PKEY_X25519_1)),
            (BOB_KID_X25519_1, BOB_KEY_X25519_1),
            MSG_AUTHCRYPT_X25519_A256CBC,
        );

        fn _decrypt_works<CE, KDF, KE, KW>(
            sender: Option<(&str, &str)>,
            recepient: (&str, &str),
            msg: &str,
        ) where
            CE: KeyAeadInPlace + KeySecretBytes,
            KDF: JoseKDF<KE, KW>,
            KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
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
        KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
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

    const MSG_ANONCRYPT_X25519_XC20P: &str = r#"
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

    const MSG_AUTHCRYPT_X25519_A256CBC: &str = r#"
    {
        "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
        "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
        "recipients":[
           {
              "encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
              "header":{
                 "kid":"did:example:bob#key-x25519-1"
              }
           },
           {
              "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
              "header":{
                 "kid":"did:example:bob#key-x25519-2"
              }
           },
           {
              "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
              "header":{
                 "kid":"did:example:bob#key-x25519-3"
              }
           }
        ],
        "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
        "iv":"o02OXDQ6_-sKz2PX_6oyJg"
     }
    "#;

    const MSG_ECDH_1PU_APP_B: &str = r#"
    {
        "protected":"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19",
        "recipients":[
            {
                "header":{
                    "kid":"bob-key-2"
                },
                "encrypted_key":"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
            },
            {
                "header":{
                    "kid":"2021-05-06"
                },
                "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"
            }
        ],
        "iv":"AAECAwQFBgcICQoLDA0ODw",
        "ciphertext":"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
        "tag":"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"
    }
    "#;

    const ALICE_ECDH_1PU_APP_B: &str = r#"
    {
        "kty": "OKP",
        "crv": "X25519",
        "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
        "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"
    }
    "#;

    const BOB_ECDH_1PU_APP_B: &str = r#"
    {
        "kty": "OKP",
        "crv": "X25519",
        "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
        "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"
    }
    "#;

    const CHARLIE_ECDH_1PU_APP_B: &str = r#"
    {
        "kty": "OKP",
        "crv": "X25519",
        "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
        "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE"
    }
    "#;
}
