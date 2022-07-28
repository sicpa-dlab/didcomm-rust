use sha2::{Digest, Sha256};

use crate::error::ToResult;
use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe::envelope::{ProtectedHeader, JWE},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedJWE<'a, 'b> {
    pub(crate) jwe: JWE<'a>,
    pub(crate) protected: ProtectedHeader<'b>,
    pub(crate) apu: Option<Vec<u8>>,
    pub(crate) apv: Vec<u8>,
}

pub(crate) fn parse<'a, 'b>(jwe: &'a str, buf: &'b mut Vec<u8>) -> Result<ParsedJWE<'a, 'b>> {
    JWE::from_str(jwe)?.parse(buf)
}

impl<'a> JWE<'a> {
    pub(crate) fn from_str(s: &str) -> Result<JWE> {
        serde_json::from_str(s).to_didcomm("Unable parse jwe")
    }

    pub(crate) fn parse<'b>(self, buf: &'b mut Vec<u8>) -> Result<ParsedJWE<'a, 'b>> {
        base64::decode_config_buf(self.protected, base64::URL_SAFE_NO_PAD, buf)
            .kind(ErrorKind::Malformed, "Unable decode protected header")?;

        let protected: ProtectedHeader =
            serde_json::from_slice(buf).to_didcomm("Unable parse protected header")?;

        let apv = base64::decode_config(protected.apv, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode apv")?;

        let apu = protected
            .apu
            .map(|apu| base64::decode_config(apu, base64::URL_SAFE_NO_PAD))
            .transpose()
            .kind(ErrorKind::Malformed, "Unable decode apu")?;

        let jwe = ParsedJWE {
            jwe: self,
            protected,
            apu,
            apv,
        };

        Ok(jwe)
    }
}

impl<'a, 'b> ParsedJWE<'a, 'b> {
    /// Verifies that apv and apu filled according DID Comm specification.
    pub(crate) fn verify_didcomm(self) -> Result<Self> {
        let did_comm_apv = {
            let mut kids = self
                .jwe
                .recipients
                .iter()
                .map(|r| r.header.kid)
                .collect::<Vec<_>>();

            kids.sort();
            Sha256::digest(kids.join(".").as_bytes())
        };

        if &self.apv != did_comm_apv.as_slice() {
            Err(err_msg(ErrorKind::Malformed, "APV mismatch"))?;
        }

        let did_comm_apu = self
            .apu
            .as_deref()
            .map(std::str::from_utf8)
            .transpose()
            .kind(ErrorKind::Malformed, "Invalid utf8 for apu")?;

        match (did_comm_apu, self.protected.skid) {
            (Some(apu), Some(skid)) if apu != skid => {
                Err(err_msg(ErrorKind::Malformed, "APU mismatch"))?
            }
            (None, Some(_)) => Err(err_msg(ErrorKind::Malformed, "SKID present, but no apu"))?,
            _ => (),
        };

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::borrow::Cow;

    use crate::{
        error::ErrorKind,
        jwe::{
            self,
            envelope::{EncAlgorithm, PerRecipientHeader, ProtectedHeader, Recipient, JWE},
            ParsedJWE,
        },
    };

    #[test]
    fn parse_works_anoncrypt() {
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

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWE {
            jwe: JWE {
                protected: "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                recipients: vec![
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-1" },
                        encrypted_key: "3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-2" },
                        encrypted_key: "j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-3" },
                        encrypted_key: "TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
                    },
                ],
                iv: "ESpmcyGiZpRjc5urDela21TOOTW8Wqd1",
                ciphertext: "KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
                tag: "6ylC_iAs4JvDQzXeY6MuYQ",
            },
            protected: ProtectedHeader {
                typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
                alg: jwe::envelope::Algorithm::EcdhEsA256kw,
                enc: EncAlgorithm::Xc20P,
                skid: None,
                apu: None,
                apv: "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA",
                epk: json!({
                    "kty":"OKP",
                    "crv":"X25519",
                    "x":"JHjsmIRZAaB0zRG_wNXLV2rPggF00hdHbW5rj8g0I24"
                }),
            },
            apu: None,
            apv: vec![53, 203, 46, 2, 122, 209, 124, 242, 186, 244, 15, 171, 145, 157, 11, 245, 117, 148, 27, 136, 204, 188, 208, 183, 102, 14, 248, 4, 252, 249, 220, 240],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_anoncrypt_unknown_fields() {
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
            "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1",
            "extra":"value"
         }
        "#;

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWE {
            jwe: JWE {
                protected: "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                recipients: vec![
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-1" },
                        encrypted_key: "3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-2" },
                        encrypted_key: "j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-3" },
                        encrypted_key: "TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
                    },
                ],
                iv: "ESpmcyGiZpRjc5urDela21TOOTW8Wqd1",
                ciphertext: "KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
                tag: "6ylC_iAs4JvDQzXeY6MuYQ",
            },
            protected: ProtectedHeader {
                typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
                alg: jwe::envelope::Algorithm::EcdhEsA256kw,
                enc: EncAlgorithm::Xc20P,
                skid: None,
                apu: None,
                apv: "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA",
                epk: json!({
                    "kty":"OKP",
                    "crv":"X25519",
                    "x":"JHjsmIRZAaB0zRG_wNXLV2rPggF00hdHbW5rj8g0I24"
                }),
            },
            apu: None,
            apv: vec![53, 203, 46, 2, 122, 209, 124, 242, 186, 244, 15, 171, 145, 157, 11, 245, 117, 148, 27, 136, 204, 188, 208, 183, 102, 14, 248, 4, 252, 249, 220, 240],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_anoncrypt_protected_unknown_fields() {
        let msg = r#"
        {
            "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwiZXh0cmEiOiJ2YWx1ZSJ9",
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

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWE {
            jwe: JWE {
                protected: "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwiZXh0cmEiOiJ2YWx1ZSJ9",
                recipients: vec![
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-1" },
                        encrypted_key: "3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-2" },
                        encrypted_key: "j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-3" },
                        encrypted_key: "TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
                    },
                ],
                iv: "ESpmcyGiZpRjc5urDela21TOOTW8Wqd1",
                ciphertext: "KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
                tag: "6ylC_iAs4JvDQzXeY6MuYQ",
            },
            protected: ProtectedHeader {
                typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
                alg: jwe::envelope::Algorithm::EcdhEsA256kw,
                enc: EncAlgorithm::Xc20P,
                skid: None,
                apu: None,
                apv: "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA",
                epk: json!({
                    "kty":"OKP",
                    "crv":"X25519",
                    "x":"JHjsmIRZAaB0zRG_wNXLV2rPggF00hdHbW5rj8g0I24"
                }),
            },
            apu: None,
            apv: vec![53, 203, 46, 2, 122, 209, 124, 242, 186, 244, 15, 171, 145, 157, 11, 245, 117, 148, 27, 136, 204, 188, 208, 183, 102, 14, 248, 4, 252, 249, 220, 240],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_authcrypt() {
        let msg = r#"
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

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWE {
            jwe: JWE {
                protected: "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
                recipients: vec![
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-1" },
                        encrypted_key: "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-2" },
                        encrypted_key: "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-3" },
                        encrypted_key: "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
                    },
                ],
                iv: "o02OXDQ6_-sKz2PX_6oyJg",
                ciphertext: "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
                tag: "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
            },
            protected: ProtectedHeader {
                typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
                alg: jwe::envelope::Algorithm::Ecdh1puA256kw,
                enc: EncAlgorithm::A256cbcHs512,
                skid: Some("did:example:alice#key-x25519-1"),
                apu: Some("ZGlkOmV4YW1wbGU6YWxpY2Uja2V5LXgyNTUxOS0x"),
                apv: "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA",
                epk: json!({
                    "kty":"OKP",
                    "crv":"X25519",
                    "x":"GFcMopJljf4pLZfch4a_GhTM_YAf6iNI1dWDGyVCaw0"
                }),
            },
            apu: Some(b"did:example:alice#key-x25519-1".to_vec()),
            apv: vec![53, 203, 46, 2, 122, 209, 124, 242, 186, 244, 15, 171, 145, 157, 11, 245, 117, 148, 27, 136, 204, 188, 208, 183, 102, 14, 248, 4, 252, 249, 220, 240],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_authcrypt_unknown_fields() {
        let msg = r#"
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
            "iv":"o02OXDQ6_-sKz2PX_6oyJg",
            "extra":"value"
         }
        "#;

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWE {
            jwe: JWE {
                protected: "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
                recipients: vec![
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-1" },
                        encrypted_key: "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-2" },
                        encrypted_key: "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-3" },
                        encrypted_key: "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
                    },
                ],
                iv: "o02OXDQ6_-sKz2PX_6oyJg",
                ciphertext: "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
                tag: "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
            },
            protected: ProtectedHeader {
                typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
                alg: jwe::envelope::Algorithm::Ecdh1puA256kw,
                enc: EncAlgorithm::A256cbcHs512,
                skid: Some("did:example:alice#key-x25519-1"),
                apu: Some("ZGlkOmV4YW1wbGU6YWxpY2Uja2V5LXgyNTUxOS0x"),
                apv: "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA",
                epk: json!({
                    "kty":"OKP",
                    "crv":"X25519",
                    "x":"GFcMopJljf4pLZfch4a_GhTM_YAf6iNI1dWDGyVCaw0"
                }),
            },
            apu: Some(b"did:example:alice#key-x25519-1".to_vec()),
            apv: vec![53, 203, 46, 2, 122, 209, 124, 242, 186, 244, 15, 171, 145, 157, 11, 245, 117, 148, 27, 136, 204, 188, 208, 183, 102, 14, 248, 4, 252, 249, 220, 240],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_authcrypt_protected_unknown_fields() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1ciLCJleHRyYSI6InZhbHVlIn0=",
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

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWE {
            jwe: JWE {
                protected: "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1ciLCJleHRyYSI6InZhbHVlIn0=",
                recipients: vec![
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-1" },
                        encrypted_key: "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-2" },
                        encrypted_key: "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-3" },
                        encrypted_key: "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
                    },
                ],
                iv: "o02OXDQ6_-sKz2PX_6oyJg",
                ciphertext: "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
                tag: "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
            },
            protected: ProtectedHeader {
                typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
                alg: jwe::envelope::Algorithm::Ecdh1puA256kw,
                enc: EncAlgorithm::A256cbcHs512,
                skid: Some("did:example:alice#key-x25519-1"),
                apu: Some("ZGlkOmV4YW1wbGU6YWxpY2Uja2V5LXgyNTUxOS0x"),
                apv: "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA",
                epk: json!({
                    "kty":"OKP",
                    "crv":"X25519",
                    "x":"GFcMopJljf4pLZfch4a_GhTM_YAf6iNI1dWDGyVCaw0"
                }),
            },
            apu: Some(b"did:example:alice#key-x25519-1".to_vec()),
            apv: vec![53, 203, 46, 2, 122, 209, 124, 242, 186, 244, 15, 171, 145, 157, 11, 245, 117, 148, 27, 136, 204, 188, 208, 183, 102, 14, 248, 4, 252, 249, 220, 240],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_unparsable() {
        let msg = r#"
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
            "iv":"o02OXDQ6_-sKz2PX_6oyJg",
         }
        "#;

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse jwe: trailing comma at line 27 column 10"
        );
    }

    #[test]
    fn parse_works_misstructured() {
        let msg = r#"
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
            "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U"
         }
        "#;

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse jwe: missing field `iv` at line 26 column 10"
        );
    }

    #[test]
    fn parse_works_udecodable_protected() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"!eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
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

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable decode protected header: Invalid byte 33, offset 0."
        );
    }

    #[test]
    fn parse_works_uparsable_protected() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1ciLH0",
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

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse protected header: trailing comma at line 1 column 317"
        );
    }

    #[test]
    fn parse_works_misstructured_protected() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ",
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

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse protected header: missing field `alg` at line 1 column 292"
        );
    }

    #[test]
    fn parse_works_undecodable_apu() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiIhWkdsa09tVjRZVzF3YkdVNllXeHBZMlVqYTJWNUxYZ3lOVFV4T1MweCIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIn0",
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

        let mut buf = vec![];
        let res = jwe::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable decode apu: Encoded text cannot have a 6-bit remainder."
        );
    }

    #[test]
    fn verify_didcomm_works_non_utf8_apu() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJ3TUhBd1EiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImFsZyI6IkVDREgtMVBVK0EyNTZLVyJ9",
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

        let mut buf = vec![];

        let res = jwe::parse(&msg, &mut buf)
            .expect("Unable parse")
            .verify_didcomm();

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Invalid utf8 for apu: invalid utf-8 sequence of 1 bytes from index 0"
        );
    }

    #[test]
    fn verify_didcomm_works_apv_mismatch() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTWNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
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

        let mut buf = vec![];

        let res = jwe::parse(&msg, &mut buf)
            .expect("Unable parse")
            .verify_didcomm();

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(format!("{}", err), "Malformed: APV mismatch");
    }

    #[test]
    fn verify_didcomm_works_anoncrypt() {
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

        let mut buf = vec![];

        let res = jwe::parse(&msg, &mut buf)
            .expect("Unable parse")
            .verify_didcomm()
            .expect("res is err");

        let exp = ParsedJWE {
            jwe: JWE {
                protected: "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
                recipients: vec![
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-1" },
                        encrypted_key: "3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-2" },
                        encrypted_key: "j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-3" },
                        encrypted_key: "TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
                    },
                ],
                iv: "ESpmcyGiZpRjc5urDela21TOOTW8Wqd1",
                ciphertext: "KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
                tag: "6ylC_iAs4JvDQzXeY6MuYQ",
            },
            protected: ProtectedHeader {
                typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
                alg: jwe::envelope::Algorithm::EcdhEsA256kw,
                enc: EncAlgorithm::Xc20P,
                skid: None,
                apu: None,
                apv: "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA",
                epk: json!({
                    "kty":"OKP",
                    "crv":"X25519",
                    "x":"JHjsmIRZAaB0zRG_wNXLV2rPggF00hdHbW5rj8g0I24"
                }),
            },
            apu: None,
            apv: vec![53, 203, 46, 2, 122, 209, 124, 242, 186, 244, 15, 171, 145, 157, 11, 245, 117, 148, 27, 136, 204, 188, 208, 183, 102, 14, 248, 4, 252, 249, 220, 240],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn verify_did_comm_works_authcrypt() {
        let msg = r#"
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

        let mut buf = vec![];

        let res = jwe::parse(&msg, &mut buf)
            .expect("Unable parse")
            .verify_didcomm()
            .expect("res is err");

        let exp = ParsedJWE {
            jwe: JWE {
                protected: "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
                recipients: vec![
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-1" },
                        encrypted_key: "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-2" },
                        encrypted_key: "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                    },
                    Recipient {
                        header: PerRecipientHeader { kid: "did:example:bob#key-x25519-3" },
                        encrypted_key: "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
                    },
                ],
                iv: "o02OXDQ6_-sKz2PX_6oyJg",
                ciphertext: "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
                tag: "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
            },
            protected: ProtectedHeader {
                typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
                alg: jwe::envelope::Algorithm::Ecdh1puA256kw,
                enc: EncAlgorithm::A256cbcHs512,
                skid: Some("did:example:alice#key-x25519-1"),
                apu: Some("ZGlkOmV4YW1wbGU6YWxpY2Uja2V5LXgyNTUxOS0x"),
                apv: "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA",
                epk: json!({
                    "kty":"OKP",
                    "crv":"X25519",
                    "x":"GFcMopJljf4pLZfch4a_GhTM_YAf6iNI1dWDGyVCaw0"
                }),
            },
            apu: Some(b"did:example:alice#key-x25519-1".to_vec()),
            apv: vec![53, 203, 46, 2, 122, 209, 124, 242, 186, 244, 15, 171, 145, 157, 11, 245, 117, 148, 27, 136, 204, 188, 208, 183, 102, 14, 248, 4, 252, 249, 220, 240],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn verify_didcomm_works_apu_mismatch() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTIiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
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

        let mut buf = vec![];

        let res = jwe::parse(&msg, &mut buf)
            .expect("Unable parse")
            .verify_didcomm();

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(format!("{}", err), "Malformed: APU mismatch");
    }

    #[test]
    fn verify_didcomm_works_no_apu_skid_present() {
        let msg = r#"
        {
            "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImFsZyI6IkVDREgtMVBVK0EyNTZLVyJ9",
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

        let mut buf = vec![];

        let res = jwe::parse(&msg, &mut buf)
            .expect("Unable parse")
            .verify_didcomm();

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(format!("{}", err), "Malformed: SKID present, but no apu");
    }
}
