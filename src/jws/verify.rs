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
            .ok_or_else(|| err_msg(ErrorKind::InvalidState, "KID not found"))?;

        let protected = self
            .protected
            .get(i)
            .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Invalid protected header index"))?;

        let sig_type = protected.alg.sig_type()?;
        let sign_input = format!("{}.{}", signature.protected, self.jws.payload);

        let signature = base64::decode_config(&signature.signature, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::Malformed, "Unable decode signature")?;

        let valid = key
            .verify_signature(sign_input.as_bytes(), &signature, Some(sig_type))
            .kind(ErrorKind::Malformed, "Unable verify signature")?;

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair},
        jwk::FromJwk,
        sign::KeySigVerify,
    };

    use crate::{
        error::{Error, ErrorKind},
        jws,
    };

    #[test]
    fn verify_works() {
        _verify_works::<Ed25519KeyPair>(ALICE_KID_ED25519, ALICE_PKEY_ED25519, ALICE_MSG_ED25519);
        _verify_works::<P256KeyPair>(ALICE_KID_P256, ALICE_PKEY_P256, ALICE_MSG_P256);
        _verify_works::<K256KeyPair>(ALICE_KID_K256, ALICE_PKEY_K256, ALICE_MSG_K256);

        fn _verify_works<K: FromJwk + KeySigVerify>(kid: &str, key: &str, msg: &str) {
            let res = _verify::<K>(kid, key, msg);
            let res = res.expect("res is err");
            assert_eq!(res, true);
        }
    }

    #[test]
    fn verify_works_multiple_signatures() {
        _verify_works_multiple_signatures::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_PKEY_ED25519,
            ALICE_MSG_ED25519_P256_K256,
        );

        _verify_works_multiple_signatures::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_PKEY_P256,
            ALICE_MSG_ED25519_P256_K256,
        );

        _verify_works_multiple_signatures::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_PKEY_K256,
            ALICE_MSG_ED25519_P256_K256,
        );

        fn _verify_works_multiple_signatures<K: FromJwk + KeySigVerify>(
            kid: &str,
            key: &str,
            msg: &str,
        ) {
            let res = _verify::<K>(kid, key, msg);
            let res = res.expect("res is err");
            assert_eq!(res, true);
        }
    }

    #[test]
    fn verify_works_different_key() {
        _verify_works_different_key::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_PKEY_ED25519,
            BOB_MSG_ED25519,
        );

        _verify_works_different_key::<P256KeyPair>(ALICE_KID_P256, ALICE_PKEY_P256, BOB_MSG_P256);

        _verify_works_different_key::<K256KeyPair>(ALICE_KID_K256, ALICE_PKEY_K256, BOB_MSG_K256);

        fn _verify_works_different_key<K: FromJwk + KeySigVerify>(kid: &str, key: &str, msg: &str) {
            let res = _verify::<K>(kid, key, msg);
            let res = res.expect("res is err");
            assert_eq!(res, false);
        }
    }

    #[test]
    fn verify_works_changed_payload() {
        _verify_works_changed_payload::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_PKEY_ED25519,
            ALICE_MSG_ED25519_CHANGED_PAYLOAD,
        );

        _verify_works_changed_payload::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_PKEY_P256,
            ALICE_MSG_P256_CHANGED_PAYLOAD,
        );

        _verify_works_changed_payload::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_PKEY_K256,
            ALICE_MSG_K256_CHANGED_PAYLOAD,
        );

        fn _verify_works_changed_payload<K: FromJwk + KeySigVerify>(
            kid: &str,
            key: &str,
            msg: &str,
        ) {
            let res = _verify::<K>(kid, key, msg);
            let res = res.expect("res is err");
            assert_eq!(res, false);
        }
    }

    #[test]
    fn verify_works_different_curve() {
        _verify_works_different_curve::<Ed25519KeyPair>(
            ALICE_KID_P256,
            ALICE_PKEY_ED25519,
            ALICE_MSG_P256,
        );

        _verify_works_different_curve::<Ed25519KeyPair>(
            ALICE_KID_K256,
            ALICE_PKEY_ED25519,
            ALICE_MSG_K256,
        );

        _verify_works_different_curve::<P256KeyPair>(
            ALICE_KID_ED25519,
            ALICE_PKEY_P256,
            BOB_MSG_ED25519,
        );

        _verify_works_different_curve::<P256KeyPair>(ALICE_KID_K256, ALICE_PKEY_P256, BOB_MSG_K256);

        _verify_works_different_curve::<K256KeyPair>(
            ALICE_KID_ED25519,
            ALICE_PKEY_K256,
            BOB_MSG_ED25519,
        );

        _verify_works_different_curve::<K256KeyPair>(ALICE_KID_P256, ALICE_PKEY_K256, BOB_MSG_P256);

        fn _verify_works_different_curve<K: FromJwk + KeySigVerify>(
            kid: &str,
            key: &str,
            msg: &str,
        ) {
            let res = _verify::<K>(kid, key, msg);
            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::Malformed);

            assert_eq!(
                format!("{}", err),
                "Malformed: Unable verify signature: Unsupported signature type"
            );
        }
    }

    #[test]
    fn verify_works_kid_not_found() {
        _verify_works_kid_not_found::<Ed25519KeyPair>(
            ALICE_KID_P256,
            ALICE_PKEY_ED25519,
            ALICE_MSG_ED25519,
        );

        _verify_works_kid_not_found::<P256KeyPair>(ALICE_KID_K256, ALICE_PKEY_P256, ALICE_MSG_P256);

        _verify_works_kid_not_found::<K256KeyPair>(
            ALICE_KID_ED25519,
            ALICE_PKEY_K256,
            ALICE_MSG_K256,
        );

        fn _verify_works_kid_not_found<K: FromJwk + KeySigVerify>(kid: &str, key: &str, msg: &str) {
            let res = _verify::<K>(kid, key, msg);

            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::InvalidState);
            assert_eq!(format!("{}", err), "Invalid state: KID not found");
        }
    }

    #[test]
    fn verify_works_undecodable_sig() {
        _verify_works_undecodable_sig::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_PKEY_ED25519,
            ALICE_MSG_ED25519_UNDECODABLE_SIG,
        );

        _verify_works_undecodable_sig::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_PKEY_P256,
            ALICE_MSG_P256_UNDECODABLE_SIG,
        );

        _verify_works_undecodable_sig::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_PKEY_K256,
            ALICE_MSG_K256_UNDECODABLE_SIG,
        );

        fn _verify_works_undecodable_sig<K: FromJwk + KeySigVerify>(
            kid: &str,
            key: &str,
            msg: &str,
        ) {
            let res = _verify::<K>(kid, key, msg);

            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::Malformed);

            assert_eq!(
                format!("{}", err),
                "Malformed: Unable decode signature: Invalid byte 33, offset 0."
            );
        }
    }

    fn _verify<Key: FromJwk + KeySigVerify>(
        kid: &str,
        key: &str,
        msg: &str,
    ) -> Result<bool, Error> {
        let key = Key::from_jwk(key).expect("unable from_jwk.");

        let mut buf = vec![];
        let msg = jws::parse(&msg, &mut buf).expect("unable parse.");

        msg.verify((kid, &key))
    }

    const ALICE_KID_ED25519: &str = "did:example:alice#key-1";

    const ALICE_KEY_ED25519: &str = r#"
    {
        "kty":"OKP",
        "d":"pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
        "crv":"Ed25519",
        "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
    }
    "#;

    const ALICE_PKEY_ED25519: &str = r#"
    {
        "kty":"OKP",
        "crv":"Ed25519",
        "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
    }
    "#;

    const ALICE_MSG_ED25519: &str = r#"
    {
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
           {
              "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
              "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
              "header":{
                 "kid":"did:example:alice#key-1"
              }
           }
        ]
    }
    "#;

    const ALICE_MSG_ED25519_CHANGED_PAYLOAD: &str = r#"
    {
        "payload":"eyJpZCI6IjAyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
           {
              "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
              "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
              "header":{
                 "kid":"did:example:alice#key-1"
              }
           }
        ]
    }
    "#;

    const ALICE_MSG_ED25519_UNDECODABLE_SIG: &str = r#"
    {
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
           {
              "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
              "signature":"!FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
              "header":{
                 "kid":"did:example:alice#key-1"
              }
           }
        ]
    }
    "#;

    const ALICE_KID_P256: &str = "did:example:alice#key-2";

    const ALICE_KEY_P256: &str = r#"
    {
        "kty":"EC",
        "d":"7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
        "crv":"P-256",
        "x":"2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
        "y":"BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
    }
    "#;

    const ALICE_PKEY_P256: &str = r#"
    {
        "kty":"EC",
        "crv":"P-256",
        "x":"2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
        "y":"BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
    }
    "#;

    const ALICE_MSG_P256: &str = r#"
    {
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
                "signature":"gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg",
                "header":{
                    "kid":"did:example:alice#key-2"
                }
            }
        ]
    }
    "#;

    const ALICE_MSG_P256_CHANGED_PAYLOAD: &str = r#"
    {
        "payload":"eyJpZCI6IjAyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
                "signature":"gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg",
                "header":{
                    "kid":"did:example:alice#key-2"
                }
            }
        ]
    }
    "#;

    const ALICE_MSG_P256_UNDECODABLE_SIG: &str = r#"
    {
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
                "signature":"!gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg",
                "header":{
                    "kid":"did:example:alice#key-2"
                }
            }
        ]
    }
    "#;

    const ALICE_KID_K256: &str = "did:example:alice#key-3";

    const ALICE_KEY_K256: &str = r#"
    {
        "kty":"EC",
        "d":"N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
        "crv":"secp256k1",
        "x":"aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
        "y":"JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
    }
    "#;

    const ALICE_PKEY_K256: &str = r#"
    {
        "kty":"EC",
        "d":"N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
        "x":"aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
        "y":"JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
    }
    "#;

    const ALICE_MSG_K256: &str = r#"
    {
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
                "signature":"EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw",
                "header":{
                    "kid":"did:example:alice#key-3"
                }
            }
        ]
    }
    "#;

    const ALICE_MSG_K256_CHANGED_PAYLOAD: &str = r#"
    {
        "payload":"eyJpZCI6IjAyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
                "signature":"EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw",
                "header":{
                    "kid":"did:example:alice#key-3"
                }
            }
        ]
    }
    "#;

    const ALICE_MSG_K256_UNDECODABLE_SIG: &str = r#"
    {
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
                "signature":"!EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw",
                "header":{
                    "kid":"did:example:alice#key-3"
                }
            }
        ]
    }
    "#;

    const ALICE_MSG_ED25519_P256_K256: &str = r#"
    {
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures":[
           {
              "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
              "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
              "header":{
                 "kid":"did:example:alice#key-1"
              }
           },
           {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
                "signature":"gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg",
                "header":{
                    "kid":"did:example:alice#key-2"
                }
            },
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
                "signature":"EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw",
                "header":{
                    "kid":"did:example:alice#key-3"
                }
            }
        ]
    }
    "#;

    /*
    Bob key Ed25519
    {"crv":"Ed25519","kty":"OKP","x":"ECEdOp9caYYVMgGomcV-bHjvJcRvh68COWd_GO-npGI","d":"CKMS_Kt8x6to6jD88d6EGo_H_fSG3L2SAEccLBGQG3U"}
    */

    const BOB_MSG_ED25519: &str = r#"
    {
        "signatures":[{
            "header":{
                "kid":"did:example:alice#key-1"
            },
            "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
            "signature":"cc2lCOjvv0asYfTCRYHDeFecet0m8u9y2SeCINttTsk7uqjVTWz6fQpjcH-uaZs1UxsXYrFqJDX6QfnUUlb-Dw"
        }],
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19"
    }"#;

    /*
    Bob key P-256:
    {"crv":"P-256","kty":"EC","x":"v1rA6xXLkpDdjoyUXxoCaSJGnKr8SCHGaXQriEqw_mA","y":"b461bvXFQf3wq8XPg9ys5_bVnzBM1iCuJCOHwzmh2zY","d":"lp9UPAQDVv6xTheeEoVJ6pHKxjAM05y3lQOGOOC_OsM"}
    */

    const BOB_MSG_P256: &str = r#"
    {
        "signatures":[{
            "header":{
                "kid":"did:example:alice#key-2"
            },
            "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
            "signature":"CCib-Bcx-eL93AHHydN5ofpcdBaPpbmg9uy86LHw3CwcWyGCt5eiCTXkVRWYiXqNOjWn03N_de-nmJsNKyaw1w"
        }],
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19"
    }
    "#;

    /*
    Bob key secp256k1
    {"crv":"secp256k1","kty":"EC","x":"FCdNdYmCb37E84HSXaXsJHNawM-njeWTjr1g-PIN5dU","y":"Ds3RWwX770Yoyr0gEgKfxxACGRQEZg1s8BnE51CvNp8","d":"QOa9-22EOgjEa9CKJMKSrEQwsssJTQUlNyuhHLE7r1M"}"
    */
    
    const BOB_MSG_K256: &str = r#"
    {
        "signatures":[{
            "header":{
                "kid":"did:example:alice#key-3"
            },
            "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
            "signature":"Jym1ZSzMJBq9hjOx0I0wG03I0nf2NySLt8GostuIQ3JE9hGluwhBBGeFaSATJt4OUEFsB_k0YuwPGSwbo3nKUw"
        }],
        "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19"
    }
    "#;
}
