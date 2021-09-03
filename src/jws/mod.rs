// TODO: Remove allow
#[allow(dead_code)]
mod envelope;

// TODO: Remove allow
#[allow(dead_code)]
mod parse;

// TODO: Remove allow
#[allow(dead_code)]
mod sign;

// TODO: Remove allow
#[allow(dead_code)]
mod verify;

// TODO: Remove allow
#[allow(unused_imports)]
pub(crate) use sign::sign;

// TODO: Remove allow
#[allow(unused_imports)]
pub(crate) use parse::{parse, ParsedJWS};

#[cfg(test)]
mod tests {
    use askar_crypto::{alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair}, jwk::FromJwk, repr::{KeyGen, KeyPublicBytes, ToPublicBytes}, sign::KeySign};

    use crate::jws::{self, envelope::Algorithm};

    #[test]
    fn sign_verify_works() {
        _sign_verify_works::<Ed25519KeyPair>(Algorithm::EdDSA);

        // TODO: Uncomment after fixing https://github.com/hyperledger/aries-askar/issues/26
        //_sign_verify_works::<P256KeyPair>(Algorithm::Es256);

        _sign_verify_works::<K256KeyPair>(Algorithm::Es256K);

        fn _sign_verify_works<Key>(alg: Algorithm)
        where
            Key: KeySign + KeyGen + ToPublicBytes + KeyPublicBytes,
        {
            let alice_kid = "did:example:alice#key-1";
            let alice_key = Key::random().expect("unable random.");

            let alice_pkey = {
                let bytes = alice_key
                    .to_public_bytes()
                    .expect("unable to_public_bytes.");

                Key::from_public_bytes(&bytes).expect("unable from_public_bytes.")
            };

            let payload = "Some payload.";

            let msg = jws::sign(payload.as_bytes(), (&alice_kid, &alice_key), alg.clone())
                .expect("unable sign.");

            let mut buf = vec![];
            let msg = jws::parse(&msg, &mut buf).expect("unable parse.");

            assert_eq!(
                msg.jws.payload,
                base64::encode_config(payload, base64::URL_SAFE_NO_PAD)
            );

            assert_eq!(msg.jws.signatures.len(), 1);
            assert_eq!(msg.jws.signatures[0].header.kid, alice_kid);

            assert_eq!(msg.protected.len(), 1);
            assert_eq!(msg.protected[0].alg, alg);
            assert_eq!(msg.protected[0].typ, "application/didcomm-signed+json");

            let valid = msg
                .verify((alice_kid, &alice_pkey))
                .expect("unable verify.");

            assert!(valid);
        }
    }

    #[test]
    fn parse_verify_works() {
        _parse_verify_works::<Ed25519KeyPair>(
            "did:example:alice#key-1",
            r#"
            {
                "kty":"OKP",
                "d":"pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                "crv":"Ed25519",
                "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
             }
            "#,
            Algorithm::EdDSA,
            r#"
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
            "#,
            "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        );

        _parse_verify_works::<P256KeyPair>(
            "did:example:alice#key-2",
            r#"
            {
                "kty":"EC",
                "d":"7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
                "crv":"P-256",
                "x":"2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                "y":"BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
             }
            "#,
            Algorithm::Es256,
            r#"
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
            "#,
            "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        );

        _parse_verify_works::<K256KeyPair>(
            "did:example:alice#key-3",
            r#"
            {
                "kty":"EC",
                "d":"N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
                "crv":"secp256k1",
                "x":"aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                "y":"JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
             }
            "#,
            Algorithm::Es256K,
            r#"
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
            "#,
            "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        );

        fn _parse_verify_works<Key: KeySign + FromJwk + ToPublicBytes + KeyPublicBytes>(
            alice_kid: &str,
            alice_key: &str,
            alg: Algorithm,
            msg: &str,
            payload: &str,
        ) {
            let alice_key = Key::from_jwk(alice_key).expect("unable from_jwk.");

            let alice_pkey = {
                let bytes = alice_key
                    .to_public_bytes()
                    .expect("unable to_public_bytes.");

                Key::from_public_bytes(&bytes).expect("unable from_public_bytes.")
            };

            let mut buf = vec![];
            let msg = jws::parse(&msg, &mut buf).expect("unable parse.");

            assert_eq!(msg.jws.payload, payload);

            assert_eq!(msg.jws.signatures.len(), 1);
            assert_eq!(msg.jws.signatures[0].header.kid, alice_kid);

            assert_eq!(msg.protected.len(), 1);
            assert_eq!(msg.protected[0].alg, alg);
            assert_eq!(msg.protected[0].typ, "application/didcomm-signed+json");

            let valid = msg
                .verify((alice_kid, &alice_pkey))
                .expect("unable verify.");

            assert!(valid);
        }
    }
}
