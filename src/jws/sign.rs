use askar_crypto::sign::KeySign;

use crate::{
    error::{ErrorKind, Result, ResultExt},
    jws::envelope::{Algorithm, Header, ProtectedHeader, CompactHeader, Signature, JWS},
};

pub(crate) fn sign<Key: KeySign>(
    payload: &[u8],
    signer: (&str, &Key),
    alg: Algorithm,
) -> Result<String> {
    let (kid, key) = signer;

    let sig_type = alg.sig_type()?;

    let protected = {
        let protected = ProtectedHeader {
            typ: "application/didcomm-signed+json",
            alg,
        };

        let protected = serde_json::to_string(&protected)
            .kind(ErrorKind::InvalidState, "Unable serialize protectd header")?;

        base64::encode_config(protected, base64::URL_SAFE_NO_PAD)
    };

    let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

    let signature = {
        // JWS Signing Input
        // The input to the digital signature or MAC computation.  Its value
        // is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
        let sign_input = format!("{}.{}", protected, payload);

        let signature = key
            .create_signature(sign_input.as_bytes(), Some(sig_type))
            .kind(ErrorKind::InvalidState, "Unable create signature")?;

        base64::encode_config(&signature, base64::URL_SAFE_NO_PAD)
    };

    let signature = Signature {
        header: Header { kid },
        protected: &protected,
        signature: &signature,
    };

    let jws = JWS {
        signatures: vec![signature],
        payload: &payload,
    };

    let jws = serde_json::to_string(&jws).kind(ErrorKind::InvalidState, "Unable serialize jws")?;

    Ok(jws)
}

pub(crate) fn sign_compact<Key: KeySign>(
    payload: &[u8],
    signer: (&str, &Key),
    typ: &str,
    alg: Algorithm,
) -> Result<String> {
    let (kid, key) = signer;

    let sig_type = alg.sig_type()?;

    let header = {
        let header = CompactHeader {
            typ,
            alg,
            kid,
        };

        let header = serde_json::to_string(&header)
            .kind(ErrorKind::InvalidState, "Unable serialize header")?;

        base64::encode_config(header, base64::URL_SAFE_NO_PAD)
    };

    let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

    let signature = {
        // JWS Signing Input
        // The input to the digital signature or MAC computation.  Its value
        // is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
        let sign_input = format!("{}.{}", header, payload);

        let signature = key
            .create_signature(sign_input.as_bytes(), Some(sig_type))
            .kind(ErrorKind::InvalidState, "Unable create signature")?;

        base64::encode_config(&signature, base64::URL_SAFE_NO_PAD)
    };

    let compact_jws = format!("{}.{}.{}", header, payload, signature);

    Ok(compact_jws)
}

#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair},
        jwk::FromJwk,
        sign::{KeySigVerify, KeySign},
    };

    use crate::{
        error::{ErrorKind, Result},
        jws::{self, envelope::Algorithm},
    };

    #[test]
    fn sign_works() {
        _sign_works::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_KEY_ED25519,
            ALICE_PKEY_ED25519,
            Algorithm::EdDSA,
            PAYLOAD,
        );

        _sign_works::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_KEY_P256,
            ALICE_PKEY_P256,
            Algorithm::Es256,
            PAYLOAD,
        );

        _sign_works::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_KEY_K256,
            ALICE_PKEY_K256,
            Algorithm::Es256K,
            PAYLOAD,
        );

        fn _sign_works<K: FromJwk + KeySign + KeySigVerify>(
            kid: &str,
            key: &str,
            pkey: &str,
            alg: Algorithm,
            payload: &str,
        ) {
            let res = _sign::<K>(kid, key, alg.clone(), payload);

            let msg = res.expect("Unable _sign");

            let mut buf = vec![];
            let msg = jws::parse(&msg, &mut buf).expect("Unable parse.");

            assert_eq!(
                msg.jws.payload,
                base64::encode_config(payload, base64::URL_SAFE_NO_PAD)
            );

            assert_eq!(msg.jws.signatures.len(), 1);
            assert_eq!(msg.jws.signatures[0].header.kid, kid);

            assert_eq!(msg.protected.len(), 1);
            assert_eq!(msg.protected[0].alg, alg);
            assert_eq!(msg.protected[0].typ, "application/didcomm-signed+json");

            let pkey = K::from_jwk(pkey).expect("unable from_jwk");
            let valid = msg.verify::<K>((kid, &pkey)).expect("Unable verify");

            assert!(valid);
        }
    }

    #[test]
    fn sign_works_incompatible_alg() {
        _sign_works_incompatible_alg::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_KEY_ED25519,
            Algorithm::Es256,
            PAYLOAD,
        );

        _sign_works_incompatible_alg::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_KEY_ED25519,
            Algorithm::Es256K,
            PAYLOAD,
        );

        _sign_works_incompatible_alg::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_KEY_P256,
            Algorithm::Es256K,
            PAYLOAD,
        );

        _sign_works_incompatible_alg::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_KEY_P256,
            Algorithm::EdDSA,
            PAYLOAD,
        );

        _sign_works_incompatible_alg::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_KEY_P256,
            Algorithm::Es256K,
            PAYLOAD,
        );

        _sign_works_incompatible_alg::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_KEY_K256,
            Algorithm::Es256,
            PAYLOAD,
        );

        _sign_works_incompatible_alg::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_KEY_K256,
            Algorithm::EdDSA,
            PAYLOAD,
        );

        _sign_works_incompatible_alg::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_KEY_K256,
            Algorithm::Es256,
            PAYLOAD,
        );

        fn _sign_works_incompatible_alg<K: FromJwk + KeySign + KeySigVerify>(
            kid: &str,
            key: &str,
            alg: Algorithm,
            payload: &str,
        ) {
            let res = _sign::<K>(kid, key, alg.clone(), payload);

            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::InvalidState);

            assert_eq!(
                format!("{}", err),
                "Invalid state: Unable create signature: Unsupported signature type"
            );
        }
    }

    #[test]
    fn sign_works_unknown_alg() {
        _sign_works_unknown_alg::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_KEY_ED25519,
            Algorithm::Other("bls".to_owned()),
            PAYLOAD,
        );

        _sign_works_unknown_alg::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_KEY_P256,
            Algorithm::Other("bls".to_owned()),
            PAYLOAD,
        );

        _sign_works_unknown_alg::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_KEY_K256,
            Algorithm::Other("bls".to_owned()),
            PAYLOAD,
        );

        fn _sign_works_unknown_alg<K: FromJwk + KeySign + KeySigVerify>(
            kid: &str,
            key: &str,
            alg: Algorithm,
            payload: &str,
        ) {
            let res = _sign::<K>(kid, key, alg.clone(), payload);

            let err = res.expect_err("res is ok");
            assert_eq!(err.kind(), ErrorKind::Unsupported);

            assert_eq!(
                format!("{}", err),
                "Unsupported crypto or method: Unsuported signature type"
            );
        }
    }

    #[test]
    fn sign_compact_works() {
        _sign_compact_works::<Ed25519KeyPair>(
            ALICE_KID_ED25519,
            ALICE_KEY_ED25519,
            ALICE_PKEY_ED25519,
            "example-typ-1",
            Algorithm::EdDSA,
            PAYLOAD,
        );

        _sign_compact_works::<P256KeyPair>(
            ALICE_KID_P256,
            ALICE_KEY_P256,
            ALICE_PKEY_P256,
            "example-typ-2",
            Algorithm::Es256,
            PAYLOAD,
        );

        _sign_compact_works::<K256KeyPair>(
            ALICE_KID_K256,
            ALICE_KEY_K256,
            ALICE_PKEY_K256,
            "example-typ-3",
            Algorithm::Es256K,
            PAYLOAD,
        );

        fn _sign_compact_works<K: FromJwk + KeySign + KeySigVerify>(
            kid: &str,
            key: &str,
            pkey: &str,
            typ: &str,
            alg: Algorithm,
            payload: &str,
        ) {
            let res =
                _sign_compact::<K>(kid, key, typ, alg.clone(), payload);

            let msg = res.expect("Unable _sign_compact");

            let mut buf = vec![];
            let msg = jws::parse_compact(&msg, &mut buf)
                .expect("Unable parse_compact.");

            assert_eq!(
                msg.payload,
                base64::encode_config(payload, base64::URL_SAFE_NO_PAD)
            );

            assert_eq!(msg.parsed_header.typ, typ);
            assert_eq!(msg.parsed_header.alg, alg);
            assert_eq!(msg.parsed_header.kid, kid);

            let pkey = K::from_jwk(pkey).expect("unable from_jwk");
            let valid = msg.verify::<K>(&pkey).expect("Unable verify");

            assert!(valid);
        }
    }

    fn _sign<K: FromJwk + KeySign>(
        kid: &str,
        key: &str,
        alg: Algorithm,
        payload: &str,
    ) -> Result<String> {
        let key = K::from_jwk(key).expect("unable from_jwk.");
        jws::sign(payload.as_bytes(), (&kid, &key), alg.clone())
    }

    fn _sign_compact<K: FromJwk + KeySign>(
        kid: &str,
        key: &str,
        typ: &str,
        alg: Algorithm,
        payload: &str,
    ) -> Result<String> {
        let key = K::from_jwk(key).expect("unable from_jwk.");
        jws::sign_compact(payload.as_bytes(), (&kid, &key), typ, alg.clone())
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

    const PAYLOAD: &str = r#"
    {"id":"1234567890","typ":"application/didcomm-plain+json","type":"http://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:alice","to":["did:example:bob"],"created_time":1516269022,"expires_time":1516385931,"body":{"messagespecificattribute":"and its value"}}
    "#;
}
