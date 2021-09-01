use askar_crypto::sign::KeySign;

use crate::{
    error::{ErrorKind, Result, ResultExt},
    jws::envelope::{Algorithm, Header, ProtectedHeader, Signature, JWS},
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
            .kind(ErrorKind::InvalidState, "unable serialize protectd header.")?;

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
            .kind(ErrorKind::InvalidState, "unable create signature.")?;

        base64::encode_config(&signature, base64::URL_SAFE_NO_PAD)
    };

    let signature = Signature {
        header: Header { kid },
        protected: &protected,
        signature: &signature,
    };

    let jws = JWS {
        signatures: vec![signature],
        payload: &&payload,
    };

    let jws = serde_json::to_string(&jws).kind(ErrorKind::InvalidState, "unable serialize jws.")?;

    Ok(jws)
}
