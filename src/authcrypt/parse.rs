use sha2::{Digest, Sha256};

use crate::{
    authcrypt::envelope::{ProtectedHeader, JWE},
    error::{err_msg, ErrorKind, Result, ResultExt},
};

pub(crate) struct ParsedJWE<'a, 'b> {
    pub(crate) jwe: JWE<'a>,
    pub(crate) protected: ProtectedHeader<'b>,
    pub(crate) skid: String,
}

pub(crate) fn parse<'a, 'b>(jwe: &'a str, buf: &'b mut Vec<u8>) -> Result<ParsedJWE<'a, 'b>> {
    let jwe: JWE = serde_json::from_str(jwe).kind(ErrorKind::InvalidState, "unable parse JWE.")?;

    base64::decode_config_buf(jwe.protected, base64::URL_SAFE_NO_PAD, buf)
        .kind(ErrorKind::InvalidState, "unable parse JWE.")?;

    let protected: ProtectedHeader =
        serde_json::from_slice(buf).kind(ErrorKind::InvalidState, "unable parse JWE.")?;

    let apv = {
        let mut kids = jwe
            .recipients
            .iter()
            .map(|r| r.header.kid)
            .collect::<Vec<_>>();

        kids.sort();
        let apv = Sha256::digest(kids.join(".").as_bytes());
        base64::encode_config(apv, base64::URL_SAFE_NO_PAD)
    };

    if protected.apv != apv {
        Err(err_msg(ErrorKind::Malformed, "apv mismatch."))?;
    }

    let skid = {
        let skid = base64::decode_config(protected.apu, base64::URL_SAFE_NO_PAD)
            .kind(ErrorKind::InvalidState, "unable parse apv.")?;

        String::from_utf8(skid).kind(ErrorKind::InvalidState, "unable parse apv.")?
    };

    if let Some(pskid) = protected.skid {
        if skid != pskid {
            Err(err_msg(ErrorKind::Malformed, "apu mismatch."))?;
        }
    }

    let jwe = ParsedJWE {
        jwe,
        protected,
        skid,
    };

    Ok(jwe)
}
