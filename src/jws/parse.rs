use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jws::envelope::{ProtectedHeader, JWS},
};

pub(crate) struct ParsedJWS<'a, 'b> {
    pub(crate) jws: JWS<'a>,
    pub(crate) protected: Vec<ProtectedHeader<'b>>,
}

pub(crate) fn parse<'a, 'b>(jws: &'a str, buf: &'b mut Vec<Vec<u8>>) -> Result<ParsedJWS<'a, 'b>> {
    let jws: JWS = serde_json::from_str(jws).kind(ErrorKind::Malformed, "unable parse jws.")?;

    let protected = {
        let len = jws.signatures.len();
        let mut protected = Vec::<ProtectedHeader>::with_capacity(len);
        buf.resize(len, vec![]);

        for (i, b) in buf.iter_mut().enumerate() {
            let signature = jws
                .signatures
                .get(i)
                .ok_or_else(|| err_msg(ErrorKind::InvalidState, "invalid signature index."))?;

            base64::decode_config_buf(signature.protected, base64::URL_SAFE_NO_PAD, b)
                .kind(ErrorKind::Malformed, "unable decode protected header.")?;

            let p: ProtectedHeader =
                serde_json::from_slice(b).kind(ErrorKind::Malformed, "unable parse protected header.")?;

            protected.push(p);
        }

        protected
    };

    Ok(ParsedJWS { jws, protected })
}
