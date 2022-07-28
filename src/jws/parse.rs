use crate::error::ToResult;
use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jws::envelope::{CompactHeader, ProtectedHeader, JWS},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedJWS<'a, 'b> {
    pub(crate) jws: JWS<'a>,
    pub(crate) protected: Vec<ProtectedHeader<'b>>,
}

pub(crate) fn parse<'a, 'b>(jws: &'a str, buf: &'b mut Vec<Vec<u8>>) -> Result<ParsedJWS<'a, 'b>> {
    JWS::from_str(jws)?.parse(buf)
}

impl<'a> JWS<'a> {
    pub(crate) fn from_str(s: &str) -> Result<JWS> {
        serde_json::from_str(s).to_didcomm("Unable parse jws")
    }

    pub(crate) fn parse<'b>(self, buf: &'b mut Vec<Vec<u8>>) -> Result<ParsedJWS<'a, 'b>> {
        let protected = {
            let len = self.signatures.len();
            let mut protected = Vec::<ProtectedHeader>::with_capacity(len);
            buf.resize(len, vec![]);

            for (i, b) in buf.iter_mut().enumerate() {
                let signature = self
                    .signatures
                    .get(i)
                    .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Invalid signature index"))?;

                base64::decode_config_buf(signature.protected, base64::URL_SAFE_NO_PAD, b)
                    .kind(ErrorKind::Malformed, "Unable decode protected header")?;

                let p: ProtectedHeader =
                    serde_json::from_slice(b).to_didcomm("Unable parse protected header")?;

                protected.push(p);
            }

            protected
        };

        Ok(ParsedJWS {
            jws: self,
            protected,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedCompactJWS<'a> {
    pub(crate) header: &'a str,
    pub(crate) parsed_header: CompactHeader<'a>,
    pub(crate) payload: &'a str,
    pub(crate) signature: &'a str,
}

pub(crate) fn parse_compact<'a>(
    compact_jws: &'a str,
    buf: &'a mut Vec<u8>,
) -> Result<ParsedCompactJWS<'a>> {
    let segments: Vec<&str> = compact_jws.split('.').collect();
    if segments.len() != 3 {
        return Err(err_msg(
            ErrorKind::Malformed,
            "Unable to parse compactly serialized JWS",
        ));
    }

    let header = segments[0];
    let payload = segments[1];
    let signature = segments[2];

    base64::decode_config_buf(header, base64::URL_SAFE_NO_PAD, buf)
        .kind(ErrorKind::Malformed, "Unable decode header")?;

    let parsed_header: CompactHeader =
        serde_json::from_slice(buf).kind(ErrorKind::Malformed, "Unable parse header")?;

    Ok(ParsedCompactJWS {
        header,
        parsed_header,
        payload,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use crate::jws::{CompactHeader, ParsedCompactJWS};
    use crate::{
        error::ErrorKind,
        jws::{
            self,
            envelope::{Algorithm, Header, ProtectedHeader, Signature, JWS},
            ParsedJWS,
        },
    };
    use std::borrow::Cow;

    #[test]
    fn parse_works() {
        let msg = r#"
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

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWS {
            jws: JWS {
                signatures: vec![Signature {
                    header: Header { kid: "did:example:alice#key-1" },
                    protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                    signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                }],
                payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            },
            protected: vec![ProtectedHeader {
                typ: Cow::Borrowed("application/didcomm-signed+json"),
                alg: Algorithm::EdDSA,
            }],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_unknown_fields() {
        let msg = r#"
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
            ],
            "extra":"value"
         }
        "#;

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWS {
            jws: JWS {
                signatures: vec![Signature {
                    header: Header { kid: "did:example:alice#key-1" },
                    protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                    signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                }],
                payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            },
            protected: vec![ProtectedHeader {
                typ: Cow::Borrowed("application/didcomm-signed+json"),
                alg: Algorithm::EdDSA,
            }],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_protected_unknown_fields() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EiLCJleHRyYSI6InZhbHVlIn0",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                     "kid":"did:example:alice#key-1"
                  }
               }
            ]
         }
        "#;

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWS {
            jws: JWS {
                signatures: vec![Signature {
                    header: Header { kid: "did:example:alice#key-1" },
                    protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EiLCJleHRyYSI6InZhbHVlIn0",
                    signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                }],
                payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            },
            protected: vec![ProtectedHeader {
                typ: Cow::Borrowed("application/didcomm-signed+json"),
                alg: Algorithm::EdDSA,
            }],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_multiple_signatures() {
        let msg = r#"
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
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header":{
                   "kid":"did:example:alice#key-2"
                }
             }
            ]
         }
        "#;

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedJWS {
            jws: JWS {
                signatures: vec![
                    Signature {
                        header: Header { kid: "did:example:alice#key-1" },
                        protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                        signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                    },
                    Signature {
                        header: Header { kid: "did:example:alice#key-2" },
                        protected: "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                        signature: "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                    }
                ],
                payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            },
            protected: vec![
                ProtectedHeader {
                  typ: Cow::Borrowed("application/didcomm-signed+json"),
                  alg: Algorithm::EdDSA,
                },
                ProtectedHeader {
                    typ: Cow::Borrowed("application/didcomm-signed+json"),
                 alg: Algorithm::EdDSA,
                }
            ],
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_works_unparsable() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                     "kid":"did:example:alice#key-1",
                  }
               }
            ]
         }
        "#;

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse jws: trailing comma at line 10 column 19"
        );
    }

    #[test]
    fn parse_works_misstructured() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
            {
                "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header":{
                }
            }
            ]
        }
        "#;

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse jws: missing field `kid` at line 9 column 17"
        );
    }

    #[test]
    fn parse_works_undecodable_protected() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"!eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                    "kid":"did:example:alice#key-1"
                 }
               }
            ]
         }
        "#;

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable decode protected header: Invalid byte 33, offset 0."
        );
    }

    #[test]
    fn parse_works_unparsable_protected() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"ey4idHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1zaWduZWQranNvbiIsImFsZyI6IkVkRFNBIn0",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                    "kid":"did:example:alice#key-1"
                 }
               }
            ]
         }
        "#;

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse protected header: key must be a string at line 1 column 2"
        );
    }

    #[test]
    fn parse_works_misstructured_protected() {
        let msg = r#"
        {
            "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures":[
               {
                  "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIn0",
                  "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                  "header":{
                    "kid":"did:example:alice#key-1"
                 }
               }
            ]
         }
        "#;

        let mut buf = vec![];
        let res = jws::parse(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse protected header: missing field `alg` at line 1 column 41"
        );
    }

    #[test]
    fn parse_compact_works() {
        let msg =
            "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let mut buf = vec![];
        let res = jws::parse_compact(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedCompactJWS {
            header: "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
                     ZSNrZXktMSJ9",
            parsed_header: CompactHeader {
                typ: "example-typ-1",
                alg: Algorithm::EdDSA,
                kid: "did:example:alice#key-1",
            },
            payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
                      eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
                      bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
                      dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
                      YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            signature: "iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
                        bHgtCg",
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_compact_works_header_unknown_fields() {
        let msg =
            "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSIsImV4dHJhIjoidmFsdWUifQ\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let mut buf = vec![];
        let res = jws::parse_compact(&msg, &mut buf);
        let res = res.expect("res is err");

        let exp = ParsedCompactJWS {
            header: "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
                     ZSNrZXktMSIsImV4dHJhIjoidmFsdWUifQ",
            parsed_header: CompactHeader {
                typ: "example-typ-1",
                alg: Algorithm::EdDSA,
                kid: "did:example:alice#key-1",
            },
            payload: "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
                      eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
                      bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
                      dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
                      YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            signature: "iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
                        bHgtCg",
        };

        assert_eq!(res, exp);
    }

    #[test]
    fn parse_compact_works_too_few_segments() {
        let msg =
            "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19";

        let mut buf = vec![];
        let res = jws::parse_compact(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable to parse compactly serialized JWS"
        );
    }

    #[test]
    fn parse_compact_works_too_many_segments() {
        let msg =
            "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg\
             .\
             eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9";

        let mut buf = vec![];
        let res = jws::parse_compact(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable to parse compactly serialized JWS"
        );
    }

    #[test]
    fn parse_compact_works_undecodable_header() {
        let msg =
            "!eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let mut buf = vec![];
        let res = jws::parse_compact(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable decode header: Encoded text cannot have a 6-bit remainder."
        );
    }

    #[test]
    fn parse_compact_works_unparsable_header() {
        let msg =
            "ey4idHlwIjoiZXhhbXBsZS10eXAtMSIsImFsZyI6IkVkRFNBIiwia2lkIjoiZGlkOmV4YW1wbGU6YWxp\
             Y2Uja2V5LTEifQ\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let mut buf = vec![];
        let res = jws::parse_compact(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse header: key must be a string at line 1 column 2"
        );
    }

    #[test]
    fn parse_compact_works_misstructured_header() {
        let msg = "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwia2lkIjoiZGlkOmV4YW1wbGU6YWxpY2Uja2V5LTEifQ\
             .\
             eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0\
             eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh\
             bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh\
             dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz\
             YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19\
             .\
             iMi3kOWHTWoKiuTT4JxD9CkcUwSby9ekpOQk0Xdm9_H6jDpLPuhfX4U2EYgdPIJERl95MIecEhrufvO4\
             bHgtCg";

        let mut buf = vec![];
        let res = jws::parse_compact(&msg, &mut buf);

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", err),
            "Malformed: Unable parse header: missing field `alg` at line 1 column 55"
        );
    }
}
