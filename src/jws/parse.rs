use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jws::envelope::{ProtectedHeader, JWS},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedJWS<'a, 'b> {
    pub(crate) jws: JWS<'a>,
    pub(crate) protected: Vec<ProtectedHeader<'b>>,
}

pub(crate) fn is_jws(msg: &str) -> bool {
    msg.contains("payload") || msg.contains("signatures")
}

pub(crate) fn parse<'a, 'b>(jws: &'a str, buf: &'b mut Vec<Vec<u8>>) -> Result<ParsedJWS<'a, 'b>> {
    let jws: JWS = serde_json::from_str(jws).kind(ErrorKind::Malformed, "Unable parse jws")?;

    let protected = {
        let len = jws.signatures.len();
        let mut protected = Vec::<ProtectedHeader>::with_capacity(len);
        buf.resize(len, vec![]);

        for (i, b) in buf.iter_mut().enumerate() {
            let signature = jws
                .signatures
                .get(i)
                .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Invalid signature index"))?;

            base64::decode_config_buf(signature.protected, base64::URL_SAFE_NO_PAD, b)
                .kind(ErrorKind::Malformed, "Unable decode protected header")?;

            let p: ProtectedHeader = serde_json::from_slice(b)
                .kind(ErrorKind::Malformed, "Unable parse protected header")?;

            protected.push(p);
        }

        protected
    };

    Ok(ParsedJWS { jws, protected })
}

#[cfg(test)]
mod tests {
    use crate::{
        error::ErrorKind,
        jws::{
            self,
            envelope::{Algorithm, Header, ProtectedHeader, Signature, JWS},
            ParsedJWS,
        },
    };

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
                typ: "application/didcomm-signed+json",
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
                typ: "application/didcomm-signed+json",
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
                typ: "application/didcomm-signed+json",
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
                  typ: "application/didcomm-signed+json",
                  alg: Algorithm::EdDSA,
                },
                ProtectedHeader {
                    typ: "application/didcomm-signed+json",
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

        let res = res.expect_err("res is ok");
        assert_eq!(res.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", res),
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

        let res = res.expect_err("res is ok");
        assert_eq!(res.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", res),
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

        let res = res.expect_err("res is ok");
        assert_eq!(res.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", res),
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

        let res = res.expect_err("res is ok");
        assert_eq!(res.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", res),
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
                  "protected":"InR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tc2lnbmVkK2pzb24ifQ",
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

        let res = res.expect_err("res is ok");
        assert_eq!(res.kind(), ErrorKind::Malformed);

        assert_eq!(
            format!("{}", res),
            "Malformed: Unable parse protected header: invalid type: string \"typ\", expected struct ProtectedHeader at line 1 column 5"
        );
    }
}
