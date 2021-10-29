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
            ErrorKind::InvalidState,
            "Unable to parse compactly serialized JWS",
        ));
    }

    let header = segments[0];
    let payload = segments[1];
    let signature = segments[2];

    base64::decode_config_buf(header, base64::URL_SAFE_NO_PAD, buf)
        .kind(ErrorKind::Malformed, "Unable decode protected header")?;

    let parsed_header: CompactHeader =
        serde_json::from_slice(buf).kind(ErrorKind::Malformed, "Unable parse protected header")?;

    Ok(ParsedCompactJWS {
        header,
        parsed_header,
        payload,
        signature,
    })
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
    use crate::jws::{CompactHeader, ParsedCompactJWS};

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

    #[test]
    fn parse_compact_works() {
        let msg =
            "eyJ0eXAiOiJleGFtcGxlLXR5cC0xIiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6ZXhhbXBsZTphbGlj\
             ZSNrZXktMSJ9\
             .\
             CiAgICB7ImlkIjoiMTIzNDU2Nzg5MCIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tcGxhaW4ranNv\
             biIsInR5cGUiOiJodHRwOi8vZXhhbXBsZS5jb20vcHJvdG9jb2xzL2xldHNfZG9fbHVuY2gvMS4wL3By\
             b3Bvc2FsIiwiZnJvbSI6ImRpZDpleGFtcGxlOmFsaWNlIiwidG8iOlsiZGlkOmV4YW1wbGU6Ym9iIl0s\
             ImNyZWF0ZWRfdGltZSI6MTUxNjI2OTAyMiwiZXhwaXJlc190aW1lIjoxNTE2Mzg1OTMxLCJib2R5Ijp7\
             Im1lc3NhZ2VzcGVjaWZpY2F0dHJpYnV0ZSI6ImFuZCBpdHMgdmFsdWUifX0KICAgIA\
             .\
             zaWcR-zXXYToP8xrzYsXQ905xxtVcpmiRObc5N5e8m-OAxmmbnEr0ZbA6DIxmSwGg_fy4EUQPRtd0qA6\
             mVRWDg";

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
            payload: "CiAgICB7ImlkIjoiMTIzNDU2Nzg5MCIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tcGxhaW4ranNv\
                      biIsInR5cGUiOiJodHRwOi8vZXhhbXBsZS5jb20vcHJvdG9jb2xzL2xldHNfZG9fbHVuY2gvMS4wL3By\
                      b3Bvc2FsIiwiZnJvbSI6ImRpZDpleGFtcGxlOmFsaWNlIiwidG8iOlsiZGlkOmV4YW1wbGU6Ym9iIl0s\
                      ImNyZWF0ZWRfdGltZSI6MTUxNjI2OTAyMiwiZXhwaXJlc190aW1lIjoxNTE2Mzg1OTMxLCJib2R5Ijp7\
                      Im1lc3NhZ2VzcGVjaWZpY2F0dHJpYnV0ZSI6ImFuZCBpdHMgdmFsdWUifX0KICAgIA",
            signature: "zaWcR-zXXYToP8xrzYsXQ905xxtVcpmiRObc5N5e8m-OAxmmbnEr0ZbA6DIxmSwGg_fy4EUQPRtd0qA6\
                        mVRWDg",
        };

        assert_eq!(res, exp);
    }
}
