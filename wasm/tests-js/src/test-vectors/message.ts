import { Message } from "didcomm";

export const IMESSAGE_SIMPLE = {
  id: "1234567890",
  typ: "application/didcomm-plain+json",
  type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
  from: "did:example:alice",
  to: ["did:example:bob"],
  created_time: 1516269022,
  expires_time: 1516385931,
  body: { messagespecificattribute: "and its value" },
};

export const MESSAGE_SIMPLE = new Message(IMESSAGE_SIMPLE);

export const IMESSAGE_MINIMAL = {
  id: "1234567890",
  typ: "application/didcomm-plain+json",
  type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
  body: {},
};

export const MESSAGE_MINIMAL = new Message(IMESSAGE_MINIMAL);

export const IMESSAGE_FROM_PRIOR = {
  id: "1234567890",
  typ: "application/didcomm-plain+json",
  type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
  from: "did:example:alice",
  to: ["did:example:bob"],
  created_time: 1516269022,
  expires_time: 1516385931,
  from_prior:
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOmNoYXJsaWUja2V5LTEifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpjaGFybGllIiwic3ViIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJhdWQiOiIxMjMiLCJleHAiOjEyMzQsIm5iZiI6MTIzNDUsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.ir0tegXiGJIZIMagO5P853KwhzGTEw0OpFFAyarUV-nQrtbI_ELbxT9l7jPBoPve_-60ifGJ9v3ArmFjELFlDA",
  body: { messagespecificattribute: "and its value" },
};

export const MESSAGE_FROM_PRIOR = new Message(IMESSAGE_FROM_PRIOR);

export const IFORWARD_MESSAGE = {
  id: "8404000a-1c6d-4c8c-8c60-e383128d9677",
  typ: "application/didcomm-plain+json",
  type: "https://didcomm.org/routing/2.0/forward",
  body: {
    next: "did:example:bob",
  },
  attachments: [
    {
      data: {
        json: {
          ciphertext:
            "ajYDBYyuuftb0f-pCj9iz7uhSJFK95F_WsXcXSKN2HrfPdojdRb9Ss_xI0zJnTC97yRmO9vmfyR8-MkQ_1gh-KyEHZe6UTM7JWpSWC9onReNLTOLaMoM09W8Fb45ZFbqaqZ1Kt3qvKIXEu2BwrZ2jLRu7r2Lo-cDJhDwzhHux27gd-j9Dhvtct3B2AMzXdu2J4fLqIdz9h0XkiI3PB4tLYsgY6KwDMtLyePDbb747bqViqWoBFgDLX2zgL3R9Okxt7RG4-1vqRHfURgcONofWMpFHEFq3WaplipogvuwouP3hJv3OMppBz2KTo1ULg3WWAdrac7laa2XQ6UE1PUo6Cq7IH7mdVoZwRc2v__swib6_WLTZMTW",
          iv: "hC-Frpywx0Pix6Lak-Rwlpw0IbG28rGo",
          protected:
            "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJYQzIwUCIsImFwdiI6Ik5jc3VBbnJSZlBLNjlBLXJrWjBMOVhXVUc0ak12TkMzWmc3NEJQejUzUEEiLCJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ikg0QURobjA0S1VnX1dXQWpiR0s3eTJ3QkQtTmtsbUhXa0lHUl9jeGtKMXcifX0",
          recipients: [
            {
              encrypted_key:
                "Bjk-DOK_2omU_LN13TEGs3WBAwWaimaAQVvtIdE4mmCW83M8kOWKfw",
              header: { kid: "did:example:bob#key-x25519-1" },
            },
            {
              encrypted_key:
                "SuPR0JolzyGPeNiaj9EoD822TsHXRLJbkyQgOnF_MG-DfPdQ5y2Eeg",
              header: { kid: "did:example:bob#key-x25519-2" },
            },
            {
              encrypted_key:
                "6H5qA6Hic0L2B_lzg6q37VbkmHoi8d82seRxswtXp9c1FpTg8cG76w",
              header: { kid: "did:example:bob#key-x25519-3" },
            },
          ],
          tag: "j4VLGYCa70LhHyDDLUDzKw",
        },
      },
    },
  ],
};

export const FORWARD_MESSAGE = new Message(IFORWARD_MESSAGE);
