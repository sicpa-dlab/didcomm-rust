import { DIDDoc } from "didcomm";

export const CHARLIE_DID_DOC: DIDDoc = {
  id: "did:example:charlie",
  keyAgreement: ["did:example:charlie#key-x25519-1"],
  authentication: ["did:example:charlie#key-1"],
  verificationMethod: [
    {
      id: "did:example:charlie#key-x25519-1",
      type: "JsonWebKey2020",
      controller: "did:example:charlie#key-x25519-1",
      verification_material: {
        format: "JWK",
        value: {
          crv: "X25519",
          kty: "OKP",
          x: "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
        },
      },
    },
    {
      id: "did:example:charlie#key-1",
      type: "JsonWebKey2020",
      controller: "did:example:charlie#key-1",
      verification_material: {
        format: "JWK",
        value: {
          crv: "Ed25519",
          kty: "OKP",
          x: "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
        },
      },
    },
  ],
  service: [],
};
