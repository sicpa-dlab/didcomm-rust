import { DIDDoc } from "didcomm";

export const CHARLIE_DID_DOC: DIDDoc = {
  did: "did:example:charlie",
  key_agreements: ["did:example:charlie#key-x25519-1"],
  authentications: ["did:example:charlie#key-1"],
  verification_methods: [
    {
      id: "did:example:charlie#key-x25519-1",
      type: "JsonWebKey2020",
      controller: "did:example:charlie#key-x25519-1",
      verification_material: {
        JWK: {
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
        JWK: {
          crv: "Ed25519",
          kty: "OKP",
          x: "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
        },
      },
    },
  ],
  services: [],
};
