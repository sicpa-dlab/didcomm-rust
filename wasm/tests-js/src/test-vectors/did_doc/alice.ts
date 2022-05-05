import { DIDDoc, VerificationMethod } from "didcomm";

export const ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET: VerificationMethod =
  {
    id: "did:example:alice#key-x25519-not-in-secrets-1",
    type: "JsonWebKey2020",
    controller: "did:example:alice#key-x25519-not-in-secrets-1",
    verification_material: {
      format: "JWK",
      value: {
        crv: "X25519",
        kty: "OKP",
        x: "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
      },
    },
  };

export const ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519: VerificationMethod = {
  id: "did:example:alice#key-x25519-1",
  type: "JsonWebKey2020",
  controller: "did:example:alice#key-x25519-1",
  verification_material: {
    format: "JWK",
    value: {
      crv: "X25519",
      kty: "OKP",
      x: "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
    },
  },
};

export const ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256: VerificationMethod = {
  id: "did:example:alice#key-p256-1",
  type: "JsonWebKey2020",
  controller: "did:example:alice#key-p256-1",
  verification_material: {
    format: "JWK",
    value: {
      crv: "P-256",
      kty: "EC",
      x: "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
      y: "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
    },
  },
};

export const ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521: VerificationMethod = {
  id: "did:example:alice#key-p521-1",
  type: "JsonWebKey2020",
  controller: "did:example:alice#key-p521-1",
  verification_material: {
    format: "JWK",
    value: {
      crv: "P-521",
      kty: "EC",
      x: "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
      y: "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk",
    },
  },
};

export const ALICE_AUTH_METHOD_25519: VerificationMethod = {
  id: "did:example:alice#key-1",
  type: "JsonWebKey2020",
  controller: "did:example:alice#key-1",
  verification_material: {
    format: "JWK",
    value: {
      crv: "Ed25519",
      kty: "OKP",
      x: "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
    },
  },
};

export const ALICE_AUTH_METHOD_P256: VerificationMethod = {
  id: "did:example:alice#key-2",
  type: "JsonWebKey2020",
  controller: "did:example:alice#key-2",
  verification_material: {
    format: "JWK",
    value: {
      crv: "P-256",
      kty: "EC",
      x: "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
      y: "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
    },
  },
};

export const ALICE_AUTH_METHOD_SECP256K1: VerificationMethod = {
  id: "did:example:alice#key-3",
  type: "JsonWebKey2020",
  controller: "did:example:alice#key-3",
  verification_material: {
    format: "JWK",
    value: {
      crv: "secp256k1",
      kty: "EC",
      x: "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
      y: "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk",
    },
  },
};

export const ALICE_DID_DOC: DIDDoc = {
  did: "did:example:alice",
  key_agreements: [
    "did:example:alice#key-x25519-not-in-secrets-1",
    "did:example:alice#key-x25519-1",
    "did:example:alice#key-p256-1",
    "did:example:alice#key-p521-1",
  ],
  authentications: [
    "did:example:alice#key-1",
    "did:example:alice#key-2",
    "did:example:alice#key-3",
  ],
  verification_methods: [
    ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET,
    ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
    ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
    ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521,
    ALICE_AUTH_METHOD_25519,
    ALICE_AUTH_METHOD_P256,
    ALICE_AUTH_METHOD_SECP256K1,
  ],
  services: [],
};
