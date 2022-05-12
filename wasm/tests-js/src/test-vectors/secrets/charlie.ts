import { Secret } from "didcomm";

export const CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519: Secret = {
  id: "did:example:charlie#key-x25519-1",
  type: "JsonWebKey2020",
  secret_material: {
    format: "JWK",
    value: {
      crv: "X25519",
      d: "Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
      kty: "OKP",
      x: "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
    },
  },
};

export const CHARLIE_SECRET_AUTH_KEY_ED25519: Secret = {
  id: "did:example:charlie#key-1",
  type: "JsonWebKey2020",
  secret_material: {
    format: "JWK",
    value: {
      crv: "Ed25519",
      d: "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
      kty: "OKP",
      x: "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
    },
  },
};

export const CHARLIE_SECRETS: Secret[] = [
  CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519,
  CHARLIE_SECRET_AUTH_KEY_ED25519,
];
