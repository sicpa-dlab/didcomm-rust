import { Secret } from "..";

export const CHARLIE_ROTATED_TO_ALICE_SECRETS: Secret[] = [
  {
    id: "did:example:charlie#key-x25519-1",
    type: "JsonWebKey2020",
    privateKeyJwk: {
      crv: "X25519",
      d: "Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
      kty: "OKP",
      x: "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
    },
  },
  {
    id: "did:example:charlie#key-1",
    type: "JsonWebKey2020",
    privateKeyJwk: {
      crv: "Ed25519",
      d: "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
      kty: "OKP",
      x: "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
    },
  },
  {
    id: "did:example:alice#key-1",
    type: "JsonWebKey2020",
    privateKeyJwk: {
      crv: "Ed25519",
      d: "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
      kty: "OKP",
      x: "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
    },
  },
  {
    id: "did:example:alice#key-2",
    type: "JsonWebKey2020",
    privateKeyJwk: {
      crv: "P-256",
      d: "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
      kty: "EC",
      x: "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
      y: "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
    },
  },
  {
    id: "did:example:alice#key-3",
    type: "JsonWebKey2020",
    privateKeyJwk: {
      crv: "secp256k1",
      d: "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
      kty: "EC",
      x: "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
      y: "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk",
    },
  },
  {
    id: "did:example:alice#key-x25519-1",
    type: "JsonWebKey2020",
    privateKeyJwk: {
      crv: "X25519",
      d: "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
      kty: "OKP",
      x: "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
    },
  },
  {
    id: "did:example:alice#key-p256-1",
    type: "JsonWebKey2020",
    privateKeyJwk: {
      crv: "P-256",
      d: "sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
      kty: "EC",
      x: "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
      y: "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
    },
  },
  {
    id: "did:example:alice#key-p521-1",
    type: "JsonWebKey2020",
    privateKeyJwk: {
      crv: "P-521",
      d: "AQCQKE7rZpxPnX9RgjXxeywrAMp1fJsyFe4cir1gWj-8t8xWaM_E2qBkTTzyjbRBu-JPXHe_auT850iYmE34SkWi",
      kty: "EC",
      x: "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
      y: "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk",
    },
  },
];
