export const BOB_DID_DOC = {
  did: "did:example:bob",
  key_agreements: [
    "did:example:bob#key-x25519-1",
    "did:example:bob#key-x25519-2",
    "did:example:bob#key-x25519-3",
    "did:example:bob#key-p256-1",
    "did:example:bob#key-p256-2",
    "did:example:bob#key-p384-1",
    "did:example:bob#key-p384-2",
    "did:example:bob#key-p521-1",
    "did:example:bob#key-p521-2",
  ],
  authentications: [],
  verification_methods: [
    {
      id: "did:example:bob#key-x25519-1",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-x25519-1",
      verification_material: {
        JWK: {
          crv: "X25519",
          kty: "OKP",
          x: "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
        },
      },
    },
    {
      id: "did:example:bob#key-x25519-2",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-x25519-2",
      verification_material: {
        JWK: {
          crv: "X25519",
          kty: "OKP",
          x: "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
        },
      },
    },
    {
      id: "did:example:bob#key-x25519-3",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-x25519-3",
      verification_material: {
        JWK: {
          crv: "X25519",
          kty: "OKP",
          x: "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
        },
      },
    },
    {
      id: "did:example:bob#key-p256-1",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-p256-1",
      verification_material: {
        JWK: {
          crv: "P-256",
          kty: "EC",
          x: "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
          y: "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
        },
      },
    },
    {
      id: "did:example:bob#key-p256-2",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-p256-2",
      verification_material: {
        JWK: {
          crv: "P-256",
          kty: "EC",
          x: "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
          y: "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
        },
      },
    },
    {
      id: "did:example:bob#key-p384-1",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-p384-1",
      verification_material: {
        JWK: {
          crv: "P-384",
          kty: "EC",
          x: "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
          y: "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
        },
      },
    },
    {
      id: "did:example:bob#key-p384-2",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-p384-2",
      verification_material: {
        JWK: {
          crv: "P-384",
          kty: "EC",
          x: "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
          y: "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
        },
      },
    },
    {
      id: "did:example:bob#key-p521-1",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-p521-1",
      verification_material: {
        JWK: {
          crv: "P-521",
          kty: "EC",
          x: "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
          y: "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
        },
      },
    },
    {
      id: "did:example:bob#key-p521-2",
      type: "JsonWebKey2020",
      controller: "did:example:bob#key-p521-2",
      verification_material: {
        JWK: {
          crv: "P-521",
          kty: "EC",
          x: "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
          y: "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH",
        },
      },
    },
  ],
  services: [],
};
