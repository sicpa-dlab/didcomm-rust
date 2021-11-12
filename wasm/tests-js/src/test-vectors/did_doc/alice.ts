export const ALICE_DID_DOC = {
    "did": "did:example:alice",
    "key_agreements": [
        "did:example:alice#key-x25519-not-in-secrets-1",
        "did:example:alice#key-x25519-1",
        "did:example:alice#key-p256-1",
        "did:example:alice#key-p521-1"
    ],
    "authentications": [
        "did:example:alice#key-1",
        "did:example:alice#key-2",
        "did:example:alice#key-3"
    ],
    "verification_methods": [
        {
            "id": "did:example:alice#key-x25519-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice#key-x25519-1",
            "verification_material": {
                "JWK": {
                    "crv": "X25519",
                    "kty": "OKP",
                    "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
                }
            }
        },
        {
            "id": "did:example:alice#key-p256-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice#key-p256-1",
            "verification_material": {
                "JWK": {
                    "crv": "P-256",
                    "kty": "EC",
                    "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                    "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
                }
            }
        },
        {
            "id": "did:example:alice#key-p521-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice#key-p521-1",
            "verification_material": {
                "JWK": {
                    "crv": "P-521",
                    "kty": "EC",
                    "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
                    "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk"
                }
            }
        },
        {
            "id": "did:example:alice#key-not-in-secrets-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice#key-not-in-secrets-1",
            "verification_material": {
                "JWK": {
                    "crv": "Ed25519",
                    "kty": "OKP",
                    "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                }
            }
        },
        {
            "id": "did:example:alice#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice#key-1",
            "verification_material": {
                "JWK": {
                    "crv": "Ed25519",
                    "kty": "OKP",
                    "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                }
            }
        },
        {
            "id": "did:example:alice#key-2",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice#key-2",
            "verification_material": {
                "JWK": {
                    "crv": "P-256",
                    "kty": "EC",
                    "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                    "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
                }
            }
        },
        {
            "id": "did:example:alice#key-3",
            "type": "JsonWebKey2020",
            "controller": "did:example:alice#key-3",
            "verification_material": {
                "JWK": {
                    "crv": "secp256k1",
                    "kty": "EC",
                    "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                    "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
                }
            }
        }
    ],
    "services": [
    ]
};