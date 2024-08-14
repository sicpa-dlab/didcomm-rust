type SecretType =
    "JsonWebKey2020" | "X25519KeyAgreementKey2019"
    | "Ed25519VerificationKey2018" | "EcdsaSecp256k1VerificationKey2019" | string

export class Secret {
    /**
     * A key ID identifying a secret (private key).
     */
    id: string;

    /**
     * Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
     */
    type: SecretType;

    /**
     * Possible value of the secret (private key)
     */
    privateKeyJwk: any;
}
