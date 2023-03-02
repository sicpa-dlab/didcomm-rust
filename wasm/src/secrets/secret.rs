use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const SECRET_TS: &'static str = r#"
/**
 * Represents secret.
 */
type Secret = {
    /**
     * A key ID identifying a secret (private key).
     */
    id: string,

    /**
     * Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
     */
    type: SecretType,

    /**
     * Possible value of the secret (private key)
     */
    privateKeyJwk?: any,
    privateKeyMultibase?: string,
    privateKeyBase58?: string,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const SECRET_TYPE_TS: &'static str = r#"
/**
 * Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
 */
type SecretType =
    "JsonWebKey2020" | "X25519KeyAgreementKey2019" 
    | "Ed25519VerificationKey2018" | "EcdsaSecp256k1VerificationKey2019" | string
"#;
