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
     * Value of the secret (private key)
     */
    secret_material: SecretMaterial,
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

#[wasm_bindgen(typescript_custom_section)]
const SECRET_MATERIAL_FORMAT_TS: &'static str = r#"
/**
 * The representation format of secret material
 */
type SecretMaterialFormat = "JWK" | "Multibase" | "Base58" | "Hex" | "Other" | string
"#;

#[wasm_bindgen(typescript_custom_section)]
const SECRET_MATERIAL_TS: &'static str = r#"
/**
 * Represents secret crypto material.
 */
type SecretMaterial = {
    format: SecretMaterialFormat,
    value: any,
}
"#;
