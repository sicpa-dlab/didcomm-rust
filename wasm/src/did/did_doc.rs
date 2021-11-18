use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const DID_DOC_TS: &'static str = r#"
/**
 * Represents DID Document (https://www.w3.org/TR/did-core/)
 */
type DIDDoc = {
    /**
     * DID for the given DID Doc
     */
    did: string,

    /**
     * DID URLs of verification methods used for key agreement.
     * See https://www.w3.org/TR/did-core/#verification-methods.
     */
    key_agreements: Array<string>,

    /**
     * Returns DID URLs of verification methods used for authentication.
     * See https://www.w3.org/TR/did-core/#authentication
     */
    authentications: Array<string>,

    /**
     * All local verification methods including embedded to
     * key agreement and authentication sections.
     * See https://www.w3.org/TR/did-core/#verification-methods.
     */
    verification_methods: Array<VerificationMethod>,

    /**
     * All services (https://www.w3.org/TR/did-core/#services)
     */
    services: Array<Service>,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const VERIFICATION_METHOD_TS: &'static str = r#"
/**
 * Represents verification method record in DID Document
 * (https://www.w3.org/TR/did-core/#verification-methods).
 */
type VerificationMethod = {
    id: string,
    type: VerificationMethodType,
    controller: string,
    verification_material: VerificationMaterial,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const VERIFICATION_METHOD_TYPE_TS: &'static str = r#"
type VerificationMethodType = "JsonWebKey2020" | "X25519KeyAgreementKey2019" 
    | "Ed25519VerificationKey2018" | "EcdsaSecp256k1VerificationKey2019" | string
"#;

#[wasm_bindgen(typescript_custom_section)]
const VERIFICATION_MATERIAL_TYPE_TS: &'static str = r#"
/**
 * Represents verification material (https://www.w3.org/TR/did-core/#verification-material)
 */
type VerificationMaterial = {
    "JWK": any,
} | {
    "Multibase": string,
} | {
    "Base58": string,
} | {
    "Hex": string,
} | {
    "Other": any,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const SERVICE_TS: &'static str = r#"
/**
 * Represents service record in DID Document (https://www.w3.org/TR/did-core/#services).
 */
type Service = {
    id: string,
    kind: ServiceKind,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const SERVICE_KIND_TS: &'static str = r#"
/**
 * Represents additional service properties defined for specific Service type.
 */
type ServiceKind = {
    "DIDCommMessaging": DIDCommMessagingService,
} | {
    "Other": any,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const DIDCOMM_MESSAGING_SERVICE_TS: &'static str = r#"
/**
 * Properties for DIDCommMessagingService
 * (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
 */
type DIDCommMessagingService = {
    service_endpoint: string,
    accept: Array<string>,
    route_keys: Array<string>,
}
"#;
