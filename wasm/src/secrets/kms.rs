use async_trait::async_trait;
use didcomm::{
    error::{err_msg, ErrorKind, Result as _Result, ResultContext, ResultExt},
    secrets::{
        A256Kw, AesKey, KeyManagementService as _KeyManagementService, KeySecretBytes, KidOrJwk,
        KnownKeyAlg, KnownSignatureType, SecretBytes,
    },
};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::{prelude::*, JsCast};

use crate::error::FromJsResult;

#[wasm_bindgen]
extern "C" {
    pub type KeyManagementService;

    // Promise resolves to JsValue(object) that can be deserialized to Secret
    #[wasm_bindgen(structural, method, catch)]
    pub async fn get_key_alg(
        this: &KeyManagementService,
        secret_id: &str,
    ) -> Result<JsValue, JsValue>;

    // Promise resolves to JsValue(object) that can be casted to Array<string>
    #[wasm_bindgen(structural, method, catch)]
    pub async fn find_secrets(
        this: &KeyManagementService,
        secret_ids: Array,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn create_signature(
        this: &KeyManagementService,
        secret_id: &str,
        message: &[u8],
        sig_type: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(structural, method, catch)]
    async fn derive_aes_key_using_ecdh_1pu(
        this: &KeyManagementService,
        ephem_key: JsValue,
        send_key: JsValue,
        recip_key: JsValue,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(structural, method, catch)]
    async fn derive_aes_key_using_ecdh_es(
        this: &KeyManagementService,
        ephem_key: JsValue,
        recip_key: JsValue,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen(typescript_custom_section)]
const KNOWN_KEY_ALG: &'static str = r#"
type KnownKeyAlg = "Ed25519" | "X25519" | "P256" | "K256" | "Unsupported" | string
"#;

#[wasm_bindgen(typescript_custom_section)]
const KEY_MANAGEMENT_SERVICE_TS: &'static str = r#"
/**
 * Interface for key management service.
 * Manages secrets such as private keys to be used for signing and encryption.
 */
interface KeyManagementService {
    /**
     * Finds secret (usually private key) identified by the given key ID.
     *
     * @param `secret_id` the ID (in form of DID URL) identifying a secret
     *
     * @returns A secret (usually private key) or None of there is no secret for the given ID
     *
     * @throws DIDCommIoError - IO error in resolving process
     * @throws DIDCommInvalidState - Code error or unexpected state was detected
     *
     * ```
     * let e = Error("Unble perform io operation");
     * e.name = "DIDCommIoError"
     * throw e
     * ```
     */
    get_key_alg(secret_id: string): Promise<KnownKeyAlg>;

    /**
     * Find all secrets that have one of the given IDs.
     * Return secrets only for key IDs for which a secret is present.
     *
     * @param `secret_ids` the IDs find secrets for
     *
     * @returns possible empty list of all secrets that have one of the given IDs.
     *
     * @throws DIDCommIoError - IO error in resolving process
     * @throws DIDCommInvalidState - Code error or unexpected state was detected
     *
     * Note to throw compatible error use code like this
     *
     * ```
     * let e = Error("Unble perform io operation");
     * e.name = "DIDCommIoError"
     * throw e
     * ```
     */
    find_secrets(secret_ids: Array<string>): Promise<Array<string>>;

    create_signature(secret_id: string, message: Uint8Array, sig_type: KnownSignatureType | null): Promise<Uint8Array>;

    derive_aes_key_using_ecdh_1pu(ephem_key: KidOrJwk, send_key: KidOrJwk, recip_key: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, cc_tag: Uint8Array, receive: bool): Promise<Uint8Array>;

    derive_aes_key_using_ecdh_es(ephem_key: KidOrJwk, recip_key: KidOrJwk, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, receive: boolean): Promise<Uint8Array;
}
"#;

// TODO: think is it possible to avoid ownership on DIDResolver
pub(crate) struct JsKeyManagementService(pub(crate) KeyManagementService);

#[async_trait(?Send)]
impl _KeyManagementService for JsKeyManagementService {
    async fn get_key_alg(&self, secret_id: &str) -> _Result<KnownKeyAlg> {
        let key_alg = self
            .0
            .get_key_alg(secret_id)
            .await
            .from_js()
            .context("Unable get key alg")?;

        let key_alg = serde_wasm_bindgen::from_value(key_alg).map_err(|_| {
            err_msg(
                ErrorKind::InvalidState,
                "Unable deserialize KeyAlg from JsValue",
            )
        })?;

        Ok(key_alg)
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> _Result<Vec<&'a str>> {
        let _secret_ids = secret_ids
            .into_iter()
            .map(|s| JsValue::from_str(s))
            .collect::<Array>();

        // TODO: better error conversion
        let found = self
            .0
            .find_secrets(_secret_ids)
            .await
            .from_js()
            .context("Unable find secrets")?;

        let found: Vec<_> = found
            .dyn_into::<Array>()
            .map_err(|_| {
                err_msg(
                    ErrorKind::InvalidState,
                    "Unable covert secret ids JsValue to Array",
                )
            })?
            .iter()
            .map(|v| v.as_string())
            .flatten()
            .collect();

        let found: Vec<_> = secret_ids
            .iter()
            .filter(|&s| found.iter().find(|_s| _s == s).is_some())
            .map(|&s| s)
            .collect();

        Ok(found)
    }

    async fn create_signature(
        &self,
        secret_id: &str,
        message: &[u8],
        sig_type: Option<KnownSignatureType>,
    ) -> _Result<SecretBytes> {
        let sig_type = serde_wasm_bindgen::to_value(&sig_type).map_err(|_| {
            err_msg(
                ErrorKind::InvalidState,
                "Unable covert KnownSignatureType to JsValue",
            )
        })?;

        let secret_bytes = self
            .0
            .create_signature(secret_id, message, sig_type)
            .await
            .from_js()
            .context("Unable to create signature")?;

        let secret_bytes = Uint8Array::new(&secret_bytes);

        Ok(SecretBytes::from_slice(&secret_bytes.to_vec()))
    }

    async fn derive_aes_key_using_ecdh_1pu(
        &self,
        ephem_key: KidOrJwk,
        send_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> _Result<AesKey<A256Kw>> {
        let ephem_key = serde_wasm_bindgen::to_value(&ephem_key)
            .map_err(|_| err_msg(ErrorKind::InvalidState, "Unable covert KidOrJwk to JsValue"))?;

        let send_key = serde_wasm_bindgen::to_value(&send_key)
            .map_err(|_| err_msg(ErrorKind::InvalidState, "Unable covert KidOrJwk to JsValue"))?;

        let recip_key = serde_wasm_bindgen::to_value(&recip_key)
            .map_err(|_| err_msg(ErrorKind::InvalidState, "Unable covert KidOrJwk to JsValue"))?;

        let derived_key = self
            .0
            .derive_aes_key_using_ecdh_1pu(
                ephem_key, send_key, recip_key, alg, apu, apv, cc_tag, receive,
            )
            .await
            .from_js()
            .context("Unable to derive key")?;

        let derived_key = Uint8Array::new(&derived_key);

        let derived_key = AesKey::from_secret_bytes(&derived_key.to_vec()).kind(
            ErrorKind::InvalidState,
            format!("Unable deserialize derived_key"),
        )?;

        Ok(derived_key)
    }

    async fn derive_aes_key_using_ecdh_es(
        &self,
        ephem_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> _Result<AesKey<A256Kw>> {
        let ephem_key = serde_wasm_bindgen::to_value(&ephem_key)
            .map_err(|_| err_msg(ErrorKind::InvalidState, "Unable covert KidOrJwk to JsValue"))?;

        let recip_key = serde_wasm_bindgen::to_value(&recip_key)
            .map_err(|_| err_msg(ErrorKind::InvalidState, "Unable covert KidOrJwk to JsValue"))?;

        let derived_key = self
            .0
            .derive_aes_key_using_ecdh_es(ephem_key, recip_key, alg, apu, apv, receive)
            .await
            .from_js()
            .context("Unable to derive key")?;

        let derived_key = Uint8Array::new(&derived_key);

        let derived_key = AesKey::from_secret_bytes(&derived_key.to_vec()).kind(
            ErrorKind::InvalidState,
            format!("Unable deserialize derived_key"),
        )?;

        Ok(derived_key)
    }
}
