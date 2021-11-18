use async_trait::async_trait;
use didcomm::{
    error::{err_msg, ErrorKind, Result as _Result, ResultContext, ResultExt},
    secrets::{Secret, SecretsResolver as _SecretsResolver},
};
use js_sys::Array;
use wasm_bindgen::{prelude::*, JsCast};

use crate::error::FromJsResult;

#[wasm_bindgen]
extern "C" {
    pub type SecretsResolver;

    // Promise resolves to JsValue(object) that can be deserialized to Secret
    #[wasm_bindgen(structural, method, catch)]
    pub async fn get_secret(this: &SecretsResolver, secret_id: &str) -> Result<JsValue, JsValue>;

    // Promise resolves to JsValue(object) that can be casted to Array<string>
    #[wasm_bindgen(structural, method, catch)]
    pub async fn find_secrets(
        this: &SecretsResolver,
        secret_ids: Array,
    ) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen(typescript_custom_section)]
const SECRET_RESOLVER_TS: &'static str = r#"
/**
 * Interface for secrets resolver.
 * Resolves secrets such as private keys to be used for signing and encryption.
 */
interface SecretsResolver {
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
    get_secret(secret_id: string): Promise<Secret | null>;

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
}
"#;

// TODO: think is it possible to avoid ownership on DIDResolver
pub(crate) struct JsSecretsResolver(pub(crate) SecretsResolver);

#[async_trait(?Send)]
impl _SecretsResolver for JsSecretsResolver {
    async fn get_secret(&self, secret_id: &str) -> _Result<Option<Secret>> {
        // TODO: better error conversion
        let secret = self
            .0
            .get_secret(secret_id)
            .await
            .from_js()
            .context("Unable get secret")?;

        let secret: Option<Secret> = secret.into_serde().kind(
            ErrorKind::InvalidState,
            "Unable deserialize Secret from JsValue",
        )?;

        Ok(secret)
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
}
