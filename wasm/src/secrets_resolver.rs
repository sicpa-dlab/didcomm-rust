use async_trait::async_trait;
use didcomm::{
    error::{err_msg, ErrorKind, Result as _Result, ResultExt},
    secrets::{Secret, SecretsResolver as _SecretsResolver},
};
use js_sys::Array;
use std::convert::TryFrom;
use wasm_bindgen::prelude::*;

/// TODO: Provide description
/// Promise resolves to JsValue(object) that can be deserialized to DIDDoc
#[wasm_bindgen]
extern "C" {
    pub type SecretsResolver;

    // TODO: Is better typing possible?
    #[wasm_bindgen(structural, method, catch)]
    pub async fn get_secret(this: &SecretsResolver, secret_id: &str) -> Result<JsValue, JsValue>;

    // TODO: Is better typing possible?
    #[wasm_bindgen(structural, method, catch)]
    pub async fn find_secrets(
        this: &SecretsResolver,
        secret_ids: Array,
    ) -> Result<JsValue, JsValue>;
}

// TODO: think is it possible to avoid ownership on DIDResolver
pub(crate) struct JsSecretsResolver(pub(crate) SecretsResolver);

#[async_trait(?Send)]
impl _SecretsResolver for JsSecretsResolver {
    async fn get_secret(&self, secret_id: &str) -> _Result<Option<Secret>> {
        // TODO: better error conversion
        let secret = self.0.get_secret(secret_id).await.map_err(|e| {
            err_msg(
                ErrorKind::InvalidState,
                format!("Unable get secret {:#?}", e),
            )
        })?;

        let secret: Option<Secret> = secret.into_serde().kind(
            ErrorKind::InvalidState,
            "Unable deserialize Secret from JsValue",
        )?;

        Ok(secret)
    }

    /// Find all secrets that have one of the given IDs.
    /// Return secrets only for key IDs for which a secret is present.
    ///
    /// # Parameters
    /// - `secret_ids` the IDs find secrets for
    ///
    /// # Returns
    /// possible empty list of all secrets that have one of the given IDs.
    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> _Result<Vec<&'a str>> {
        let _secret_ids = secret_ids
            .into_iter()
            .map(|s| JsValue::from_str(s))
            .collect::<Array>();

        // TODO: better error conversion
        let found = self.0.find_secrets(_secret_ids).await.map_err(|e| {
            err_msg(
                ErrorKind::InvalidState,
                format!("Unable find secrets {:#?}", e),
            )
        })?;

        let found: Vec<_> = Array::try_from(found)
            .kind(
                ErrorKind::InvalidState,
                "Unable covert secret ids JsValue to Array",
            )?
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
