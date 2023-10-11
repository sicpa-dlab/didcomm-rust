use async_trait::async_trait;
use didcomm::{
    did::{DIDDoc, DIDResolver as _DIDResolver},
    error::{ErrorKind, Result as _Result, ResultContext, ResultExt},
};
use wasm_bindgen::prelude::*;

use crate::error::FromJsResult;

#[wasm_bindgen]
extern "C" {
    pub type DIDResolver;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn resolve(this: &DIDResolver, did: &str) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen(typescript_custom_section)]
const DID_RESOLVER_TS: &'static str = r#"
/**
 * Represents DID Doc resolver (https://www.w3.org/TR/did-core/#did-resolution).
 */
interface DIDResolver {
    /**
     * Resolves a DID document by the given DID.
     *
     * @param `did` a DID to be resolved.
     *
     * @returns An instance of resolved DID DOC or null if DID is not found.
     *
     * @throws DIDCommMalformed - Resolved DID Doc looks malformed
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
    resolve(did: string): Promise<DIDDoc | null>;
}
"#;

pub(crate) struct JsDIDResolver(pub(crate) DIDResolver);

#[async_trait(?Send)]
impl _DIDResolver for JsDIDResolver {
    async fn resolve(&self, did: &str) -> _Result<Option<DIDDoc>> {
        let ddoc = self
            .0
            .resolve(did)
            .await
            .from_js()
            .context("Unable resolve did")?;

        let ddoc: Option<DIDDoc> = ddoc.into_serde().kind(
            ErrorKind::InvalidState,
            "Unable deserialize DIDDoc from JsValue",
        )?;

        Ok(ddoc)
    }
}
