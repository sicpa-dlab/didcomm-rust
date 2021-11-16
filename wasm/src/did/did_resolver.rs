use async_trait::async_trait;
use didcomm::{
    did::{DIDDoc, DIDResolver as _DIDResolver},
    error::{err_msg, ErrorKind, Result as _Result, ResultExt},
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    pub type DIDResolver;

    // TODO: Is better typing possible?
    #[wasm_bindgen(structural, method, catch)]
    pub async fn resolve(this: &DIDResolver, did: &str) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen(typescript_custom_section)]
const DID_RESOLVER_TS: &'static str = r#"
interface DIDResolver {
    resolve(did: String): Promise<DIDDoc | null>;
}
"#;

pub(crate) struct JsDIDResolver(pub(crate) DIDResolver);

#[async_trait(?Send)]
impl _DIDResolver for JsDIDResolver {
    async fn resolve(&self, did: &str) -> _Result<Option<DIDDoc>> {
        // TODO: better error conversion
        let ddoc = self.0.resolve(did).await.map_err(|e| {
            err_msg(
                ErrorKind::InvalidState,
                format!("Unable resolve did {:#?}", e),
            )
        })?;

        let ddoc: Option<DIDDoc> = ddoc.into_serde().kind(
            ErrorKind::InvalidState,
            "Unable deserialize DIDDoc from JsValue",
        )?;

        Ok(ddoc)
    }
}
