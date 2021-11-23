use js_sys::{Array, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{
    error::JsResult, DIDResolver, FromPrior, JsDIDResolver, JsSecretsResolver, SecretsResolver,
};

#[wasm_bindgen]
impl FromPrior {
    #[wasm_bindgen(skip_typescript)]
    pub fn pack(
        &self,
        issuer_kid: Option<String>,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
    ) -> Promise {
        let from_prior = self.0.clone();
        let did_resolver = JsDIDResolver(did_resolver);
        let secrets_resolver = JsSecretsResolver(secrets_resolver);

        future_to_promise(async move {
            let (msg, metadata) = from_prior
                .pack(issuer_kid.as_deref(), &did_resolver, &secrets_resolver)
                .await
                .as_js()?;

            let res = {
                let res = Array::new_with_length(2);
                res.set(0, msg.into());
                res.set(1, metadata.into());
                res
            };

            Ok(res.into())
        })
    }
}

#[wasm_bindgen(typescript_custom_section)]
const FROM_PRIOR_PACK_TS: &'static str = r#"
interface FromPrior {
    pack(
        issuer_kid: string | null,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
    ): Promise<[string, string]>;
}
"#;
