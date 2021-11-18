use std::rc::Rc;

use didcomm::{
    error::{ErrorKind, ResultExt},
    UnpackOptions,
};
use js_sys::{Array, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{
    error::JsResult, utils::set_panic_hook, DIDResolver, JsDIDResolver, JsSecretsResolver, Message,
    SecretsResolver,
};

#[wasm_bindgen(skip_typescript)]
impl Message {
    #[wasm_bindgen(skip_typescript)]
    pub fn unpack(
        msg: String,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
        options: JsValue,
    ) -> Promise {
        // TODO: Better place?
        set_panic_hook();

        let did_resolver = JsDIDResolver(did_resolver);
        let secrets_resolver = JsSecretsResolver(secrets_resolver);

        future_to_promise(async move {
            let options: UnpackOptions = options
                .into_serde()
                .kind(ErrorKind::Malformed, "Options param is malformed")
                .as_js()?;

            let (msg, metadata) =
                didcomm::Message::unpack(&msg, &did_resolver, &secrets_resolver, &options)
                    .await
                    .as_js()?;

            let metadata = JsValue::from_serde(&metadata)
                .kind(ErrorKind::InvalidState, "Unable serialize UnpackMetadata")
                .as_js()?;

            let res = {
                let res = Array::new_with_length(2);
                res.set(0, Message(Rc::new(msg)).into());
                res.set(1, metadata);
                res
            };

            Ok(res.into())
        })
    }
}

#[wasm_bindgen(typescript_custom_section)]
const MESSAGE_UNPACK_TS: &'static str = r#"
export namespace Message {
    /** 
     * Unpacks the packed message by doing decryption and verifying the signatures.
     * This method supports all DID Comm message types (encrypted, signed, plaintext).
     *
     * If unpack options expect a particular property (for example that a message is encrypted)
     * and the packed message doesn't meet the criteria (it's not encrypted), then a MessageUntrusted
     * error will be returned.
     *
     * @param `packed_msg` the message as JSON string to be unpacked
     * @param `did_resolver` instance of `DIDResolver` to resolve DIDs
     * @param `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
     * @param `options` allow fine configuration of unpacking process and imposing additional restrictions
     * to message to be trusted.
     *
     * @returns Tuple `[message, metadata]`.
     * - `message` plain message instance
     * - `metadata` additional metadata about this `unpack` execution like used keys identifiers,
     *   trust context, algorithms and etc.
     *
     * @throws DIDCommDIDNotResolved
     * @throws DIDCommDIDUrlNotFound
     * @throws DIDCommMalformed
     * @throws DIDCommIoError
     * @throws DIDCommInvalidState
     * @throws DIDCommNoCompatibleCrypto
     * @throws DIDCommUnsupported
     * @throws DIDCommIllegalArgument
     */
    function unpack(
        msg: string,
        did_resolver: DIDResolver,
        secrets_resolver: SecretsResolver,
        options: UnpackOptions,
    ): Promise<[Message, UnpackMetadata]>;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const PACK_UNPACK_OPTIONS_TS: &'static str = r#"
/**
 *  Allows fine customization of unpacking process
 */
type UnpackOptions = {
    /**
     * Whether the plaintext must be decryptable by all keys resolved by the secrets resolver.
     * False by default.
     */
    expect_decrypt_by_all_keys?: boolean,

    /**
     * If `true` and the packed message is a `Forward`
     * wrapping a plaintext packed for the given recipient, then both Forward and packed plaintext are unpacked automatically,
     * and the unpacked plaintext will be returned instead of unpacked Forward.
     * False by default.
     */
    unwrap_re_wrapping_forward?: boolean,
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const UNPACK_METADATA_TS: &'static str = r#"
/**
 * Additional metadata about this `unpack` method execution like trust predicates
 * and used keys identifiers.
 */
type UnpackMetadata = {
    /**
     * Whether the plaintext has been encrypted.
     */
    encrypted: boolean,

    /**
     * Whether the plaintext has been authenticated.
     */
    authenticated: boolean,

    /**
     * Whether the plaintext has been signed.
     */
    non_repudiation: boolean,

    /**
     * Whether the sender ID was protected.
     */
    anonymous_sender: boolean,

    /**
     * Whether the plaintext was re-wrapped in a forward message by a mediator.
     */
    re_wrapped_in_forward: boolean,

    /**
     * Key ID of the sender used for authentication encryption
     * if the plaintext has been authenticated and encrypted.
     */
    encrypted_from_kid?: string,

    /**
     * Target key IDS for encryption if the plaintext has been encrypted.
     */
    encrypted_to_kids?: Array<string>,

    /**
     * Key ID used for signature if the plaintext has been signed.
     */
    sign_from: string,

    /**
     * Key ID used for from_prior header signature if from_prior header is present
     */
    from_prior_issuer_kid?: string,

    /**
     * Algorithm used for authenticated encryption.
     * Default "A256cbcHs512Ecdh1puA256kw"
     */
    enc_alg_auth?: "A256cbcHs512Ecdh1puA256kw",
 
    /**
     * Algorithm used for anonymous encryption.
     * Default "Xc20pEcdhEsA256kw"
     */
    enc_alg_anon?: "A256cbcHs512EcdhEsA256kw" | "Xc20pEcdhEsA256kw" | "A256gcmEcdhEsA256kw",

    /**
     * Algorithm used for message signing.
     */
    sign_alg?: "EdDSA" | "ES256" | "ES256K",

    /**
     * If the plaintext has been signed, the JWS is returned for non-repudiation purposes.
     */
    signed_message?: string,

    /**
     * If plaintext contains from_prior header, its unpacked value is returned
     */
    from_prior?: FromPrior,
}
"#;
