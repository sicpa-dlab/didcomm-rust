use std::collections::HashMap;
use std::sync::Arc;

use aries_askar::crypto::alg::{AnyKey, EcCurves};
use aries_askar::crypto::jwk::FromJwk;
use aries_askar::crypto::jwk::ToJwk;
use aries_askar::crypto::kdf::ecdh_1pu::Ecdh1PU;
use aries_askar::crypto::kdf::ecdh_es::EcdhEs;
use aries_askar::crypto::kdf::FromKeyDerivation;
use aries_askar::crypto::sign::KeySign;
use aries_askar::kms::KeyAlg;
use async_trait::async_trait;
use didcomm_core::secrets::resolvers::example::Secret;
use didcomm_core::secrets::A256Kw;
use didcomm_core::secrets::AesKey;
use didcomm_core::secrets::KnownKeyAlg;
use didcomm_core::secrets::KnownSignatureType;

use crate::secrets::kms::KidOrJwkAdapted;
use crate::{
    common::ErrorCode, secrets::KeyManagementService, OnFindSecretsResult, OnGetKeyAlgResult,
    OnSecretBytesResult,
};

/// Allows resolve pre-defined did's for `example` and other methods.
pub struct ExampleKMS {
    known_secrets: HashMap<String, Arc<AnyKey>>,
}

impl ExampleKMS {
    pub fn new(secrets: Vec<Secret>) -> Self {
        let known_secrets = secrets
            .iter()
            .map(|s| (s.id.clone(), s.to_key().unwrap()))
            .collect();
        Self { known_secrets }
    }

    fn resolve_key(&self, x: KidOrJwkAdapted) -> Arc<AnyKey> {
        match x {
            KidOrJwkAdapted::Kid { kid } => self.known_secrets.get(&kid).unwrap().clone(),
            KidOrJwkAdapted::Jwk { jwk } => Arc::<AnyKey>::from_jwk(&jwk).unwrap(),
        }
    }
}

#[async_trait]
impl KeyManagementService for ExampleKMS {
    fn get_key_alg(&self, secret_id: String, cb: Arc<OnGetKeyAlgResult>) -> ErrorCode {
        let key = match self.known_secrets.get(&secret_id) {
            Some(secret) => secret,
            None => return ErrorCode::Error,
        };

        let alg = match key.algorithm() {
            KeyAlg::Ed25519 => KnownKeyAlg::Ed25519,
            KeyAlg::X25519 => KnownKeyAlg::X25519,
            KeyAlg::EcCurve(EcCurves::Secp256r1) => KnownKeyAlg::P256,
            KeyAlg::EcCurve(EcCurves::Secp256k1) => KnownKeyAlg::K256,
            _ => KnownKeyAlg::Unsupported,
        };

        match cb.success(alg) {
            Ok(_) => ErrorCode::Success,
            Err(_) => ErrorCode::Error,
        }
    }

    fn find_secrets(&self, secret_ids: Vec<String>, cb: Arc<OnFindSecretsResult>) -> ErrorCode {
        let res = secret_ids
            .iter()
            .filter(|sid| self.known_secrets.contains_key(*sid))
            .map(|sid| sid.clone())
            .collect();

        match cb.success(res) {
            Ok(_) => ErrorCode::Success,
            Err(_) => ErrorCode::Error,
        }
    }

    fn create_signature(
        &self,
        secret_id: String,
        message: Vec<u8>,
        sig_type: Option<KnownSignatureType>,
        cb: Arc<OnSecretBytesResult>,
    ) -> ErrorCode {
        let key = match self.known_secrets.get(&secret_id) {
            Some(secret) => secret,
            None => return ErrorCode::Error,
        };

        let signature = match key.create_signature(&message, sig_type.map(|x| x.into())) {
            Ok(signature) => signature,
            Err(_) => return ErrorCode::Error,
        };

        match cb.success(signature.into_vec()) {
            Ok(_) => ErrorCode::Success,
            Err(_) => ErrorCode::Error,
        }
    }

    fn derive_aes_key_using_ecdh_1pu(
        &self,
        ephem_key: KidOrJwkAdapted,
        send_key: KidOrJwkAdapted,
        recip_key: KidOrJwkAdapted,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
        cb: Arc<OnSecretBytesResult>,
    ) -> ErrorCode {
        let ephem_key = self.resolve_key(ephem_key);
        let send_key = self.resolve_key(send_key);
        let recip_key = self.resolve_key(recip_key);

        let deriviation = Ecdh1PU::new(
            ephem_key.as_ref(),
            send_key.as_ref(),
            recip_key.as_ref(),
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        );

        let kw = match AesKey::<A256Kw>::from_key_derivation(deriviation) {
            Ok(kw) => kw,
            Err(_) => return ErrorCode::Error,
        };

        let kw = match kw.to_jwk_secret(None) {
            Ok(sb) => sb,
            Err(_) => return ErrorCode::Error,
        };

        match cb.success(kw.to_vec()) {
            Ok(_) => ErrorCode::Success,
            Err(_) => ErrorCode::Error,
        }
    }

    fn derive_aes_key_using_ecdh_es(
        &self,
        ephem_key: KidOrJwkAdapted,
        recip_key: KidOrJwkAdapted,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
        cb: Arc<OnSecretBytesResult>,
    ) -> ErrorCode {
        let ephem_key = self.resolve_key(ephem_key);
        let recip_key = self.resolve_key(recip_key);

        let deriviation = EcdhEs::new(
            ephem_key.as_ref(),
            recip_key.as_ref(),
            &alg,
            &apu,
            &apv,
            receive,
        );

        let kw = match AesKey::<A256Kw>::from_key_derivation(deriviation) {
            Ok(kw) => kw,
            Err(_) => return ErrorCode::Error,
        };

        let kw = match kw.to_jwk_secret(None) {
            Ok(sb) => sb,
            Err(_) => return ErrorCode::Error,
        };

        match cb.success(kw.to_vec()) {
            Ok(_) => ErrorCode::Success,
            Err(_) => ErrorCode::Error,
        }
    }
}
