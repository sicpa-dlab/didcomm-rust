use std::sync::Arc;

use async_trait::async_trait;
use didcomm_core::{
    error::{ErrorKind, Result, ResultExt},
    secrets::{
        A256Kw, AesKey, KeyManagementService as _KeyManagementService, KeySecretBytes, KidOrJwk,
        KnownKeyAlg, KnownSignatureType, SecretBytes,
    },
};

use crate::kms::{OnFindSecretsResult, OnGetKeyAlgResult, OnSecretBytesResult};

use super::KeyManagementService;

pub struct KeyManagementServiceAdapter {
    kms: Arc<Box<dyn KeyManagementService>>,
}

impl KeyManagementServiceAdapter {
    pub fn new(kms: Arc<Box<dyn KeyManagementService>>) -> Self {
        KeyManagementServiceAdapter { kms }
    }
}

#[async_trait]
impl _KeyManagementService for KeyManagementServiceAdapter {
    async fn get_key_alg(&self, secret_id: &str) -> Result<KnownKeyAlg> {
        let (cb, receiver) = OnGetKeyAlgResult::new();

        self.kms.get_key_alg(String::from(secret_id), cb);

        let res = receiver
            .get()
            .await
            .kind(ErrorKind::InvalidState, "can not get key alg")?;
        Ok(res)
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        let (cb, receiver) = OnFindSecretsResult::new();

        self.kms
            .find_secrets(secret_ids.iter().map(|&s| String::from(s)).collect(), cb);

        let res = receiver
            .get()
            .await
            .kind(ErrorKind::InvalidState, "can not get secret")?;

        Ok(secret_ids
            .iter()
            .filter(|&&sid| res.iter().find(|&s| s == sid).is_some())
            .map(|sid| *sid)
            .collect())
    }

    async fn create_signature(
        &self,
        secret_id: &str,
        message: &[u8],
        sig_type: Option<KnownSignatureType>,
    ) -> Result<SecretBytes> {
        let (cb, receiver) = OnSecretBytesResult::new();

        self.kms
            .create_signature(secret_id.to_string(), message.to_vec(), sig_type, cb);

        let res = receiver
            .get()
            .await
            .kind(ErrorKind::InvalidState, "can not create signature")?;
        Ok(SecretBytes::from_slice(&res))
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
    ) -> Result<AesKey<A256Kw>> {
        let (cb, receiver) = OnSecretBytesResult::new();

        self.kms.derive_aes_key_using_ecdh_1pu(
            ephem_key.into(),
            send_key.into(),
            recip_key.into(),
            alg,
            apu,
            apv,
            cc_tag,
            receive,
            cb,
        );

        let res = receiver
            .get()
            .await
            .kind(ErrorKind::InvalidState, "can not derive key using ECDH-1PU")?;
        let res = AesKey::from_secret_bytes(&res).kind(
            ErrorKind::InvalidState,
            "can not convert derived key from secret bytes",
        )?;
        Ok(res)
    }

    async fn derive_aes_key_using_ecdh_es(
        &self,
        ephem_key: KidOrJwk,
        recip_key: KidOrJwk,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let (cb, receiver) = OnSecretBytesResult::new();

        self.kms.derive_aes_key_using_ecdh_es(
            ephem_key.into(),
            recip_key.into(),
            alg,
            apu,
            apv,
            receive,
            cb,
        );

        let res = receiver
            .get()
            .await
            .kind(ErrorKind::InvalidState, "can not derive key using ECDH-1PU")?;
        let res = AesKey::from_secret_bytes(&res).kind(
            ErrorKind::InvalidState,
            "can not convert derived key from secret bytes",
        )?;
        Ok(res)
    }
}
