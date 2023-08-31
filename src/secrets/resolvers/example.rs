use askar_crypto::alg::aes::{A256Kw, AesKey};
use askar_crypto::alg::p256::P256KeyPair;
use askar_crypto::alg::x25519::X25519KeyPair;
use askar_crypto::kdf::ecdh_1pu::Ecdh1PU;
use askar_crypto::kdf::ecdh_es::EcdhEs;
use async_trait::async_trait;

use crate::utils::crypto::{AsKnownKeyPair, JoseKDF};
use crate::{
    error::Result,
    secrets::{Secret, SecretsResolver},
};

pub struct ExampleSecretsResolver {
    known_secrets: Vec<Secret>,
}

impl ExampleSecretsResolver {
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        ExampleSecretsResolver { known_secrets }
    }
}

#[cfg_attr(feature = "uniffi", async_trait)]
#[cfg_attr(not(feature = "uniffi"), async_trait(?Send))]
impl SecretsResolver for ExampleSecretsResolver {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        Ok(self
            .known_secrets
            .iter()
            .find(|s| s.id == secret_id)
            .map(|s| s.clone()))
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        Ok(secret_ids
            .iter()
            .filter(|&&sid| self.known_secrets.iter().find(|s| s.id == sid).is_some())
            .map(|sid| *sid)
            .collect())
    }

    async fn derive_aes_key_from_x25519_using_edch1pu(
        &self,
        ephem_key: X25519KeyPair,
        send_kid: String,
        recip_key: X25519KeyPair,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(&send_kid).await?.expect("Secret not found");

        Ecdh1PU::derive_key(
            &ephem_key,
            Some(&key.as_x25519()?),
            &recip_key,
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        )
    }

    async fn derive_aes_key_from_p256_using_edch1pu(
        &self,
        ephem_key: P256KeyPair,
        send_kid: String,
        recip_key: P256KeyPair,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(&send_kid).await?.expect("Secret not found");

        Ecdh1PU::derive_key(
            &ephem_key,
            Some(&key.as_p256()?),
            &recip_key,
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        )
    }

    async fn derive_aes_key_from_x25519_using_edch1pu_receive(
        &self,
        ephem_key: X25519KeyPair,
        send_key: X25519KeyPair,
        recip_kid: &str,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(recip_kid).await?.expect("Secret not found");

        Ecdh1PU::derive_key(
            &ephem_key,
            Some(&send_key),
            &key.as_x25519()?,
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        )
    }

    async fn derive_aes_key_from_p256_using_edch1pu_receive(
        &self,
        ephem_key: P256KeyPair,
        send_key: P256KeyPair,
        recip_kid: &str,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(recip_kid).await?.expect("Secret not found");

        Ecdh1PU::derive_key(
            &ephem_key,
            Some(&send_key),
            &key.as_p256()?,
            &alg,
            &apu,
            &apv,
            &cc_tag,
            receive,
        )
    }

    async fn derive_aes_key_from_x25519_using_edches(
        &self,
        ephem_key: X25519KeyPair,
        recip_kid: &str,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(recip_kid).await?.expect("Secret not found");

        EcdhEs::derive_key(
            &ephem_key,
            None,
            &key.as_x25519()?,
            &alg,
            &apu,
            &apv,
            &[],
            receive,
        )
    }

    async fn derive_aes_key_from_p256_using_edches(
        &self,
        ephem_key: P256KeyPair,
        recip_kid: &str,
        alg: Vec<u8>,
        apu: Vec<u8>,
        apv: Vec<u8>,
        receive: bool,
    ) -> Result<AesKey<A256Kw>> {
        let key = self.get_secret(recip_kid).await?.expect("Secret not found");

        EcdhEs::derive_key(
            &ephem_key,
            None,
            &key.as_p256()?,
            &alg,
            &apu,
            &apv,
            &[],
            receive,
        )
    }
}
