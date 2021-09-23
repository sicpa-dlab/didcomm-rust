use askar_crypto::{
    alg::{
        aes::{A128Kw, A256Kw, AesKey},
        ed25519::Ed25519KeyPair,
        k256::K256KeyPair,
        p256::P256KeyPair,
    },
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
    repr::{KeySecretBytes, ToSecretBytes},
};

use crate::error::{err_msg, ErrorKind, Result, ResultExt};

/// Note this trait is compatible with KW algorithms only
pub(crate) trait KeyWrap: KeyAeadInPlace {
    fn wrap_key<K: KeyAeadInPlace + ToSecretBytes>(&self, key: &K) -> Result<SecretBytes> {
        let params = self.aead_params();

        let key_len = key
            .secret_bytes_length()
            .kind(ErrorKind::InvalidState, "Unable get key len")?;

        let mut buf = SecretBytes::with_capacity(key_len + params.tag_length);

        key.write_secret_bytes(&mut buf)
            .kind(ErrorKind::InvalidState, "Unable encrypt")?;

        self.encrypt_in_place(&mut buf, &[], &[])
            .kind(ErrorKind::InvalidState, "Unable encrypt")?;

        Ok(buf)
    }

    fn unwrap_key<K: KeyAeadInPlace + KeySecretBytes>(&self, ciphertext: &[u8]) -> Result<K> {
        let mut buf = SecretBytes::from_slice(ciphertext);

        self.decrypt_in_place(&mut buf, &[], &[])
            .kind(ErrorKind::Malformed, "Unable decrypt key")?;

        let key =
            K::from_secret_bytes(buf.as_ref()).kind(ErrorKind::Malformed, "Unable create key")?;

        Ok(key)
    }
}

impl KeyWrap for AesKey<A256Kw> {}

impl KeyWrap for AesKey<A128Kw> {}

pub(crate) trait JoseKDF<Key: KeyExchange, KW: KeyWrap + Sized> {
    fn derive_key(
        ephem_key: &Key,
        send_key: Option<&Key>,
        recip_key: &Key,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<KW>;
}

impl<Key: KeyExchange, KW: KeyWrap + FromKeyDerivation + Sized> JoseKDF<Key, KW>
    for Ecdh1PU<'_, Key>
{
    fn derive_key(
        ephem_key: &Key,
        send_key: Option<&Key>,
        recip_key: &Key,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<KW> {
        let send_key = send_key
            .ok_or_else(|| err_msg(ErrorKind::InvalidState, "No sender key for ecdh-1pu"))?;
        let deriviation = Ecdh1PU::new(
            ephem_key, send_key, recip_key, alg, apu, apv, cc_tag, receive,
        );

        let kw = KW::from_key_derivation(deriviation)
            .kind(ErrorKind::InvalidState, "Unable derive kw")?;

        Ok(kw)
    }
}

impl<Key: KeyExchange, KW: KeyWrap + FromKeyDerivation + Sized> JoseKDF<Key, KW>
    for EcdhEs<'_, Key>
{
    fn derive_key(
        ephem_key: &Key,
        _send_key: Option<&Key>,
        recip_key: &Key,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        _cc_tag: &[u8],
        receive: bool,
    ) -> Result<KW> {
        let deriviation = EcdhEs::new(ephem_key, recip_key, alg, apu, apv, receive);

        let kw = KW::from_key_derivation(deriviation)
            .kind(ErrorKind::InvalidState, "Unable derive kw")?;

        Ok(kw)
    }
}

pub(crate) enum SignKeyPair {
    Ed25519KeyPair(Ed25519KeyPair),
    P256KeyPair(P256KeyPair),
    K256KeyPair(K256KeyPair),
}
