use askar_crypto::{
    alg::{
        aes::{A128Kw, A256Kw, AesKey},
        ed25519::Ed25519KeyPair,
        k256::K256KeyPair,
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
    repr::{KeySecretBytes, ToSecretBytes},
    sign::SignatureType,
};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnownKeyAlg {
    Ed25519,
    X25519,
    P256,
    K256,
    Unsupported,
}

#[derive(Debug)]
pub(crate) enum KnownKeyPair {
    Ed25519(Ed25519KeyPair),
    X25519(X25519KeyPair),
    P256(P256KeyPair),
    K256(K256KeyPair),
}

pub(crate) trait AsKnownKeyPair {
    fn key_alg(&self) -> KnownKeyAlg;
    fn as_key_pair(&self) -> Result<KnownKeyPair>;

    fn as_ed25519(&self) -> Result<Ed25519KeyPair> {
        if self.key_alg() != KnownKeyAlg::Ed25519 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::Ed25519(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }

    fn as_x25519(&self) -> Result<X25519KeyPair> {
        if self.key_alg() != KnownKeyAlg::X25519 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::X25519(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }

    fn as_p256(&self) -> Result<P256KeyPair> {
        if self.key_alg() != KnownKeyAlg::P256 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::P256(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }

    fn as_k256(&self) -> Result<K256KeyPair> {
        if self.key_alg() != KnownKeyAlg::K256 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::K256(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KnownSignatureType {
    /// Standard signature output for ed25519
    EdDSA,
    /// Elliptic curve DSA using P-256 and SHA-256
    ES256,
    /// Elliptic curve DSA using K-256 and SHA-256
    ES256K,
}

impl From<SignatureType> for KnownSignatureType {
    fn from(value: SignatureType) -> Self {
        match value {
            SignatureType::EdDSA => KnownSignatureType::EdDSA,
            SignatureType::ES256 => KnownSignatureType::ES256,
            SignatureType::ES256K => KnownSignatureType::ES256K,
        }
    }
}

impl From<KnownSignatureType> for SignatureType {
    fn from(value: KnownSignatureType) -> Self {
        match value {
            KnownSignatureType::EdDSA => SignatureType::EdDSA,
            KnownSignatureType::ES256 => SignatureType::ES256,
            KnownSignatureType::ES256K => SignatureType::ES256K,
        }
    }
}
