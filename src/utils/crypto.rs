use askar_crypto::{
    alg::aes::{A256Kw, AesKey, AesType},
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, FromKeyDerivation, KeyExchange},
    repr::{KeySecretBytes, ToSecretBytes},
};

use crate::error::{err_msg, ErrorKind, Result, ResultExt};

/// Note that trait is compatible with KW algorithms only
pub(crate) trait KeyWrap: KeyAeadInPlace {
    fn wrap_key<K: KeyAeadInPlace + ToSecretBytes>(&self, key: &K) -> Result<SecretBytes> {
        let params = self.aead_params();

        let key_len = key
            .secret_bytes_length()
            .kind(ErrorKind::InvalidState, "unable get key len.")?;

        let mut buf = SecretBytes::with_capacity(key_len + params.tag_length);

        key.write_secret_bytes(&mut buf)
            .kind(ErrorKind::InvalidState, "unable encrypt.")?;

        self.encrypt_in_place(&mut buf, &[], &[])
            .kind(ErrorKind::InvalidState, "unable encrypt.")?;

        Ok(buf)
    }

    fn unwrap_key<K: KeyAeadInPlace + KeySecretBytes>(&self, cyphertext: &[u8]) -> Result<K> {
        let mut buf = SecretBytes::from_slice(cyphertext);

        self.decrypt_in_place(&mut buf, &[], &[])
            .kind(ErrorKind::Malformed, "unable decrypt key.")?;

        let key =
            K::from_secret_bytes(buf.as_ref()).kind(ErrorKind::Malformed, "unable create key.")?;

        Ok(key)
    }

    fn jwk_alg() -> &'static str;
}

impl KeyWrap for AesKey<A256Kw> {
    fn jwk_alg() -> &'static str {
        A256Kw::JWK_ALG
    }
}

pub(crate) trait JoseKDF<Key: KeyExchange, KW: KeyWrap + Sized> {
    fn derive_key(
        ephem_key: &Key,
        send_key: Option<&Key>,
        recip_key: &Key,
        apu: Option<&[u8]>,
        apv: &[u8],
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
        apu: Option<&[u8]>,
        apv: &[u8],
        receive: bool,
    ) -> Result<KW> {
        let send_key = send_key
            .ok_or_else(|| err_msg(ErrorKind::InvalidState, "no sendery key for ecdh-1pu."))?;

        let apu = apu.ok_or_else(|| err_msg(ErrorKind::InvalidState, "no apu for ecdh-1pu."))?;

        let deriviation = Ecdh1PU::new(
            ephem_key,
            send_key,
            recip_key,
            KW::jwk_alg().as_bytes(),
            apu,
            apv,
            &[],
            receive,
        );

        let kw = KW::from_key_derivation(deriviation)
            .kind(ErrorKind::InvalidState, "unable derive kw.")?;

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
        _apu: Option<&[u8]>,
        apv: &[u8],
        receive: bool,
    ) -> Result<KW> {
        let deriviation = EcdhEs::new(
            ephem_key,
            recip_key,
            KW::jwk_alg().as_bytes(),
            &[],
            apv,
            receive,
        );

        let kw = KW::from_key_derivation(deriviation)
            .kind(ErrorKind::InvalidState, "unable derive kw.")?;

        Ok(kw)
    }
}
