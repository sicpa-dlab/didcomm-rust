use askar_crypto::{
    alg::aes::{A256Kw, AesKey},
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    repr::{KeySecretBytes, ToSecretBytes},
};

use crate::error::{ErrorKind, Result, ResultExt};

/// Note that trait is compatible with KW algorithms only
pub(crate) trait KeyWrap: KeyAeadInPlace {
    fn wrap_key<K: KeyAeadInPlace + ToSecretBytes>(&self, key: &K) -> Result<SecretBytes> {
        let params = self.aead_params();

        let key_len = key
            .secret_bytes_length()
            .kind(ErrorKind::InvalidState, "unable get key len.")?;

        let mut encrypted_key = SecretBytes::with_capacity(key_len + params.tag_length);

        self.encrypt_in_place(&mut encrypted_key, &[], &[])
            .kind(ErrorKind::InvalidState, "unable encrypt.")?;

        Ok(encrypted_key)
    }

    fn unwrap_key<K: KeyAeadInPlace + KeySecretBytes>(&self, cyphertext: &[u8]) -> Result<K> {
        let mut buf = SecretBytes::from_slice(cyphertext);

        self.decrypt_in_place(&mut buf, &[], &[])
            .kind(ErrorKind::Malformed, "unable decrypt key.")?;

        let key =
            K::from_secret_bytes(buf.as_ref()).kind(ErrorKind::Malformed, "unable create key.")?;

        Ok(key)
    }
}

impl KeyWrap for AesKey<A256Kw> {}
