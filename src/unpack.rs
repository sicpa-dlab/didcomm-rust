use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg, SignAlg},
    did::DIDResolver,
    error::Result,
    secrets::SecretsResolver,
    Message,
};

impl Message {
    /// Unpacks the packed message by doing decryption and verifying the signatures.
    /// This method supports all DID Comm message types (encrypted, signed, plaintext).
    ///
    /// If unpack options expect a particular property (for example that a message is encrypted)
    /// and the packed message doesn't meet the criteria (it's not encrypted), then a MessageUntrusted
    /// error will be returned.
    ///
    /// # Params
    /// - `packed_msg` the message as JSON string to be unpacked
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    /// - `options` allow fine configuration of unpacking process and imposing additional restrictions
    /// to message to be trusted.
    ///
    /// # Returns
    /// Tuple `(message, metadata)`.
    /// - `message` plain message instance
    /// - `metadata` additional metadata about this `unpack` execution like used keys identifiers,
    ///   trust context, algorithms and etc.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotResolved` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `MessageMalformed` message doesn't correspond to DID Comm or has invalid encryption or signatures.
    /// - `MessageUntrusted` message doesn't satisfy checks requested by unpack options.
    /// - `SecretNotFound` No recipient secrets found.
    /// - `InvalidState` Indicates library error.
    /// - `IOError` IO error during DID or secrets resolving.
    /// TODO: verify and update errors list
    pub async fn unpack<'dr, 'sr>(
        _packed_msg: &str,
        _did_resolver: &'dr (dyn DIDResolver + 'dr),
        _secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        _options: &UnpackOptions,
    ) -> Result<(Self, UnpackMetadata)> {
        todo!()
    }
}

/// Allows fine customization of unpacking process
pub struct UnpackOptions {
    /// Whether the plaintext must be signed by the sender. Not expected by default.
    pub expect_non_repudiation: bool,

    /// Whether the plaintext must be encrypted by the sender. Not expected by default.
    pub expect_encrypted: bool,

    /// Whether the plaintext must be authenticated by the sender. Not expected by default.
    pub expect_authenticated: bool,

    /// Whether the sender ID must be protected. Not expected by default.
    pub expect_hidden_sender: bool,

    /// Whether the same DID must be used for encryption and signing. True by default.
    pub expect_signed_by_encrypter: bool,

    /// Whether the plaintext must be decryptable by all keys resolved by the secrets resolver. False by default.
    pub expect_decrypt_by_all_keys: bool,

    /// If `true` (default), and the packed message is a `Forward`
    /// wrapping a plaintext packed for the given recipient, then both Forward and packed plaintext are unpacked automatically,
    /// and the unpacked plaintext will be returned instead of unpacked Forward.
    pub unwrap_re_wrapping_forward: bool,
}

impl Default for UnpackOptions {
    fn default() -> Self {
        UnpackOptions {
            expect_non_repudiation: false,
            expect_encrypted: false,
            expect_authenticated: false,
            expect_hidden_sender: false,
            expect_signed_by_encrypter: true,
            expect_decrypt_by_all_keys: false,
            unwrap_re_wrapping_forward: true,
        }
    }
}

pub struct UnpackMetadata {
    /// Whether the plaintext has been encrypted
    pub encrypted: bool,

    /// Whether the plaintext has been authenticated
    pub authenticated: bool,

    /// Whether the plaintext has been signed
    pub non_repudiation: bool,

    /// Whether the sender ID was protected
    pub anonymous_sender: bool,

    /// Whether the plaintext was re-wrapped in a forward message by a mediator
    pub re_wrapped_in_forward: bool,

    /// Key ID of the sender used for authentication encryption if the plaintext has been authenticated and encrypted
    pub encrypted_from_kid: Option<String>,

    /// Target key IDS for encryption if the plaintext has been encrypted
    pub encrypted_to_kids: Option<Vec<String>>,

    /// Key ID used for signature if the plaintext has been signed
    pub sign_from: Option<String>,

    /// Algorithm used for authenticated encryption
    pub enc_alg_auth: Option<AuthCryptAlg>,

    /// Algorithm used for anonymous encryption
    pub enc_alg_anon: Option<AnonCryptAlg>,

    /// Algorithm used for message signing
    pub sign_alg: Option<SignAlg>,

    /// If the plaintext has been signed, the JWS is returned for non-repudiation purposes
    pub signed_plaintext: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver};

    #[tokio::test]
    async fn unpack_works() {
        let msg = "{}"; // TODO: use test vector from DID Comm specification.

        let did_resolver = ExampleDIDResolver::new();
        let secrets_resolver = ExampleSecretsResolver::new();

        let (_msg, _metadata) = Message::unpack(
            msg,
            &did_resolver,
            &secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("unpack is ok.");
    }
}
