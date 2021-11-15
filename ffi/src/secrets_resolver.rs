use async_trait::async_trait;
use didcomm::error::{err_msg, ErrorKind, Result, ToResult};
use didcomm::secrets::{Secret, SecretsResolver};

#[async_trait]
pub trait FFISecretsResolver: Sync + Send {
    fn get_secret(&self, secret_id: &str) -> Result<Option<String>>;
    fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>>;
}

pub struct SecretResolverAdapter {
    secret_resolver: Box<dyn FFISecretsResolver>,
}

impl SecretResolverAdapter {
    pub fn new(secret_resolver: Box<dyn FFISecretsResolver>) -> Self {
        SecretResolverAdapter { secret_resolver }
    }
}

#[async_trait]
impl SecretsResolver for SecretResolverAdapter {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        // TODO: better error conversion
        let secret = self.secret_resolver.get_secret(secret_id).map_err(|e| {
            err_msg(
                ErrorKind::InvalidState,
                format!("Unable resolve did {:#?}", e),
            )
        })?;

        match secret {
            Some(secret) => Ok(serde_json::from_str(&secret)
                .to_didcomm("Unable deserialize DIDDoc from JsValue")?),
            None => Ok(None),
        }
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        // TODO: better error conversion
        self.secret_resolver.find_secrets(secret_ids).map_err(|e| {
            err_msg(
                ErrorKind::InvalidState,
                format!("Unable resolve did {:#?}", e),
            )
        })
    }
}

pub struct ExampleFFISecretResolver {
    known_secrets: Vec<String>,
}

impl ExampleFFISecretResolver {
    pub fn new(known_secrets: Vec<String>) -> Self {
        ExampleFFISecretResolver { known_secrets }
    }
}

impl FFISecretsResolver for ExampleFFISecretResolver {
    fn get_secret(&self, secret_id: &str) -> Result<Option<String>> {
        Ok(self
            .known_secrets
            .iter()
            .map(|secret| {
                let s: Secret = serde_json::from_str(secret).unwrap();
                s
            })
            .find(|secret| secret.id == secret_id)
            .map(|ddoc| serde_json::to_string(&ddoc).unwrap()))
    }

    fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        Ok(secret_ids
            .iter()
            .filter(|&&sid| {
                self.known_secrets
                    .iter()
                    .map(|secret| {
                        let s: Secret = serde_json::from_str(secret).unwrap();
                        s
                    })
                    .find(|s| s.id == sid)
                    .is_some()
            })
            .map(|sid| *sid)
            .collect())
    }
}
