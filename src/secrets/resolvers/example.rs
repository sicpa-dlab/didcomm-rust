use async_trait::async_trait;

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

#[async_trait(?Send)]
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
}
