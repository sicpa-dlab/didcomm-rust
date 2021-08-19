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

#[async_trait]
impl SecretsResolver for ExampleSecretsResolver {
    async fn resolve(&self, _did_url: &str) -> Result<Option<Secret>> {
        todo!()
    }
}
