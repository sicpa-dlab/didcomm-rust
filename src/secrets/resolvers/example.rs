use async_trait::async_trait;

use crate::{
    error::Result,
    secrets::{Secret, SecretsResolver},
};

pub struct ExampleSecretsResolver {}

impl ExampleSecretsResolver {
    pub fn new() -> Self {
        ExampleSecretsResolver {}
    }
}

#[async_trait]
impl SecretsResolver for ExampleSecretsResolver {
    async fn resolve(&self, _did_url: &str) -> Result<Option<Secret>> {
        todo!()
    }
}
