use async_trait::async_trait;

use crate::{
    did::{DIDDoc, DIDResolver, Service, VerificationMethod},
    error::Result,
};

/// Allows resolve pre-defined did's for `example` and other methods.
pub struct ExampleDIDResolver {
    known_dids: Vec<ExampleDIDDoc>,
}

impl ExampleDIDResolver {
    pub fn new(known_dids: Vec<ExampleDIDDoc>) -> Self {
        ExampleDIDResolver { known_dids }
    }
}

#[async_trait]
impl DIDResolver for ExampleDIDResolver {
    async fn resolve(&self, _did: &str) -> Result<Option<Box<dyn DIDDoc>>> {
        Ok(self
            .known_dids
            .iter()
            .find(|ddoc| ddoc.did() == _did)
            .map(|ddoc| Box::new((*ddoc).clone()) as Box<dyn DIDDoc>))
    }
}

#[derive(Clone, Debug)]
pub struct ExampleDIDDoc {
    did: String,
    key_agreements: Vec<String>,
    authentications: Vec<String>,
    verification_methods: Vec<VerificationMethod>,
    services: Vec<Service>,
}

impl DIDDoc for ExampleDIDDoc {
    fn did(&self) -> &str {
        &self.did
    }

    fn key_agreements(&self) -> &[String] {
        &self.key_agreements
    }

    fn authentications(&self) -> &[String] {
        &self.authentications
    }

    fn verification_methods(&self) -> &[VerificationMethod] {
        &self.verification_methods
    }

    fn services(&self) -> &[Service] {
        &self.services
    }
}
