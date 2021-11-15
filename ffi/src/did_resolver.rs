use async_trait::async_trait;
use didcomm::did::{DIDDoc, DIDResolver};
use didcomm::error::{err_msg, ErrorKind, Result, ToResult};

#[async_trait]
pub trait FFIDIDResolver: Sync + Send {
    fn resolve(&self, did: String) -> Result<Option<String>>;
}

pub struct DIDResolverAdapter {
    did_resolver: Box<dyn FFIDIDResolver>,
}

impl DIDResolverAdapter {
    pub fn new(did_resolver: Box<dyn FFIDIDResolver>) -> Self {
        DIDResolverAdapter { did_resolver }
    }
}

#[async_trait]
impl DIDResolver for DIDResolverAdapter {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        // TODO: better error conversion
        let ddoc = self.did_resolver.resolve(String::from(did)).map_err(|e| {
            err_msg(
                ErrorKind::InvalidState,
                format!("Unable resolve did {:#?}", e),
            )
        })?;

        match ddoc {
            Some(ddoc) => {
                Ok(serde_json::from_str(&ddoc)
                    .to_didcomm("Unable deserialize DIDDoc from JsValue")?)
            }
            None => Ok(None),
        }
    }
}

pub struct ExampleFFIDIDResolver {
    known_dids: Vec<String>,
}

impl ExampleFFIDIDResolver {
    pub fn new(known_dids: Vec<String>) -> Self {
        ExampleFFIDIDResolver { known_dids }
    }
}

impl FFIDIDResolver for ExampleFFIDIDResolver {
    fn resolve(&self, did: String) -> Result<Option<String>> {
        Ok(self
            .known_dids
            .iter()
            .map(|ddoc| {
                let d: DIDDoc = serde_json::from_str(ddoc).unwrap();
                d
            })
            .find(|ddoc| ddoc.did == did)
            .map(|ddoc| serde_json::to_string(&ddoc).unwrap()))
    }
}
