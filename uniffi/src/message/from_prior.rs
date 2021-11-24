use std::sync::Arc;

use didcomm::{error::ErrorKind, FromPrior as _FromPrior};

use crate::DIDComm;

use crate::common::{ErrorCode, EXECUTOR};
use crate::did_resolver_adapter::FFIDIDResolverAdapter;
use crate::secrets_resolver_adapter::FFISecretsResolverAdapter;

pub trait OnFromPriorPackResult: Sync + Send {
    fn success(&self, from_prior_jwt: String, kid: String);
    fn error(&self, err: ErrorKind, err_msg: String);
}

pub trait OnFromPriorUnpackResult: Sync + Send {
    // TODO: return FromPriorExt
    fn success(&self, from_prior: _FromPrior, kid: String);
    fn error(&self, err: ErrorKind, err_msg: String);
}

pub struct FromPriorExt(Arc<_FromPrior>);

impl FromPriorExt {
    pub fn new(iss: String, sub: String, exp: Option<u64>) -> Self {
        FromPriorExt(Arc::new(_FromPrior {
            iss: iss,
            sub: sub,
            exp: exp,
            aud: None,
            iat: None,
            jti: None,
            nbf: None,
        }))
    }

    pub fn get_iss(&self) -> String {
        self.0.iss.clone()
    }
    pub fn get_sub(&self) -> String {
        self.0.sub.clone()
    }
    pub fn get_exp(&self) -> Option<u64> {
        self.0.exp
    }
}

impl DIDComm {
    pub fn pack_from_prior(
        &self,
        msg: &FromPriorExt,
        issuer_kid: Option<String>,
        cb: Box<dyn OnFromPriorPackResult>,
    ) -> ErrorCode {
        let msg = msg.0.clone();
        let did_resolver = FFIDIDResolverAdapter::new(self.did_resolver.clone());
        let secret_resolver = FFISecretsResolverAdapter::new(self.secret_resolver.clone());

        let future = async move {
            msg.pack(issuer_kid.as_deref(), &did_resolver, &secret_resolver)
                .await
        };
        EXECUTOR.spawn_ok(async move {
            match future.await {
                Ok((from_prior_jwt, kid)) => cb.success(from_prior_jwt, kid),
                Err(err) => cb.error(err.kind(), err.to_string()),
            }
        });

        ErrorCode::Success
    }

    pub fn unpack_from_prior(
        &self,
        from_prior_jwt: String,
        cb: Box<dyn OnFromPriorUnpackResult>,
    ) -> ErrorCode {
        let did_resolver = FFIDIDResolverAdapter::new(self.did_resolver.clone());

        let future = async move { _FromPrior::unpack(&from_prior_jwt, &did_resolver).await };
        EXECUTOR.spawn_ok(async move {
            match future.await {
                Ok((from_prior_jwt, kid)) => cb.success(from_prior_jwt, kid),
                Err(err) => cb.error(err.kind(), err.to_string()),
            }
        });

        ErrorCode::Success
    }
}

// TODO: tests
