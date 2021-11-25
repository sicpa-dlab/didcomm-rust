use std::sync::Arc;

use didcomm_core::{error::ErrorKind, FromPrior as _FromPrior};

use crate::DIDComm;

use crate::common::{ErrorCode, EXECUTOR};
use crate::did_resolver_adapter::DIDResolverAdapter;
use crate::secrets_resolver_adapter::SecretsResolverAdapter;

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
        let did_resolver = DIDResolverAdapter::new(self.did_resolver.clone());
        let secret_resolver = SecretsResolverAdapter::new(self.secret_resolver.clone());

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
        let did_resolver = DIDResolverAdapter::new(self.did_resolver.clone());

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

#[cfg(test)]
mod tests {
    use crate::test_vectors::{
        ALICE_DID, CHARLIE_DID, CHARLIE_ROTATED_TO_ALICE_SECRETS, CHARLIE_SECRET_AUTH_KEY_ED25519,
    };
    use crate::{
        test_vectors::test_helper::{
            create_did_resolver, get_ok, FromPriorPackResult, FromPriorUnpackResult,
        },
        DIDComm, ExampleSecretsResolver, FromPriorExt,
    };

    #[tokio::test]
    async fn pack_from_prior_works() {
        let (cb, receiver) = FromPriorPackResult::new();

        let from_prior = FromPriorExt::new(CHARLIE_DID.into(), ALICE_DID.into(), None);

        DIDComm::new(
            create_did_resolver(),
            Box::new(ExampleSecretsResolver::new(
                CHARLIE_ROTATED_TO_ALICE_SECRETS.clone(),
            )),
        )
        .pack_from_prior(
            &from_prior,
            Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone()),
            cb,
        );

        let (_, kid) = get_ok(receiver).await;
        assert_eq!(kid, CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone());
    }

    #[tokio::test]
    async fn unpack_from_prior_works() {
        let (cb, receiver) = FromPriorPackResult::new();
        let did_comm = DIDComm::new(
            create_did_resolver(),
            Box::new(ExampleSecretsResolver::new(
                CHARLIE_ROTATED_TO_ALICE_SECRETS.clone(),
            )),
        );

        let from_prior = FromPriorExt::new(CHARLIE_DID.into(), ALICE_DID.into(), Some(1234));
        did_comm.pack_from_prior(
            &from_prior,
            Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone()),
            cb,
        );
        let (res, _) = get_ok(receiver).await;

        let (cb, receiver) = FromPriorUnpackResult::new();
        did_comm.unpack_from_prior(res, cb);
        let (res, kid) = get_ok(receiver).await;

        assert_eq!(kid, CHARLIE_SECRET_AUTH_KEY_ED25519.id.clone());
        assert_eq!(CHARLIE_DID.clone(), res.iss);
        assert_eq!(ALICE_DID.clone(), res.sub);
        assert_eq!(Some(1234), res.exp);
    }
}
