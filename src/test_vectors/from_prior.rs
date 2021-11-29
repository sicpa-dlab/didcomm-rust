use lazy_static::lazy_static;

use super::common::{ALICE_DID, CHARLIE_DID};
use crate::{
    didcomm::FromPrior,
    test_vectors::{ALICE_AUTH_METHOD_25519, CHARLIE_AUTH_METHOD_25519},
};

lazy_static! {
    pub static ref FROM_PRIOR_MINIMAL: FromPrior =
        FromPrior::build(CHARLIE_DID.into(), ALICE_DID.into()).finalize();
}

lazy_static! {
    pub static ref FROM_PRIOR_FULL: FromPrior =
        FromPrior::build(CHARLIE_DID.into(), ALICE_DID.into())
            .aud("123".into())
            .exp(1234)
            .nbf(12345)
            .iat(123456)
            .jti("dfg".into())
            .finalize();
}

lazy_static! {
    pub static ref FROM_PRIOR_INVALID_ISS: FromPrior =
        FromPrior::build("invalid".into(), ALICE_DID.into())
            .aud("123".into())
            .exp(1234)
            .nbf(12345)
            .iat(123456)
            .jti("dfg".into())
            .finalize();
}

lazy_static! {
    pub static ref FROM_PRIOR_INVALID_ISS_DID_URL: FromPrior =
        FromPrior::build(CHARLIE_AUTH_METHOD_25519.id.clone(), ALICE_DID.into())
            .aud("123".into())
            .exp(1234)
            .nbf(12345)
            .iat(123456)
            .jti("dfg".into())
            .finalize();
}

lazy_static! {
    pub static ref FROM_PRIOR_INVALID_SUB: FromPrior =
        FromPrior::build(CHARLIE_DID.into(), "invalid".into())
            .aud("123".into())
            .exp(1234)
            .nbf(12345)
            .iat(123456)
            .jti("dfg".into())
            .finalize();
}

lazy_static! {
    pub static ref FROM_PRIOR_INVALID_SUB_DID_URL: FromPrior =
        FromPrior::build(CHARLIE_DID.into(), ALICE_AUTH_METHOD_25519.id.clone())
            .aud("123".into())
            .exp(1234)
            .nbf(12345)
            .iat(123456)
            .jti("dfg".into())
            .finalize();
}

lazy_static! {
    pub static ref FROM_PRIOR_INVALID_EQUAL_ISS_AND_SUB: FromPrior =
        FromPrior::build(ALICE_DID.into(), ALICE_DID.into())
            .aud("123".into())
            .exp(1234)
            .nbf(12345)
            .iat(123456)
            .jti("dfg".into())
            .finalize();
}
