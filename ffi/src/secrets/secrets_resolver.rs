use didcomm::error::ErrorKind;

use crate::common::ErrorCode;

pub trait FFISecretsResolver: Sync + Send {
    fn get_secret(
        &self, 
        secret_id: String, 
        cb: Box<dyn OnGetSecretResult>
    ) -> ErrorCode;

    fn find_secrets(
        &self,
        secret_ids: Vec<String>,
        cb: Box<dyn OnFindSecretsResult>
    ) -> ErrorCode;
}

pub trait OnGetSecretResult: Sync + Send {
    fn success(&self, result: Option<String>);
    fn error(&self, err: ErrorKind, msg: String);
}

pub trait OnFindSecretsResult: Sync + Send {
    fn success(&self, result: Vec<String>);
    fn error(&self, err: ErrorKind, msg: String);
}

