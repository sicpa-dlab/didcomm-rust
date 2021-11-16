use didcomm::error::{ErrorKind as _ErrorKind, Result as _Result};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/src/error.js")]
extern "C" {
    pub(crate) type DIDCommError;

    #[wasm_bindgen(constructor)]
    fn new(kind: ErrorKind, message: &str) -> DIDCommError;
}

pub(crate) trait JsResult<T> {
    fn as_js(self) -> Result<T, DIDCommError>;
}

impl<T> JsResult<T> for _Result<T> {
    fn as_js(self) -> Result<T, DIDCommError> {
        self.map_err(|e| DIDCommError::new(e.kind().into(), &format!("{}", e)))
    }
}

#[wasm_bindgen]
pub enum ErrorKind {
    DIDNotResolved,
    DIDUrlNotFound,
    SecretNotFound,
    Malformed,
    IoError,
    InvalidState,
    NoCompatibleCrypto,
    Unsupported,
    IllegalArgument,
}

impl From<_ErrorKind> for ErrorKind {
    fn from(kind: _ErrorKind) -> Self {
        match kind {
            _ErrorKind::DIDNotResolved => Self::DIDNotResolved,
            _ErrorKind::DIDUrlNotFound => Self::DIDUrlNotFound,
            _ErrorKind::SecretNotFound => Self::SecretNotFound,
            _ErrorKind::Malformed => Self::Malformed,
            _ErrorKind::IoError => Self::IoError,
            _ErrorKind::InvalidState => Self::InvalidState,
            _ErrorKind::NoCompatibleCrypto => Self::NoCompatibleCrypto,
            _ErrorKind::Unsupported => Self::Unsupported,
            _ErrorKind::IllegalArgument => Self::IllegalArgument,
        }
    }
}

#[wasm_bindgen(typescript_custom_section)]
const DIDCOMM_ERROR: &'static str = r#"
type DIDCommError = {kind: ErrorKind} & Error;
"#;
