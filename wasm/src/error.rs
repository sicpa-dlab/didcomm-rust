use didcomm::error::{err_msg as _err_msg, ErrorKind as _ErrorKind, Result as _Result};
use js_sys::{Error as JsError, JsString};
use wasm_bindgen::{prelude::*, JsCast};

// Alows convertion of didcomm error to javascript error
pub(crate) trait JsResult<T> {
    fn as_js(self) -> Result<T, JsError>;
}

impl<T> JsResult<T> for _Result<T> {
    fn as_js(self) -> Result<T, JsError> {
        self.map_err(|e| {
            let name = match e.kind() {
                _ErrorKind::DIDNotResolved => "DIDCommDIDNotResolved",
                _ErrorKind::DIDUrlNotFound => "DIDCommDIDUrlNotFound",
                _ErrorKind::Malformed => "DIDCommMalformed",
                _ErrorKind::IoError => "DIDCommIoError",
                _ErrorKind::InvalidState => "DIDCommInvalidState",
                _ErrorKind::NoCompatibleCrypto => "DIDCommNoCompatibleCrypto",
                _ErrorKind::Unsupported => "DIDCommUnsupported",
                _ErrorKind::IllegalArgument => "DIDCommIllegalArgument",
                _ErrorKind::SecretNotFound => "DIDCommSecretNotFound",
            };

            let e = JsError::new(&format!("{}", e));
            e.set_name(name);
            e
        })
    }
}

// Alows convertion of javascript error to didcomm error
pub(crate) trait FromJsResult<T> {
    fn from_js(self) -> _Result<T>;
}

impl<T> FromJsResult<T> for Result<T, JsValue> {
    fn from_js(self) -> _Result<T> {
        self.map_err(|e| {
            // String was thrown
            if let Some(e) = e.dyn_ref::<JsString>() {
                return _err_msg(
                    _ErrorKind::InvalidState,
                    e.as_string().unwrap_or(format!("{:?}", e)),
                );
            }

            // Error instance was thrown
            if let Some(e) = e.dyn_ref::<JsError>() {
                let kind = match e.name().as_string().as_deref() {
                    Some("DIDCommDIDNotResolved") => _ErrorKind::DIDNotResolved,
                    Some("DIDCommDIDUrlNotFound") => _ErrorKind::DIDUrlNotFound,
                    Some("DIDCommMalformed") => _ErrorKind::Malformed,
                    Some("DIDCommIoError") => _ErrorKind::IoError,
                    Some("DIDCommInvalidState") => _ErrorKind::InvalidState,
                    Some("DIDCommNoCompatibleCrypto") => _ErrorKind::NoCompatibleCrypto,
                    Some("DIDCommUnsupported") => _ErrorKind::Unsupported,
                    Some("DIDCommIllegalArgument") => _ErrorKind::IllegalArgument,
                    _ => _ErrorKind::InvalidState,
                };

                let message = e.message().as_string().unwrap_or(format!("{:?}", e));

                return _err_msg(kind, message);
            }

            // Something unusual was thrown
            _err_msg(_ErrorKind::InvalidState, format!("{:?}", e))
        })
    }
}
