use crate::{did::VerificationMethod, error::Result, secrets::Secret, utils::crypto::SignKeyPair};

pub(crate) fn did_or_url(did_or_url: &str) -> (&str, Option<&str>) {
    // TODO: does it make sense to validate DID here?

    match did_or_url.split_once("#") {
        Some((did, _)) => (did, Some(did_or_url)),
        None => (did_or_url, None),
    }
}

pub(crate) trait ToSignKeyPair {
    fn to_sign_key_pair(&self) -> Result<SignKeyPair>;
}

impl ToSignKeyPair for VerificationMethod {
    fn to_sign_key_pair(&self) -> Result<SignKeyPair> {
        todo!()
    }
}

impl ToSignKeyPair for Secret {
    fn to_sign_key_pair(&self) -> Result<SignKeyPair> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::did::did_or_url;

    #[test]
    fn did_or_url_works() {
        let res = did_or_url("did:example:alice");
        assert_eq!(res, ("did:example:alice", None));

        let res = did_or_url("did:example:alice#key-1");
        assert_eq!(res, ("did:example:alice", Some("did:example:alice#key-1")));

        let res = did_or_url("#key-1");
        assert_eq!(res, ("", Some("#key-1")));

        let res = did_or_url("#");
        assert_eq!(res, ("", Some("#")));
    }
}
