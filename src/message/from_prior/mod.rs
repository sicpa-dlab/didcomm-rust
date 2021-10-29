use serde::{Deserialize, Serialize};

mod pack;
mod unpack;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct FromPrior {
    pub iss: String,

    pub sub: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

const JWT_TYP: &str = "JWT";

impl FromPrior {
    pub fn build(iss: String, sub: String) -> FromPriorBuilder {
        FromPriorBuilder::new(iss, sub)
    }
}

pub struct FromPriorBuilder {
    iss: String,
    sub: String,
    aud: Option<String>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    jti: Option<String>,
}

impl FromPriorBuilder {
    fn new(iss: String, sub: String) -> Self {
        FromPriorBuilder {
            iss,
            sub,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
        }
    }

    pub fn aud(mut self, aud: String) -> Self {
        self.aud = Some(aud);
        self
    }

    pub fn exp(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    pub fn nbf(mut self, nbf: u64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    pub fn iat(mut self, iat: u64) -> Self {
        self.iat = Some(iat);
        self
    }

    pub fn jti(mut self, jti: String) -> Self {
        self.jti = Some(jti);
        self
    }

    pub fn finalize(self) -> FromPrior {
        FromPrior {
            iss: self.iss,
            sub: self.sub,
            aud: self.aud,
            exp: self.exp,
            nbf: self.nbf,
            iat: self.iat,
            jti: self.jti,
        }
    }
}
