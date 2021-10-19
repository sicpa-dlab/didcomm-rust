#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FromPrior {
    pub iss: String,
    pub sub: String,
    pub aud: Option<String>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub jti: Option<String>,
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
