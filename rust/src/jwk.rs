use anyhow::Result;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::str::FromStr;

use super::claims::Claims;

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    pub fn match_kid(&self, token: &str) -> Option<&Jwk> {
        let header = jsonwebtoken::decode_header(token).ok()?;
        let kid = header.kid?;
        self.keys.iter().find(|key| key.kid == kid)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Jwk {
    kid: String,
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    n: String,
    e: String,
    x5c: Vec<String>,
    x5t: String,
    #[serde(rename = "x5t#S256")]
    x5t_s256: String,
}

impl Jwk {
    pub fn validate(&self, token: &str) -> Result<Claims> {
        let decoding_key = DecodingKey::from_rsa_components(&self.n, &self.e)?;
        let alg = Algorithm::from_str(self.alg.as_str())?;
        let mut validation = Validation::new(alg);
        validation.set_audience(&["account"]);

        let result = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)?;
        Ok(result.claims)
    }
}
