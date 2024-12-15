use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    iss: String,
    sub: String,
    exp: u64,
    iat: u64,
    jti: String,
    typ: String,
    azp: String,
    email_verified: bool,
    name: String,
    preferred_username: String,
    given_name: String,
    family_name: String,
    email: String,
}

impl Claims {
    pub fn iss(&self) -> &String {
        &self.iss
    }
    pub fn sub(&self) -> &String {
        &self.sub
    }
    pub fn exp(&self) -> &u64 {
        &self.exp
    }
    pub fn iat(&self) -> &u64 {
        &self.iat
    }
    pub fn jti(&self) -> &String {
        &self.jti
    }
    pub fn typ(&self) -> &String {
        &self.typ
    }
    pub fn azp(&self) -> &String {
        &self.azp
    }
    pub fn email_verified(&self) -> &bool {
        &self.email_verified
    }
    pub fn name(&self) -> &String {
        &self.name
    }
    pub fn preferred_username(&self) -> &String {
        &self.preferred_username
    }
    pub fn email(&self) -> &String {
        &self.email
    }
    pub fn given_name(&self) -> &String {
        &self.given_name
    }
    pub fn family_name(&self) -> &String {
        &self.family_name
    }
}
