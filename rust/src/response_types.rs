use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    access_token: String,
    refresh_token: String,
    id_token: String,
    expires_in: i64,
}

impl TokenResponse {
    pub fn access_token(&self) -> &String {
        &self.access_token
    }
    pub fn refresh_token(&self) -> &String {
        &self.refresh_token
    }
    pub fn id_token(&self) -> &String {
        &self.id_token
    }
    pub fn access_token_expires_in(&self) -> i64 {
        self.expires_in
    }
}
