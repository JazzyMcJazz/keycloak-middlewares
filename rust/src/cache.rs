use super::jwk::Jwks;
use std::time::SystemTime;

#[derive(Debug)]
pub struct JwksCache {
    jwks: Option<Jwks>,
    expires: SystemTime,
}

impl Default for JwksCache {
    fn default() -> Self {
        JwksCache {
            jwks: None,
            expires: JwksCache::new_expiration(),
        }
    }
}

impl JwksCache {
    pub fn from(jwks: Jwks) -> Self {
        JwksCache {
            jwks: Some(jwks),
            expires: JwksCache::new_expiration(),
        }
    }

    pub fn get(&mut self) -> Option<&Jwks> {
        if self.is_expired() {
            self.jwks = None;
        }

        self.jwks.as_ref()
    }

    pub fn put(&mut self, jwks: Jwks) {
        self.jwks = Some(jwks);
        self.expires = JwksCache::new_expiration();
    }

    pub fn is_expired(&self) -> bool {
        self.expires < SystemTime::now()
    }

    pub fn new_expiration() -> SystemTime {
        SystemTime::now() + std::time::Duration::from_secs(60 * 60 * 24) // 24 hours
    }
}
