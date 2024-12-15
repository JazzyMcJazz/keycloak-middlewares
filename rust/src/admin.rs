use anyhow::{anyhow, bail, Result};
use jsonwebtoken::TokenData;
use lru::LruCache;
use rand::Rng;
use serde::de::DeserializeOwned;
use std::{fmt, num::NonZeroUsize, sync::Arc};
use tokio::sync::Mutex;

use super::{
    cache::JwksCache, claims::Claims, enums::GrantType, jwk::Jwks, response_types::TokenResponse,
};

pub struct Keycloak {
    kc_base_url: String,
    kc_realm_id: String,
    kc_client_id: String,
    kc_client_secret: String,
    jwk_cache: Arc<Mutex<LruCache<&'static str, JwksCache>>>,
}

impl Default for Keycloak {
    /// Create a new Keycloak instance with values from the environment
    fn default() -> Self {
        let kc_base_url = std::env::var("KEYCLOAK_BASE_URL")
            .expect("KEYCLOAK_BASE_URL is missing from the environment");
        let kc_realm_id = std::env::var("KEYCLOAK_REALM_ID")
            .expect("KEYCLOAK_REALM_ID is missing from the environment");
        let kc_client_id = std::env::var("KEYCLOAK_CLIENT_ID")
            .expect("KEYCLOAK_CLIENT_ID is missing from the environment");
        let kc_client_secret = std::env::var("KEYCLOAK_CLIENT_SECRET")
            .expect("KEYCLOAK_CLIENT_SECRET is missing from the environment");

        Self {
            kc_base_url,
            kc_realm_id,
            kc_client_id,
            kc_client_secret,
            jwk_cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(1).unwrap()))),
        }
    }
}

impl Keycloak {
    /// Create a new Keycloak instance with the provided values
    pub fn new(
        kc_base_url: String,
        kc_realm_id: String,
        kc_client_id: String,
        kc_client_secret: String,
    ) -> Self {
        Self {
            kc_base_url,
            kc_realm_id,
            kc_client_id,
            kc_client_secret,
            jwk_cache: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(1).unwrap()))),
        }
    }

    pub async fn exchange_token(
        &self,
        grant_type: GrantType<'_>,
        redirect_uri: &str,
    ) -> Result<TokenResponse> {
        let client = reqwest::Client::new();
        let base_url = &self.kc_base_url;
        let realm_id = &self.kc_realm_id;
        let token_url = format!("{base_url}/realms/{realm_id}/protocol/openid-connect/token");
        let form = [
            ("grant_type", grant_type.type_field_value()),
            ("client_id", &self.kc_client_id),
            ("redirect_uri", redirect_uri),
            (grant_type.code_field_key(), grant_type.code_field_value()),
            ("client_secret", &self.kc_client_secret),
        ];

        let response = client.post(&token_url).form(&form).send().await;

        match response {
            Ok(response) => {
                if response.status().is_success() {
                    let token = response.json::<TokenResponse>().await?;
                    Ok(token)
                } else {
                    bail!(response.text().await?)
                }
            }
            Err(e) => bail!(e),
        }
    }

    /// Insecurely decode a token without verifying the signature
    pub fn decode_token<T: DeserializeOwned>(&self, token: &str) -> Result<TokenData<T>> {
        let key = jsonwebtoken::DecodingKey::from_secret(&[]);
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.validate_nbf = false;

        let decoded = jsonwebtoken::decode::<T>(token, &key, &validation)?;

        Ok(decoded)
    }

    pub async fn validate_token(&self, token: &str) -> Result<Claims> {
        let mut jwks = self.get_jwks().await?;

        let jwk = match jwks.match_kid(token) {
            Some(jwk) => jwk,
            None => {
                // If the token is not found in the JWKS, fetch the JWKS again and try to find the token
                jwks = self.fetch_jwks().await?;
                let jwk = jwks
                    .match_kid(token)
                    .ok_or(anyhow!("Token not found in JWKS"))?;

                // Update the cache with the new JWKS if a matching JWK is found
                self.jwk_cache
                    .lock()
                    .await
                    .put("c", JwksCache::from(jwks.clone()));
                jwk
            }
        };

        jwk.validate(token)
    }

    pub fn login_url(&self, redirect_uri: &str) -> String {
        let state = generate_state();
        let base_url = &self.kc_base_url;
        let realm_id = &self.kc_realm_id;
        let client_id = &self.kc_client_id;

        let login_url = format!(
            "{base_url}/realms/{realm_id}/protocol/openid-connect/auth?client_id={client_id}&response_type=code&scope=openid&redirect_uri={redirect_uri}&state={state}",
        );
        login_url
    }

    pub async fn logout(&self, refresh_token: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let base_url = &self.kc_base_url;
        let realm_id = &self.kc_realm_id;
        let client_id = &self.kc_client_id;
        let client_secret = &self.kc_client_secret;

        let token_url = format!("{base_url}/realms/{realm_id}/protocol/openid-connect/logout");
        let form = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", &refresh_token.to_owned()),
        ];

        client.post(&token_url).form(&form).send().await?;
        Ok(())
    }

    async fn get_jwks(&self) -> Result<Jwks> {
        let mut cache = self.jwk_cache.lock().await;

        match cache.get_mut("c") {
            Some(cache) => {
                let jwks = cache.get();
                let jwks = match jwks {
                    None => {
                        let result = self.fetch_jwks().await?;
                        cache.put(result.clone());
                        result
                    }
                    Some(jwks) => jwks.clone(),
                };

                Ok(jwks.clone())
            }
            None => {
                let result = self.fetch_jwks().await?;
                cache.put("c", JwksCache::from(result.clone()));
                Ok(result)
            }
        }
    }

    async fn fetch_jwks(&self) -> Result<Jwks> {
        let client = reqwest::Client::new();
        let base_url = &self.kc_base_url;
        let realm_id = &self.kc_realm_id;
        let jwks_url = format!("{base_url}/realms/{realm_id}/protocol/openid-connect/certs");

        let response = client.get(&jwks_url).send().await;

        match response {
            Ok(response) => {
                if response.status().is_success() {
                    let jwks = response.json::<Jwks>().await?;
                    Ok(jwks)
                } else {
                    bail!("Failed to get JWKS")
                }
            }
            Err(e) => {
                bail!(e)
            }
        }
    }
}

impl fmt::Debug for Keycloak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keycloak")
            .field("cache_locked", &self.jwk_cache.try_lock().is_err())
            .finish()
    }
}

// Implement Clone manually
impl Clone for Keycloak {
    fn clone(&self) -> Self {
        Keycloak {
            kc_base_url: self.kc_base_url.clone(),
            kc_realm_id: self.kc_realm_id.clone(),
            kc_client_id: self.kc_client_id.clone(),
            kc_client_secret: self.kc_client_secret.clone(),
            jwk_cache: self.jwk_cache.clone(),
        }
    }
}

fn generate_state() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}
