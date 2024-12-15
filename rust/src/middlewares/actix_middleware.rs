use crate::{enums::GrantType, response_types::TokenResponse, Keycloak};
use actix_web::{
    body::MessageBody,
    cookie::{self, Cookie, SameSite},
    dev::{ServiceRequest, ServiceResponse},
    error,
    middleware::Next,
    web, Error, HttpResponse,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct ExpirationClaim {
    exp: u64,
}

impl ExpirationClaim {
    pub fn exp(&self) -> &u64 {
        &self.exp
    }
}

pub async fn auth_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody + 'static>, Error> {
    let access_token = req.cookie("access_token").map(|c| c.value().to_string());
    let refresh_token = req.cookie("refresh_token").map(|c| c.value().to_string());

    let kc = req
        .app_data::<web::Data<Keycloak>>()
        .ok_or_else(|| error::ErrorInternalServerError("Internal Server Error"))?;

    let redirect_uri = {
        let info = req.connection_info();
        let path = match req.uri().path_and_query() {
            Some(p) => normalize_path_and_query(p.as_str()),
            None => req.uri().path().to_string(),
        };
        format!("{}://{}{}", info.scheme(), info.host(), path)
    };

    let (mut tokens, mut access_token_data, mut refresh_token_data) = (
        None::<TokenResponse>,
        None::<jsonwebtoken::TokenData<ExpirationClaim>>,
        None::<jsonwebtoken::TokenData<ExpirationClaim>>,
    );

    // Validate the access token
    if let Some(token) = access_token {
        kc.validate_token(&token)
            .await
            .map_err(|_| error::ErrorUnauthorized("Unauthorized [Invalid Access Token]"))?;

    // Refresh the token if the access token is expired
    } else if let Some(token) = refresh_token {
        let token_reponse = kc
            .exchange_token(GrantType::RefreshToken(&token), &redirect_uri)
            .await
            .map_err(|e| error::ErrorUnauthorized(format!("Unauthorized [Error Exchanging Refresh Token] | {e}")))?;

        let decoded_access_token = kc
            .decode_token(&token_reponse.access_token())
            .map_err(|_| error::ErrorUnauthorized("Unauthorized [Error Decoding New Access Token (1)]"))?;

        let decoded_refresh_token = kc
            .decode_token(&token_reponse.refresh_token())
            .map_err(|_| error::ErrorUnauthorized("Unauthorized [Error Decoding New Refresh Token (1)]"))?;

        tokens = Some(token_reponse);
        access_token_data = Some(decoded_access_token);
        refresh_token_data = Some(decoded_refresh_token);
    // Exchange the authorization code for tokens if the code is present
    } else if let Some(code) = req.query_string().split('&').find_map(|kv| {
        let mut parts = kv.split('=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k == "code" {
                return Some(v);
            }
        }
        None
    }) {
        let tokens = kc
            .exchange_token(
                GrantType::AuthorizationCode(code.to_string()),
                &redirect_uri,
            )
            .await
            .map_err(|_| error::ErrorUnauthorized("Unauthorized [Error Exchanging Authorization Code]"))?;

        let access_token_data = kc
            .decode_token::<ExpirationClaim>(&tokens.access_token())
            .map_err(|_| error::ErrorUnauthorized("Unauthorized [Error Decoding Access Token (2)]"))?;

        let refresh_token_data = kc
            .decode_token::<ExpirationClaim>(&tokens.refresh_token())
            .map_err(|_| error::ErrorUnauthorized("Unauthorized [Error Decoding Refresh Token (2)]"))?;

        let (req, _) = req.into_parts();
        let res = HttpResponse::Found()
            .cookie(create_cookie(
                "access_token",
                &tokens.access_token(),
                *access_token_data.claims.exp() as i64,
            ))
            .cookie(create_cookie(
                "refresh_token",
                &tokens.refresh_token(),
                *refresh_token_data.claims.exp() as i64,
            ))
            .insert_header(("Location", redirect_uri))
            .finish()
            .map_into_right_body();

        return Ok(ServiceResponse::new(req, res));

    // Redirect to the login page if no tokens are present
    } else {
        let login_url = kc.login_url(&redirect_uri);
        let req = req.into_parts().0;
        let res = HttpResponse::Found()
            .insert_header(("Location", login_url))
            .finish()
            .map_into_right_body();
        return Ok(ServiceResponse::new(req, res));
    }

    let mut res = next
        .call(req)
        .await
        .map(ServiceResponse::map_into_left_body)?;

    // Set the access and refresh tokens as cookies if they have been updated
    if let (Some(tokens), Some(access_token_data), Some(refresh_token_data)) =
        (tokens, access_token_data, refresh_token_data)
    {
        res.response_mut().add_cookie(&create_cookie(
            "access_token",
            &tokens.access_token(),
            *access_token_data.claims.exp() as i64,
        ))?;
        res.response_mut().add_cookie(&create_cookie(
            "refresh_token",
            &tokens.refresh_token(),
            *refresh_token_data.claims.exp() as i64,
        ))?;
    }

    Ok(res)
}

fn normalize_path_and_query(path_and_query: &str) -> String {
    let parts: Vec<&str> = path_and_query.split('?').collect();
    if parts.len() > 1 {
        let query = parts[1];
        let filtered_query = query
            .split('&')
            .filter(|kv| {
                let key = kv.split('=').next().unwrap_or("");
                !matches!(key, "state" | "session_state" | "iss" | "code")
            })
            .collect::<Vec<&str>>()
            .join("&")
            .trim_end_matches('/')
            .to_string();
        format!(
            "{}{}{}",
            parts[0],
            if filtered_query.is_empty() { "" } else { "?" },
            filtered_query
        )
    } else {
        path_and_query.to_string()
    }
}

fn create_cookie<'a>(name: &'a str, value: &'a str, exp: i64) -> Cookie<'a> {
    let exp = match cookie::time::OffsetDateTime::from_unix_timestamp(exp) {
        Ok(exp) => exp,
        Err(_) => cookie::time::OffsetDateTime::now_utc(),
    };

    Cookie::build(name, value)
        .http_only(true)
        .secure(true)
        .path("/")
        .expires(exp)
        .same_site(SameSite::Lax)
        .finish()
}
