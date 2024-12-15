# Keycloak Middlewares for Rust

## Installation

Add the following to Cargo.toml:
```toml
[dependencies]
keycloak-middlewares = { git = "https://github.com/JazzyMcJazz/keycloak-middlewares.git" }
```

## Usage

### Actix Middleware:

#### 1. Include the `actix` feature.

#### 2. Add Keycloak and the middleware to you App:

```rust
use keycloak_middlewares::{
    Keycloak, 
    actix::auth_middleware
};

#[actix_web::main]
pub async fn server() -> std::io::Result<()> {
    
    // Instantiate with environment variables
    let kc = Keycloak::default();

    // Instantiate with values
    let kc = Keycloak::new(
        kc_base_url,
        kc_realm_id,
        kc_client_id,
        kc_client_secret
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(kc.clone()))
            .wrap(from_fn(auth_middleware))
    })
    .bind((host, port))?
    .run().await
}
```

## Environment Variables
If using `Keycloak::default()` the following variables must be available in your environment:

```
KEYCLOAK_BASE_URL
KEYCLOAK_REALM_ID
KEYCLOAK_CLIENT_ID
KEYCLOAK_CLIENT_SECRET
```

