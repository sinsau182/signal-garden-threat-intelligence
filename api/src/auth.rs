//! Supabase JWT verification — the Rust replacement for `auth-middleware.ts`.
//!
//! Instead of calling `supabase.auth.getClaims()` over the network per request,
//! we verify the Bearer token locally:
//!   * asymmetric tokens (RS256/ES256) against the project JWKS, fetched from
//!     `$SUPABASE_URL/auth/v1/.well-known/jwks.json` and cached;
//!   * legacy HS256 tokens against `SUPABASE_JWT_SECRET` when that env is set.
//!
//! `AuthUser` is an axum extractor; apply it to a handler to require auth. It is
//! not yet wired to any route (the DB endpoints that need it come later), so it
//! is allowed to be unused for now.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::{request::Parts, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use tokio::sync::RwLock;

/// How long a fetched JWKS stays fresh before we refetch.
const JWKS_TTL: Duration = Duration::from_secs(3600);

/// Thread-safe, lazily-populated JWKS cache.
#[derive(Clone)]
pub struct JwksCache {
    inner: Arc<RwLock<Option<Cached>>>,
}

struct Cached {
    set: JwkSet,
    fetched: Instant,
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Return a cached JWKS, refetching if empty or stale.
    async fn get(&self, http: &reqwest::Client) -> Result<JwkSet, String> {
        if let Some(c) = self.inner.read().await.as_ref() {
            if c.fetched.elapsed() < JWKS_TTL {
                return Ok(c.set.clone());
            }
        }

        let base = std::env::var("SUPABASE_URL")
            .map_err(|_| "Missing Supabase environment variable(s): SUPABASE_URL".to_string())?;
        let url = format!("{}/auth/v1/.well-known/jwks.json", base.trim_end_matches('/'));
        let set: JwkSet = http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {e}"))?;

        *self.inner.write().await = Some(Cached {
            set: set.clone(),
            fetched: Instant::now(),
        });
        Ok(set)
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Authenticated principal extracted from a verified token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// `sub` claim — the Supabase user id.
    pub user_id: String,
    /// Full claims payload, for downstream role/aud checks.
    pub claims: Value,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    crate::AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = crate::AppState::from_ref(state);
        let token = bearer_token(parts)?;
        verify(&token, &app.http, &app.jwks)
            .await
            .map(|claims| AuthUser {
                user_id: claims
                    .get("sub")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                claims,
            })
            .and_then(|u| {
                if u.user_id.is_empty() {
                    Err(unauthorized("No user ID found in token"))
                } else {
                    Ok(u)
                }
            })
    }
}

/// Pull and sanity-check the `Authorization: Bearer <jwt>` header.
fn bearer_token(parts: &Parts) -> Result<String, (StatusCode, String)> {
    let header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| unauthorized("No authorization header provided"))?
        .to_str()
        .map_err(|_| unauthorized("Invalid authorization header"))?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| unauthorized("Only Bearer tokens are supported"))?
        .trim();

    if token.is_empty() {
        return Err(unauthorized("No token provided"));
    }
    if token.split('.').count() != 3 {
        return Err(unauthorized("Invalid token"));
    }
    Ok(token.to_string())
}

/// Verify a token and return its claims, or an Unauthorized rejection.
async fn verify(
    token: &str,
    http: &reqwest::Client,
    jwks: &JwksCache,
) -> Result<Value, (StatusCode, String)> {
    let header = decode_header(token).map_err(|_| unauthorized("Invalid token"))?;

    let mut validation = Validation::new(header.alg);
    // Supabase user tokens carry aud = "authenticated".
    validation.set_audience(&["authenticated"]);

    let key = match header.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let secret = std::env::var("SUPABASE_JWT_SECRET").map_err(|_| {
                unauthorized("HS256 token but SUPABASE_JWT_SECRET is not configured")
            })?;
            DecodingKey::from_secret(secret.as_bytes())
        }
        _ => {
            let kid = header
                .kid
                .ok_or_else(|| unauthorized("Token missing key id (kid)"))?;
            let set = jwks
                .get(http)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            let jwk = set
                .find(&kid)
                .ok_or_else(|| unauthorized("Signing key not found in JWKS"))?;
            DecodingKey::from_jwk(jwk).map_err(|_| unauthorized("Unusable signing key"))?
        }
    };

    let data = decode::<Value>(token, &key, &validation)
        .map_err(|_| unauthorized("Invalid token"))?;
    Ok(data.claims)
}

fn unauthorized(msg: &str) -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, format!("Unauthorized: {msg}"))
}
