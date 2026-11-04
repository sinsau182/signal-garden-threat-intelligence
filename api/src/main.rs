//! Signal Garden vSOC — Rust API service.
//!
//! Backend-only port of the TanStack Start server functions. This phase covers
//! the public, keyless threat-intel endpoints (no auth, no database):
//!   GET  /api/intel/live        -> CISA KEV + FIRST EPSS, aggregated (intel::live)
//!   POST /api/intel/osv         -> OSV.dev package/version lookup     (osv::query)
//!   GET  /api/intel/nvd         -> NVD API 2.0 recent CVEs           (nvd::recent)
//!   GET  /api/intel/feed-status -> live reachability for the catalog (feed_status::status)
//! plus a /health check. Auth (JWKS) is wired in `auth` but not yet applied to
//! any route; database endpoints come in a later phase.

mod auth;
mod feed_status;
mod intel;
mod nvd;
mod osv;

use std::time::Duration;

use axum::{routing::get, routing::post, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Shared state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    /// One pooled HTTP client reused for all outbound feed calls.
    pub http: reqwest::Client,
    /// JWKS cache for Supabase token verification (used once auth is applied).
    pub jwks: auth::JwksCache,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .init();

    let http = reqwest::Client::builder()
        .user_agent("vsoc-intel/1.0")
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build HTTP client");

    let state = AppState {
        http,
        jwks: auth::JwksCache::new(),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/intel/live", get(intel::live))
        .route("/api/intel/osv", post(osv::query))
        .route("/api/intel/nvd", get(nvd::recent))
        .route("/api/intel/feed-status", get(feed_status::status))
        // Dev-friendly CORS so the Vite frontend can call us. Tighten for prod
        // via an allowlist (see AppState / env wiring in a later step).
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);
    let addr = format!("0.0.0.0:{port}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    tracing::info!("vsoc-api listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

/// Liveness probe.
async fn health() -> &'static str {
    "ok"
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
