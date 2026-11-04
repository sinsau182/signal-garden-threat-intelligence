//! Port of `queryOsv` from `src/lib/intel.functions.ts`.
//!
//! Live: OSV.dev lookup for a package/version. Public data only.
//! Inputs are length-clamped exactly like the TS `inputValidator`.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::AppState;

const OSV_URL: &str = "https://api.osv.dev/v1/query";

/// Request body: `{ name, version, ecosystem }`.
#[derive(Debug, Deserialize)]
pub struct OsvInput {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvRaw {
    #[serde(default)]
    vulns: Vec<OsvVulnRaw>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnRaw {
    id: String,
    summary: Option<String>,
    aliases: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct OsvVuln {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aliases: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OsvResult {
    vulns: Vec<OsvVuln>,
    error: Option<String>,
}

/// Clamp a string to at most `max` characters (char-wise, like JS `slice`).
fn clamp(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// `POST /api/intel/osv`
pub async fn query(State(state): State<AppState>, Json(input): Json<OsvInput>) -> Json<OsvResult> {
    let name = clamp(&input.name, 200);
    let version = clamp(&input.version, 50);
    let ecosystem = clamp(&input.ecosystem, 30);

    let body = OsvQuery {
        package: OsvPackage {
            name,
            ecosystem,
        },
        version,
    };

    let res = match state.http.post(OSV_URL).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            return Json(OsvResult {
                vulns: vec![],
                error: Some(format!("OSV request failed: {e}")),
            })
        }
    };

    if !res.status().is_success() {
        return Json(OsvResult {
            vulns: vec![],
            error: Some(format!("OSV {}", res.status().as_u16())),
        });
    }

    let raw: OsvRaw = match res.json().await {
        Ok(j) => j,
        Err(e) => {
            return Json(OsvResult {
                vulns: vec![],
                error: Some(format!("OSV parse failed: {e}")),
            })
        }
    };

    let vulns = raw
        .vulns
        .into_iter()
        .take(30)
        .map(|v| OsvVuln {
            id: v.id,
            summary: v.summary,
            aliases: v.aliases,
        })
        .collect();

    Json(OsvResult { vulns, error: None })
}
