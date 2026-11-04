//! Port of `getNvdRecent` from `src/lib/intel.functions.ts`.
//!
//! Live: NVD API 2.0 — the most recently published CVEs. Keyless by default
//! (NVD rate-limits anonymous callers); set `NVD_API_KEY` to raise the limit,
//! sent as the `apiKey` header exactly like the TS version. Public data only.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

const NVD_URL: &str =
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&startIndex=0";

/// Flattened CVE record returned to the frontend (mirrors `NvdItem`).
#[derive(Debug, Serialize)]
struct NvdItem {
    id: String,
    published: String,
    summary: String,
    cvss: Option<f64>,
    severity: Option<String>,
}

// --- Raw NVD response shapes (only the fields we use) ---

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(rename = "totalResults")]
    total_results: u64,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnWrap>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnWrap {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    published: String,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: Option<NvdMetrics>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31", default)]
    v31: Vec<NvdMetric>,
    #[serde(rename = "cvssMetricV30", default)]
    v30: Vec<NvdMetric>,
}

#[derive(Debug, Deserialize)]
struct NvdMetric {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity")]
    base_severity: String,
}

/// `GET /api/intel/nvd`
pub async fn recent(State(state): State<AppState>) -> Json<Value> {
    let fetched_at = crate::intel::now_iso8601();
    let key = std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty());

    match build(&state.http, key.as_deref()).await {
        Ok((total, items)) => Json(json!({
            "ok": true,
            "fetchedAt": fetched_at,
            "total": total,
            "items": items,
            "keyed": key.is_some(),
        })),
        Err(err) => Json(json!({
            "ok": false,
            "fetchedAt": fetched_at,
            "error": err,
        })),
    }
}

async fn build(
    http: &reqwest::Client,
    api_key: Option<&str>,
) -> Result<(u64, Vec<NvdItem>), String> {
    let mut req = http.get(NVD_URL);
    if let Some(k) = api_key {
        req = req.header("apiKey", k);
    }

    let res = req.send().await.map_err(|e| format!("fetch failed: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("NVD {}", res.status().as_u16()));
    }
    let body: NvdResponse = res.json().await.map_err(|e| format!("fetch failed: {e}"))?;

    let mut items: Vec<NvdItem> = body
        .vulnerabilities
        .into_iter()
        .map(|w| {
            let cve = w.cve;
            // Prefer an English description, else the first available.
            let summary = cve
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .or_else(|| cve.descriptions.first())
                .map(|d| d.value.clone())
                .unwrap_or_default();
            // Prefer CVSS v3.1, fall back to v3.0 — first metric of each.
            let metric = cve.metrics.as_ref().and_then(|m| {
                m.v31.first().or_else(|| m.v30.first())
            });
            NvdItem {
                id: cve.id,
                published: cve.published,
                summary,
                cvss: metric.map(|m| m.cvss_data.base_score),
                severity: metric.map(|m| m.cvss_data.base_severity.clone()),
            }
        })
        .collect();

    // Newest first (string compare on ISO timestamps), then cap at 20.
    items.sort_by(|a, b| b.published.cmp(&a.published));
    items.truncate(20);

    Ok((body.total_results, items))
}
