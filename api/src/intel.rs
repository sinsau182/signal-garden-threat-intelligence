//! Port of `getLiveIntel` from `src/lib/intel.functions.ts`.
//!
//! Live: CISA KEV (latest additions) enriched with FIRST EPSS. Public data only.
//! The JSON shape mirrors the TanStack server fn so the frontend contract is
//! unchanged (camelCase fields; `latest` items keep the raw KEV field names).

use std::collections::HashMap;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// One KEV catalog entry. Field names match the CISA feed and are re-serialized
/// as-is (the frontend reads `cveID`, `vendorProject`, …), plus optional EPSS.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KevItem {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vendorProject")]
    pub vendor_project: String,
    pub product: String,
    #[serde(rename = "vulnerabilityName")]
    pub vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "dueDate")]
    pub due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse")]
    pub known_ransomware_campaign_use: String,
    #[serde(rename = "shortDescription")]
    pub short_description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentile: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct KevCatalog {
    #[serde(rename = "catalogVersion")]
    catalog_version: String,
    count: u64,
    vulnerabilities: Vec<KevItem>,
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    data: Vec<EpssRow>,
}

#[derive(Debug, Deserialize)]
struct EpssRow {
    cve: String,
    epss: String,
    percentile: String,
}

#[derive(Debug, Serialize)]
struct MonthCount {
    month: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct VendorCount {
    vendor: String,
    count: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntelOk {
    ok: bool,
    fetched_at: String,
    catalog_version: String,
    total: u64,
    ransomware: usize,
    latest: Vec<KevItem>,
    monthly: Vec<MonthCount>,
    top_vendors: Vec<VendorCount>,
    epss_ok: bool,
}

/// `GET /api/intel/live`
pub async fn live(State(state): State<AppState>) -> Json<Value> {
    let fetched_at = now_iso8601();
    match build_intel(&state.http, &fetched_at).await {
        Ok(ok) => Json(serde_json::to_value(ok).unwrap_or_else(|_| {
            json!({ "ok": false, "fetchedAt": fetched_at, "error": "serialize failed" })
        })),
        Err(err) => Json(json!({
            "ok": false,
            "fetchedAt": fetched_at,
            "error": err,
        })),
    }
}

async fn build_intel(http: &reqwest::Client, fetched_at: &str) -> Result<IntelOk, String> {
    let res = http
        .get(KEV_URL)
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("KEV {}", res.status().as_u16()));
    }
    let catalog: KevCatalog = res
        .json()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;

    // Latest 40 additions, newest first (string compare on YYYY-MM-DD).
    let mut latest: Vec<KevItem> = catalog.vulnerabilities.clone();
    latest.sort_by(|a, b| b.date_added.cmp(&a.date_added));
    latest.truncate(40);

    // EPSS enrichment is optional — any failure leaves scores unset.
    let epss_ok = enrich_epss(http, &mut latest).await;

    // Aggregates over the whole catalog.
    let mut by_month: HashMap<String, u64> = HashMap::new();
    for v in &catalog.vulnerabilities {
        let key: String = v.date_added.chars().take(7).collect(); // YYYY-MM
        *by_month.entry(key).or_insert(0) += 1;
    }
    let mut monthly: Vec<MonthCount> = by_month
        .into_iter()
        .map(|(month, count)| MonthCount { month, count })
        .collect();
    monthly.sort_by(|a, b| a.month.cmp(&b.month));
    if monthly.len() > 12 {
        monthly = monthly.split_off(monthly.len() - 12);
    }

    let mut vendors: HashMap<String, u64> = HashMap::new();
    for v in &catalog.vulnerabilities {
        *vendors.entry(v.vendor_project.clone()).or_insert(0) += 1;
    }
    let mut top_vendors: Vec<VendorCount> = vendors
        .into_iter()
        .map(|(vendor, count)| VendorCount { vendor, count })
        .collect();
    top_vendors.sort_by(|a, b| b.count.cmp(&a.count));
    top_vendors.truncate(8);

    let ransomware = catalog
        .vulnerabilities
        .iter()
        .filter(|v| v.known_ransomware_campaign_use == "Known")
        .count();

    Ok(IntelOk {
        ok: true,
        fetched_at: fetched_at.to_string(),
        catalog_version: catalog.catalog_version,
        total: catalog.count,
        ransomware,
        latest,
        monthly,
        top_vendors,
        epss_ok,
    })
}

/// Fetch EPSS scores for the given CVEs and merge them in. Returns whether the
/// lookup succeeded (mirrors `epssOk` in the TS version).
async fn enrich_epss(http: &reqwest::Client, latest: &mut [KevItem]) -> bool {
    if latest.is_empty() {
        return false;
    }
    let cves = latest
        .iter()
        .map(|v| v.cve_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let url = format!("https://api.first.org/data/v1/epss?cve={cves}");

    let Ok(res) = http.get(&url).send().await else {
        return false;
    };
    if !res.status().is_success() {
        return false;
    }
    let Ok(body) = res.json::<EpssResponse>().await else {
        return false;
    };

    let map: HashMap<&str, &EpssRow> = body.data.iter().map(|d| (d.cve.as_str(), d)).collect();
    for v in latest.iter_mut() {
        if let Some(d) = map.get(v.cve_id.as_str()) {
            v.epss = d.epss.parse().ok();
            v.percentile = d.percentile.parse().ok();
        }
    }
    true
}

/// ISO-8601 UTC timestamp with milliseconds, e.g. `2026-11-03T12:34:56.000Z`,
/// matching JS `new Date().toISOString()`. Computed without extra crates.
pub(crate) fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = dur.as_millis();
    let secs = (millis / 1000) as i64;
    let ms = (millis % 1000) as u32;

    // Civil date from Unix days (Howard Hinnant's algorithm).
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{ms:03}Z",
        y = y,
        m = m,
        d = d,
        hour = hour,
        min = min,
        sec = sec,
        ms = ms,
    )
}
