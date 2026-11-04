//! Port of `getFeedStatus` from `src/lib/intel.functions.ts`.
//!
//! Live: real reachability for the feed catalog. The four keyless, probe-safe
//! feeds are checked now with a short timeout; keyed/heavy feeds are reported by
//! access level (`key-required`), and everything else as `planned`. The catalog
//! itself mirrors `sources` in `src/lib/data.ts`.

use axum::{extract::State, Json};
use serde::Serialize;
use serde_json::{json, Value};

use crate::AppState;

/// Per-probe timeout, matching the 7s `AbortController` in the TS version.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(7);

/// A feed catalog entry (mirrors `FeedSource`). `live` is emitted only when set,
/// like the optional TS field.
#[derive(Debug, Clone, Serialize)]
struct FeedSource {
    name: &'static str,
    category: &'static str,
    data: &'static str,
    access: &'static str, // "Free" | "Free key" | "Paid key" | "Membership"
    cadence: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    live: Option<bool>,
    url: &'static str,
}

/// Catalog of 23 sources — kept in sync with `src/lib/data.ts`.
const SOURCES: &[FeedSource] = &[
    FeedSource { name: "CISA KEV", category: "Vulnerability", data: "Known exploited CVEs", access: "Free", cadence: "6h", live: Some(true), url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
    FeedSource { name: "FIRST EPSS", category: "Vulnerability", data: "Exploit probability", access: "Free", cadence: "24h", live: Some(true), url: "https://www.first.org/epss/" },
    FeedSource { name: "NVD API 2.0", category: "Vulnerability", data: "CVE, CVSS, CPE, CWE", access: "Free key", cadence: "2h", live: Some(true), url: "https://nvd.nist.gov/developers" },
    FeedSource { name: "OSV.dev", category: "Vulnerability", data: "Open-source package vulns", access: "Free", cadence: "1h", live: Some(true), url: "https://osv.dev" },
    FeedSource { name: "GitHub Advisory DB", category: "Vulnerability", data: "GHSA package advisories", access: "Free key", cadence: "1h", live: None, url: "https://github.com/advisories" },
    FeedSource { name: "MITRE cvelistV5", category: "Vulnerability", data: "Authoritative CVE records", access: "Free", cadence: "1h", live: None, url: "https://github.com/CVEProject/cvelistV5" },
    FeedSource { name: "Exploit-DB", category: "Vulnerability", data: "Public exploits", access: "Free", cadence: "24h", live: None, url: "https://www.exploit-db.com" },
    FeedSource { name: "VulnCheck KEV", category: "Vulnerability", data: "Extended KEV", access: "Free key", cadence: "6h", live: None, url: "https://vulncheck.com" },
    FeedSource { name: "Distro trackers", category: "Vulnerability", data: "Debian/Ubuntu/RHEL/Alpine fix status", access: "Free", cadence: "12h", live: None, url: "https://security-tracker.debian.org" },
    FeedSource { name: "CISA ICS advisories", category: "Advisories", data: "ICS / OT advisories", access: "Free", cadence: "6h", live: None, url: "https://www.cisa.gov/news-events/cybersecurity-advisories" },
    FeedSource { name: "ENISA EUVD", category: "Advisories", data: "EU vulnerability database", access: "Free", cadence: "6h", live: None, url: "https://euvd.enisa.europa.eu" },
    FeedSource { name: "BSI CERT-Bund / CERT/CC", category: "Advisories", data: "National CERT advisories", access: "Free", cadence: "12h", live: None, url: "https://wid.cert-bund.de" },
    FeedSource { name: "Vendor CSAF feeds", category: "Advisories", data: "Siemens, Bosch, Cisco, Red Hat CSAF 2.0", access: "Free", cadence: "6h", live: None, url: "https://csaf.io" },
    FeedSource { name: "Auto-ISAC", category: "Advisories", data: "Automotive threat sharing", access: "Membership", cadence: "24h", live: None, url: "https://automotiveisac.com" },
    FeedSource { name: "MITRE ATT&CK STIX", category: "Actors & TTPs", data: "Actors, techniques, software", access: "Free", cadence: "weekly", live: None, url: "https://attack.mitre.org" },
    FeedSource { name: "AlienVault OTX", category: "Actors & TTPs", data: "Pulses, IOCs", access: "Free key", cadence: "1h", live: None, url: "https://otx.alienvault.com" },
    FeedSource { name: "abuse.ch", category: "IOCs", data: "URLhaus, MalwareBazaar, ThreatFox, Feodo", access: "Free", cadence: "15m", live: None, url: "https://abuse.ch" },
    FeedSource { name: "MISP / CIRCL feeds", category: "IOCs", data: "Shared community IOCs", access: "Free", cadence: "1h", live: None, url: "https://www.circl.lu/doc/misp/feed-osint/" },
    FeedSource { name: "GreyNoise Community", category: "IOCs", data: "Scanning IPs & CVE exploitation", access: "Free key", cadence: "1h", live: None, url: "https://www.greynoise.io" },
    FeedSource { name: "Shodan / Censys", category: "Exposure", data: "Internet-exposed devices", access: "Paid key", cadence: "24h", live: None, url: "https://www.shodan.io" },
    FeedSource { name: "VirusTotal", category: "IOCs", data: "File/URL reputation", access: "Free key", cadence: "on demand", live: None, url: "https://www.virustotal.com" },
    FeedSource { name: "Security news RSS", category: "Early signals", data: "BleepingComputer, The Record, SecurityWeek", access: "Free", cadence: "15m", live: None, url: "https://www.bleepingcomputer.com/feed/" },
    FeedSource { name: "GitHub PoC watch", category: "Early signals", data: "New exploit repos per CVE", access: "Free key", cadence: "1h", live: None, url: "https://github.com/search" },
];

/// Result of a live reachability probe.
#[derive(Clone, Copy)]
struct Probe {
    ok: bool,
    ms: u128,
}

/// `GET /api/intel/feed-status`
pub async fn status(State(state): State<AppState>) -> Json<Value> {
    let fetched_at = crate::intel::now_iso8601();

    // Probe the four keyless, worker-safe feeds concurrently.
    let (kev, epss, osv, nvd) = tokio::join!(
        probe_head(&state.http, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
        probe_get(&state.http, "https://api.first.org/data/v1/epss?limit=1"),
        probe_osv(&state.http),
        probe_get(&state.http, "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"),
    );

    // Map probe results back onto catalog names.
    let live_for = |name: &str| -> Option<Probe> {
        match name {
            "CISA KEV" => Some(kev),
            "FIRST EPSS" => Some(epss),
            "OSV.dev" => Some(osv),
            "NVD API 2.0" => Some(nvd),
            _ => None,
        }
    };

    let feeds: Vec<Value> = SOURCES
        .iter()
        .map(|s| {
            let (status, ms) = match live_for(s.name) {
                Some(p) => (if p.ok { "live" } else { "unreachable" }, Some(p.ms)),
                None => {
                    let st = match s.access {
                        "Free key" | "Paid key" | "Membership" => "key-required",
                        _ => "planned",
                    };
                    (st, None)
                }
            };
            // Spread the source fields, then add status + ms (mirrors `...s`).
            let mut v = serde_json::to_value(s).unwrap_or_else(|_| json!({}));
            if let Value::Object(map) = &mut v {
                map.insert("status".into(), json!(status));
                map.insert("ms".into(), json!(ms));
            }
            v
        })
        .collect();

    let live_count = feeds
        .iter()
        .filter(|f| f.get("status").and_then(Value::as_str) == Some("live"))
        .count();

    Json(json!({
        "fetchedAt": fetched_at,
        "feeds": feeds,
        "liveCount": live_count,
        "total": feeds.len(),
    }))
}

/// A GET probe: reachable + latency, with a short timeout.
async fn probe_get(http: &reqwest::Client, url: &str) -> Probe {
    run_probe(http.get(url)).await
}

/// A HEAD probe (used for the large KEV JSON file).
async fn probe_head(http: &reqwest::Client, url: &str) -> Probe {
    run_probe(http.head(url)).await
}

/// The OSV probe posts a tiny real query body, like the TS version.
async fn probe_osv(http: &reqwest::Client) -> Probe {
    let req = http
        .post("https://api.osv.dev/v1/query")
        .json(&json!({ "package": { "name": "left-pad", "ecosystem": "npm" }, "version": "0.0.1" }));
    run_probe(req).await
}

/// Execute a probe request, timing it and treating any error/timeout as "not ok".
async fn run_probe(req: reqwest::RequestBuilder) -> Probe {
    let started = std::time::Instant::now();
    let fut = req.timeout(PROBE_TIMEOUT).send();
    let ok = matches!(fut.await, Ok(res) if res.status().is_success());
    Probe {
        ok,
        ms: started.elapsed().as_millis(),
    }
}
