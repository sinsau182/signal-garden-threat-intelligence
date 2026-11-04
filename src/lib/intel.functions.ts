import { createServerFn } from "@tanstack/react-start";
import { sources, type FeedSource } from "@/lib/data";

export type KevItem = {
  cveID: string; vendorProject: string; product: string; vulnerabilityName: string;
  dateAdded: string; dueDate: string; knownRansomwareCampaignUse: string; shortDescription: string;
  epss?: number; percentile?: number;
};

/** Live: CISA KEV (latest additions) enriched with FIRST EPSS. Public data only. */
export const getLiveIntel = createServerFn({ method: "GET" }).handler(async () => {
  const fetchedAt = new Date().toISOString();
  try {
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
      headers: { "user-agent": "vsoc-intel/1.0" },
    });
    if (!res.ok) throw new Error(`KEV ${res.status}`);
    const json = (await res.json()) as { catalogVersion: string; count: number; vulnerabilities: KevItem[] };
    const latest = [...json.vulnerabilities].sort((a, b) => b.dateAdded.localeCompare(a.dateAdded)).slice(0, 40);
    let epssOk = false;
    try {
      const e = await fetch(`https://api.first.org/data/v1/epss?cve=${latest.map((v) => v.cveID).join(",")}`);
      if (e.ok) {
        const ej = (await e.json()) as { data: { cve: string; epss: string; percentile: string }[] };
        const m = new Map(ej.data.map((d) => [d.cve, d]));
        for (const v of latest) {
          const d = m.get(v.cveID);
          if (d) { v.epss = Number(d.epss); v.percentile = Number(d.percentile); }
        }
        epssOk = true;
      }
    } catch { /* EPSS optional */ }
    const byMonth = new Map<string, number>();
    for (const v of json.vulnerabilities) {
      const k = v.dateAdded.slice(0, 7);
      byMonth.set(k, (byMonth.get(k) ?? 0) + 1);
    }
    const monthly = [...byMonth.entries()].sort().slice(-12).map(([month, count]) => ({ month, count }));
    const vendors = new Map<string, number>();
    for (const v of json.vulnerabilities) vendors.set(v.vendorProject, (vendors.get(v.vendorProject) ?? 0) + 1);
    const topVendors = [...vendors.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([vendor, count]) => ({ vendor, count }));
    const ransomware = json.vulnerabilities.filter((v) => v.knownRansomwareCampaignUse === "Known").length;
    return { ok: true as const, fetchedAt, catalogVersion: json.catalogVersion, total: json.count, ransomware, latest, monthly, topVendors, epssOk };
  } catch (err) {
    return { ok: false as const, fetchedAt, error: err instanceof Error ? err.message : "fetch failed" };
  }
});

export type NvdItem = { id: string; published: string; summary: string; cvss: number | null; severity: string | null };

/** Live: NVD API 2.0 — most recently published CVEs. Keyless (rate-limited); set NVD_API_KEY to raise limits. */
export const getNvdRecent = createServerFn({ method: "GET" }).handler(async () => {
  const fetchedAt = new Date().toISOString();
  try {
    const headers: Record<string, string> = { "user-agent": "vsoc-intel/1.0" };
    const key = process.env["NVD_API_KEY"];
    if (key) headers["apiKey"] = key;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15_000);
    const res = await fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&startIndex=0", { headers, signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`NVD ${res.status}`);
    const json = (await res.json()) as {
      totalResults: number;
      vulnerabilities: { cve: { id: string; published: string; descriptions: { lang: string; value: string }[]; metrics?: { cvssMetricV31?: { cvssData: { baseScore: number; baseSeverity: string } }[]; cvssMetricV30?: { cvssData: { baseScore: number; baseSeverity: string } }[] } } }[];
    };
    const items: NvdItem[] = json.vulnerabilities.map(({ cve }) => {
      const m = cve.metrics?.cvssMetricV31?.[0] ?? cve.metrics?.cvssMetricV30?.[0];
      return {
        id: cve.id,
        published: cve.published,
        summary: cve.descriptions.find((d) => d.lang === "en")?.value ?? cve.descriptions[0]?.value ?? "",
        cvss: m ? m.cvssData.baseScore : null,
        severity: m ? m.cvssData.baseSeverity : null,
      };
    });
    items.sort((a, b) => b.published.localeCompare(a.published));
    return { ok: true as const, fetchedAt, total: json.totalResults, items: items.slice(0, 20), keyed: Boolean(key) };
  } catch (err) {
    return { ok: false as const, fetchedAt, error: err instanceof Error ? err.message : "fetch failed" };
  }
});

export type FeedStatus = FeedSource & { status: "live" | "unreachable" | "key-required" | "planned"; ms: number | null };

/** Probe one URL with a short timeout; returns reachability + latency. */
async function probe(url: string, init?: RequestInit): Promise<{ ok: boolean; ms: number }> {
  const started = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 7_000);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal, headers: { "user-agent": "vsoc-intel/1.0", ...(init?.headers ?? {}) } });
    return { ok: res.ok, ms: Date.now() - started };
  } catch {
    return { ok: false, ms: Date.now() - started };
  } finally {
    clearTimeout(timer);
  }
}

/** Live: real reachability status for the feed catalog. Keyless feeds are probed now; keyed/heavy feeds are reported by access level. */
export const getFeedStatus = createServerFn({ method: "GET" }).handler(async () => {
  const fetchedAt = new Date().toISOString();
  // Keyless, Worker-safe feeds we probe live. Match by catalog source name.
  const probes: Record<string, () => Promise<{ ok: boolean; ms: number }>> = {
    "CISA KEV": () => probe("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { method: "HEAD" }),
    "FIRST EPSS": () => probe("https://api.first.org/data/v1/epss?limit=1"),
    "OSV.dev": () => probe("https://api.osv.dev/v1/query", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ package: { name: "left-pad", ecosystem: "npm" }, version: "0.0.1" }) }),
    "NVD API 2.0": () => probe("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"),
  };
  const probeNames = Object.keys(probes);
  const results = await Promise.all(probeNames.map((n) => probes[n]!()));
  const liveMap = new Map(probeNames.map((n, i) => [n, results[i]!]));

  const feeds: FeedStatus[] = sources.map((s) => {
    const r = liveMap.get(s.name);
    if (r) return { ...s, status: r.ok ? "live" : "unreachable", ms: r.ms };
    if (s.access === "Free key" || s.access === "Paid key" || s.access === "Membership") return { ...s, status: "key-required", ms: null };
    return { ...s, status: "planned", ms: null };
  });
  return { fetchedAt, feeds, liveCount: feeds.filter((f) => f.status === "live").length, total: feeds.length };
});

/** Live: OSV.dev lookup for a package/version. */
export const queryOsv = createServerFn({ method: "POST" })
  .inputValidator((i: { name: string; version: string; ecosystem: string }) => ({
    name: String(i.name).slice(0, 200), version: String(i.version).slice(0, 50), ecosystem: String(i.ecosystem).slice(0, 30),
  }))
  .handler(async ({ data }) => {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ package: { name: data.name, ecosystem: data.ecosystem }, version: data.version }),
    });
    if (!res.ok) return { vulns: [] as { id: string; summary?: string; aliases?: string[] }[], error: `OSV ${res.status}` };
    const j = (await res.json()) as { vulns?: { id: string; summary?: string; aliases?: string[] }[] };
    return { vulns: (j.vulns ?? []).slice(0, 30).map((v) => ({ id: v.id, summary: v.summary, aliases: v.aliases })), error: null };
  });
