import { createServerFn } from "@tanstack/react-start";

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
