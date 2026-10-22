// Server-only feed adapters. Each adapter fetches a public source and upserts into `cves`.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";

type Admin = SupabaseClient<Database>;
type KevItem = {
  cveID: string; vendorProject: string; product: string; vulnerabilityName: string;
  dateAdded: string; dueDate: string; knownRansomwareCampaignUse: string; shortDescription: string; cwes?: string[];
};

async function run(admin: Admin, sourceId: string, fn: () => Promise<{ itemsIn: number; itemsNew: number }>) {
  const { data: runRow } = await admin.from("feed_runs").insert({ source_id: sourceId }).select("id").single();
  try {
    const r = await fn();
    await admin.from("feed_runs").update({ finished_at: new Date().toISOString(), items_in: r.itemsIn, items_new: r.itemsNew, status: "ok" }).eq("id", runRow!.id);
    return { source: sourceId, ok: true, ...r };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await admin.from("feed_runs").update({ finished_at: new Date().toISOString(), status: "error", error: msg.slice(0, 500) }).eq("id", runRow!.id);
    return { source: sourceId, ok: false, error: msg };
  }
}

export async function syncKev(admin: Admin) {
  return run(admin, "kev", async () => {
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { headers: { "user-agent": "vsoc-intel/1.0" } });
    if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
    const j = (await res.json()) as { vulnerabilities: KevItem[] };
    const { count: before } = await admin.from("cves").select("id", { count: "exact", head: true }).eq("kev", true);
    const rows = j.vulnerabilities.map((v) => ({
      id: v.cveID, vendor: v.vendorProject, product: v.product, title: v.vulnerabilityName, description: v.shortDescription,
      cwe: v.cwes?.[0] ?? null, kev: true, kev_added: v.dateAdded, kev_due: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === "Known", updated_at: new Date().toISOString(),
    }));
    for (let i = 0; i < rows.length; i += 500) {
      const { error } = await admin.from("cves").upsert(rows.slice(i, i + 500), { onConflict: "id" });
      if (error) throw new Error(error.message);
    }
    return { itemsIn: rows.length, itemsNew: Math.max(0, rows.length - (before ?? 0)) };
  });
}

/** Enrich KEV CVEs with EPSS in batches of 100 (FIRST API limit-friendly). */
export async function syncEpss(admin: Admin) {
  return run(admin, "epss", async () => {
    const { data: ids, error } = await admin.from("cves").select("id").eq("kev", true).limit(5000);
    if (error) throw new Error(error.message);
    let updated = 0;
    const all = (ids ?? []).map((r) => r.id);
    for (let i = 0; i < all.length; i += 100) {
      const batch = all.slice(i, i + 100);
      const r = await fetch(`https://api.first.org/data/v1/epss?cve=${batch.join(",")}&limit=100`);
      if (!r.ok) continue;
      const j = (await r.json()) as { data: { cve: string; epss: string; percentile: string }[] };
      const rows = j.data.map((d) => ({ id: d.cve, epss: Number(d.epss), epss_pct: Number(d.percentile), updated_at: new Date().toISOString() }));
      if (rows.length) {
        const { error: e2 } = await admin.from("cves").upsert(rows, { onConflict: "id" });
        if (e2) throw new Error(e2.message);
        updated += rows.length;
      }
    }
    return { itemsIn: all.length, itemsNew: updated };
  });
}
