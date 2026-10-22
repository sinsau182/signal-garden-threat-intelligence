import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

/** Feed health for the Sources tab: latest run per source. */
export const getFeedHealth = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase } = context;
    const [{ data: sources }, { data: runs }, { count: cveCount }] = await Promise.all([
      supabase.from("intel_sources").select("*").order("name"),
      supabase.from("feed_runs").select("*").order("started_at", { ascending: false }).limit(100),
      supabase.from("cves").select("id", { count: "exact", head: true }),
    ]);
    const latest = new Map<string, NonNullable<typeof runs>[number]>();
    for (const r of runs ?? []) if (!latest.has(r.source_id)) latest.set(r.source_id, r);
    return {
      cveCount: cveCount ?? 0,
      sources: (sources ?? []).map((s) => ({ ...s, lastRun: latest.get(s.id) ?? null })),
      runs: (runs ?? []).slice(0, 30),
    };
  });

/** Admin-only: trigger a feed sync now. */
export const runFeedsNow = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data: isAdmin } = await context.supabase.rpc("has_role", { _user_id: context.userId, _role: "admin" });
    if (!isAdmin) throw new Error("Only admins can run feeds");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { syncKev, syncEpss } = await import("@/lib/feeds.server");
    const kev = await syncKev(supabaseAdmin);
    const epss = await syncEpss(supabaseAdmin);
    await context.supabase.from("audit_log").insert({ actor: context.userId, action: "feed.run", entity: "intel_sources", diff: { kev, epss } });
    return { kev, epss };
  });

/** Members, roles and recent audit entries. */
export const getWorkspace = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const [{ data: profiles }, { data: roles }, { data: audit }] = await Promise.all([
      supabase.from("profiles").select("id, display_name, created_at"),
      supabase.from("user_roles").select("user_id, role"),
      supabase.from("audit_log").select("*").order("at", { ascending: false }).limit(20),
    ]);
    const myRoles = (roles ?? []).filter((r) => r.user_id === userId).map((r) => r.role);
    return {
      me: userId,
      isAdmin: myRoles.includes("admin"),
      members: (profiles ?? []).map((p) => ({ ...p, roles: (roles ?? []).filter((r) => r.user_id === p.id).map((r) => r.role) })),
      audit: audit ?? [],
    };
  });
