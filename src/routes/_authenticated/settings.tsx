import { createFileRoute } from "@tanstack/react-router";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { getWorkspace, getFeedHealth, runFeedsNow } from "@/lib/vsoc.functions";
import { DataTable, PageHeader, Panel, Tag } from "@/components/vsoc/ui";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/_authenticated/settings")({
  head: () => ({
    meta: [
      { title: "Settings — vSOC" },
      { name: "description", content: "Members, roles, MFA, audit log and public trust portal." },
      { property: "og:title", content: "Settings — vSOC" },
      { property: "og:description", content: "Workspace settings for your vSOC." },
    ],
  }),
  component: SettingsPage,
});

const workspaceQuery = queryOptions({ queryKey: ["workspace"], queryFn: () => getWorkspace(), staleTime: 60_000 });
const feedHealthQuery = queryOptions({ queryKey: ["feed-health"], queryFn: () => getFeedHealth(), staleTime: 60_000 });

function SettingsPage() {
  const qc = useQueryClient();
  const ws = useQuery(workspaceQuery);
  const health = useQuery(feedHealthQuery);
  const runNow = useServerFn(runFeedsNow);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function sync() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await runNow();
      const kev = "itemsIn" in r.kev ? `+${r.kev.itemsNew} new / ${r.kev.itemsIn} in` : `error: ${"error" in r.kev ? r.kev.error : "failed"}`;
      const epss = "itemsIn" in r.epss ? `${r.epss.itemsNew} enriched` : `error: ${"error" in r.epss ? r.epss.error : "failed"}`;
      setMsg(`Synced — KEV ${kev}; EPSS ${epss}.`);
      await Promise.all([qc.invalidateQueries({ queryKey: ["feed-health"] }), qc.invalidateQueries({ queryKey: ["workspace"] })]);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Sync failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Workspace"
        title="Settings"
        desc="Members, roles and feed health from Lovable Cloud."
        right={health.data ? <div className="flex items-center gap-1.5 text-xs text-muted-foreground"><span className="pulse-dot h-2 w-2 rounded-full bg-ok" />{health.data.cveCount.toLocaleString()} CVEs stored</div> : null}
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Members & roles">
          {ws.isError ? <p className="text-sm text-muted-foreground">Sign in to load workspace members.</p>
            : !ws.data ? <p className="text-sm text-muted-foreground">Loading…</p>
            : ws.data.members.length === 0 ? <p className="text-sm text-muted-foreground">No members yet — the first account to sign up becomes admin.</p>
            : (
              <DataTable head={["Name", "Roles"]}>
                {ws.data.members.map((m) => (
                  <tr key={m.id}>
                    <td>{m.display_name ?? m.id.slice(0, 8)}{m.id === ws.data!.me && <span className="ml-1 text-xs text-muted-foreground">(you)</span>}</td>
                    <td className="space-x-1">{m.roles.length ? m.roles.map((r) => <Tag key={r} tone={r === "admin" ? "primary" : "intel"}>{r}</Tag>) : <Tag>none</Tag>}</td>
                  </tr>
                ))}
              </DataTable>
            )}
        </Panel>

        <Panel title="Audit log">
          {ws.isError ? <p className="text-sm text-muted-foreground">Sign in to load the audit log.</p>
            : !ws.data ? <p className="text-sm text-muted-foreground">Loading…</p>
            : ws.data.audit.length === 0 ? <p className="text-sm text-muted-foreground">No audit entries yet.</p>
            : (
              <DataTable head={["Time", "Action", "Entity"]}>
                {ws.data.audit.map((a) => (
                  <tr key={a.id}>
                    <td className="font-mono text-xs">{new Date(a.at).toLocaleString()}</td>
                    <td className="text-sm">{a.action}</td>
                    <td className="text-xs text-muted-foreground">{a.entity}{a.entity_id ? ` · ${a.entity_id}` : ""}</td>
                  </tr>
                ))}
              </DataTable>
            )}
        </Panel>
      </div>

      <Panel
        title="Feed health · Lovable Cloud ingestion"
        className="mt-4"
        action={ws.data?.isAdmin ? <Button size="sm" disabled={busy} onClick={sync}>{busy ? "Syncing…" : "Run feeds now"}</Button> : null}
      >
        {msg && <p className="mb-3 text-xs text-muted-foreground">{msg}</p>}
        {health.isError ? <p className="text-sm text-muted-foreground">Sign in to load feed health.</p>
          : !health.data ? <p className="text-sm text-muted-foreground">Loading…</p>
          : (
            <DataTable head={["Source", "Category", "Cadence", "Last run", "Result", "Status"]}>
              {health.data.sources.map((s) => (
                <tr key={s.id}>
                  <td className="font-medium">{s.name}</td>
                  <td className="text-xs text-muted-foreground">{s.category}</td>
                  <td className="font-mono text-xs">{s.cadence}</td>
                  <td className="font-mono text-xs">{s.lastRun ? new Date(s.lastRun.started_at).toLocaleString() : "—"}</td>
                  <td className="font-mono text-xs">{s.lastRun ? `+${s.lastRun.items_new} / ${s.lastRun.items_in}` : "—"}</td>
                  <td>{!s.lastRun ? <Tag>never run</Tag> : s.lastRun.status === "ok" ? <Tag tone="ok">ok</Tag> : s.lastRun.status === "error" ? <Tag tone="critical">error</Tag> : <Tag tone="intel">{s.lastRun.status}</Tag>}</td>
                </tr>
              ))}
            </DataTable>
          )}
      </Panel>
      {!ws.data?.isAdmin && <p className="mt-3 text-xs text-muted-foreground">Feed sync requires an admin role and the <code>SUPABASE_SERVICE_ROLE_KEY</code> server env var. Scheduled ingestion runs via <code>/api/public/cron/feeds</code>.</p>}
    </>
  );
}
