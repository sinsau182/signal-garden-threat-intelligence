import { createFileRoute } from "@tanstack/react-router";
import { DataTable, PageHeader, Panel, Tag } from "@/components/vsoc/ui";

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

const members = [["Animesh Singh", "admin"], ["R. Mehta", "analyst"], ["K. Iyer", "analyst"], ["Auditor", "viewer"]];
const audit = [["10:42", "R. Mehta", "Set VEX not_affected on CVE-2016-5195"], ["09:15", "A. Singh", "Opened PSIRT case PS-7"], ["08:01", "system", "KEV feed sync: +3 entries"]];

function SettingsPage() {
  return (
    <>
      <PageHeader eyebrow="Workspace" title="Settings" />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Members & roles"><DataTable head={["Name", "Role"]}>{members.map(([n, r]) => <tr key={n}><td>{n}</td><td><Tag tone={r === "admin" ? "primary" : "intel"}>{r}</Tag></td></tr>)}</DataTable></Panel>
        <Panel title="Audit log"><DataTable head={["Time", "Who", "Action"]}>{audit.map(([t, w, a]) => <tr key={t}><td className="font-mono text-xs">{t}</td><td className="text-xs">{w}</td><td className="text-sm">{a}</td></tr>)}</DataTable></Panel>
      </div>
      <p className="mt-4 text-xs text-muted-foreground">Sign-in, MFA and real member management arrive with account setup.</p>
    </>
  );
}
