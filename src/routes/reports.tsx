import { createFileRoute } from "@tanstack/react-router";
import { toast } from "sonner";
import { findings, riskScore } from "@/lib/data";
import { PageHeader, Panel, Tag } from "@/components/vsoc/ui";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports — vSOC" },
      { name: "description", content: "Executive summaries, findings exports and scheduled compliance reports." },
      { property: "og:title", content: "Reports — vSOC" },
      { property: "og:description", content: "Export and schedule security reports." },
    ],
  }),
  component: Reports,
});

function exportCsv() {
  const rows = [["cve", "component", "version", "product", "risk_score", "kev", "status"], ...findings.map((f) => [f.cve, f.component, f.version, f.product, String(riskScore(f)), String(f.kev), f.status])];
  const blob = new Blob([rows.map((r) => r.join(",")).join("\n")], { type: "text/csv" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "vsoc-findings.csv"; a.click();
}

const reports = [
  ["Executive one-pager", "Risk trend, top 5 actions, CRA readiness", "Weekly · Mon 08:00"],
  ["Findings register", "All findings with risk score and status", "On demand"],
  ["CRA technical documentation", "Annex VII bundle with evidence", "Monthly"],
  ["Supplier scorecard", "Supplier risk and SBOM coverage", "Monthly"],
];

function Reports() {
  return (
    <>
      <PageHeader eyebrow="Output" title="Reports" />
      <div className="grid gap-4 md:grid-cols-2">
        {reports.map(([t, d, s], i) => (
          <Panel key={t}>
            <h3 className="font-semibold">{t}</h3><p className="mt-1 text-sm text-muted-foreground">{d}</p>
            <div className="mt-4 flex items-center justify-between"><Tag tone="intel">{s}</Tag>
              <Button size="sm" onClick={() => (i === 1 ? exportCsv() : toast.info("Scheduled export will be available once accounts are set up"))}>{i === 1 ? "Download CSV" : "Generate"}</Button></div>
          </Panel>
        ))}
      </div>
    </>
  );
}
