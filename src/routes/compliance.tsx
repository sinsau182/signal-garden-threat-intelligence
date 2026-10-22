import { createFileRoute } from "@tanstack/react-router";
import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer } from "recharts";
import { craReadiness, products } from "@/lib/data";
import { Bar, DataTable, PageHeader, Panel, Tag } from "@/components/vsoc/ui";

export const Route = createFileRoute("/compliance")({
  head: () => ({
    meta: [
      { title: "Compliance — vSOC" },
      { name: "description", content: "EU CRA, UNECE R155/R156, ISO/SAE 21434 and IEC 62443 readiness with evidence linking." },
      { property: "og:title", content: "Compliance — vSOC" },
      { property: "og:description", content: "Regulatory readiness backed by live evidence." },
    ],
  }),
  component: Compliance,
});

const timeline = [
  ["Dec 2024", "CRA enters into force", true],
  ["Jun 2026", "Conformity assessment bodies notified", true],
  ["Sep 2026", "Article 14 reporting obligations apply", true],
  ["Dec 2027", "Full CRA application · CE marking required", false],
] as const;

const frameworks = [
  ["EU Cyber Resilience Act", 68], ["UNECE R155 (CSMS)", 74], ["UNECE R156 (SUMS)", 61], ["ISO/SAE 21434", 70], ["IEC 62443-4-1", 52],
] as const;

const annex = [
  ["I.1(a) No known exploitable vulns at release", "Partial", "Vulnerabilities · KEV gate"],
  ["I.1(c) Secure by default configuration", "Met", "Products · controls"],
  ["I.2(1) Identify & document components (SBOM)", "Met", "SBOM per release"],
  ["I.2(2) Address vulns without delay", "Partial", "Remediation SLA"],
  ["I.2(4) Publicly disclose fixed vulns", "Gap", "PSIRT · advisories"],
  ["I.2(5) Coordinated disclosure policy", "Met", "Trust portal"],
  ["I.2(8) Security updates distributed securely", "Partial", "Releases"],
];

function Compliance() {
  return (
    <>
      <PageHeader eyebrow="Regulation" title="Compliance" desc="Evidence auto-links from findings, SBOMs and PSIRT cases — no manual spreadsheets." />
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="CRA readiness radar">
          <div className="h-64"><ResponsiveContainer><RadarChart data={craReadiness}><PolarGrid stroke="var(--border)" /><PolarAngleAxis dataKey="area" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} /><Radar dataKey="score" stroke="var(--primary)" fill="var(--primary)" fillOpacity={0.3} /></RadarChart></ResponsiveContainer></div>
        </Panel>
        <Panel title="Frameworks">
          <div className="space-y-3">{frameworks.map(([n, v]) => <div key={n} className="text-sm"><div className="flex justify-between"><span>{n}</span><span className="font-mono text-xs">{v}%</span></div><Bar value={v} tone={v < 60 ? "critical" : "ok"} /></div>)}</div>
        </Panel>
        <Panel title="CRA timeline">
          <ol className="relative ml-2 border-l">
            {timeline.map(([d, t, done]) => (
              <li key={d} className="mb-4 ml-4"><span className={"absolute -left-1.5 mt-1 h-3 w-3 rounded-full " + (done ? "bg-ok" : "bg-primary")} />
                <div className="font-mono text-xs text-muted-foreground">{d}</div><div className="text-sm">{t}</div></li>
            ))}
          </ol>
        </Panel>
      </div>
      <Panel title="Annex I · essential requirements matrix" className="mt-4">
        <DataTable head={["Requirement", "Status", "Evidence source"]}>
          {annex.map(([r, s, e]) => <tr key={r}><td>{r}</td><td><Tag tone={s === "Met" ? "ok" : s === "Gap" ? "critical" : "primary"}>{s}</Tag></td><td className="text-xs text-muted-foreground">{e}</td></tr>)}
        </DataTable>
      </Panel>
      <Panel title="Per-product readiness" className="mt-4">
        <div className="grid gap-3 md:grid-cols-4">{products.map((p) => <div key={p.id} className="rounded border p-3 text-sm">{p.name}<div className="mt-2 font-display text-2xl text-primary">{p.cra}%</div><Bar value={p.cra} tone="ok" /></div>)}</div>
      </Panel>
    </>
  );
}
