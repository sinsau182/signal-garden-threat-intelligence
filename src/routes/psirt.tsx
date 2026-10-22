import { createFileRoute } from "@tanstack/react-router";
import { cases } from "@/lib/data";
import { DataTable, PageHeader, Panel, SevBadge, Stat, Tag } from "@/components/vsoc/ui";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export const Route = createFileRoute("/psirt")({
  head: () => ({
    meta: [
      { title: "PSIRT — vSOC" },
      { name: "description", content: "Product security incident response: triage board, cases, advisories, playbooks and CRA Article 14 clocks." },
      { property: "og:title", content: "PSIRT — vSOC" },
      { property: "og:description", content: "Incident response with CRA Article 14 countdowns." },
    ],
  }),
  component: Psirt,
});

const stages = ["Intake", "Triage", "Investigate", "Coordinate", "Advisory", "Closed"];
const playbooks = [
  ["Actively exploited (KEV)", "critical", "Notify ENISA ≤24h, early warning, mitigation advice"],
  ["Researcher disclosure", "high", "Acknowledge ≤72h, reproduce, CVD timeline 90d"],
  ["Supplier component vuln", "high", "Request VEX from supplier, assess reachability"],
  ["Backdoor / supply-chain compromise", "critical", "Freeze builds, rebuild from clean source, rotate keys"],
];

function Psirt() {
  return (
    <>
      <PageHeader eyebrow="Response" title="Product Security Incident Response" desc="Cases flow from intake to advisory with EU CRA Article 14 reporting clocks." />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Open cases" value={cases.filter((c) => c.stage !== "Closed").length} tone="intel" />
        <Stat label="Art. 14 clocks running" value={cases.filter((c) => c.art14 > 0).length} tone="critical" />
        <Stat label="Advisories published" value="12" tone="ok" />
        <Stat label="Median time to triage" value="4.1h" />
      </div>
      <Tabs defaultValue="board" className="mt-4">
        <TabsList><TabsTrigger value="board">Triage board</TabsTrigger><TabsTrigger value="cases">Cases</TabsTrigger><TabsTrigger value="playbooks">Playbooks</TabsTrigger><TabsTrigger value="flow">Lifecycle</TabsTrigger></TabsList>
        <TabsContent value="board" className="mt-4">
          <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-6">
            {stages.map((s) => (
              <div key={s} className="panel p-2">
                <div className="label-caps mb-2 px-1">{s} · {cases.filter((c) => c.stage === s).length}</div>
                <div className="space-y-2">
                  {cases.filter((c) => c.stage === s).map((c) => (
                    <div key={c.id} className="rounded border bg-card p-2 text-xs">
                      <div className="flex justify-between"><span className="font-mono text-muted-foreground">{c.id}</span><SevBadge sev={c.sev} /></div>
                      <div className="mt-1">{c.title}</div>
                      <div className="mt-2 flex justify-between text-muted-foreground"><span>{c.owner}</span>{c.art14 > 0 && <span className={c.art14 < 24 ? "text-critical" : "text-high"}>⏱ {c.art14}h</span>}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </TabsContent>
        <TabsContent value="cases" className="mt-4">
          <Panel>
            <DataTable head={["Case", "Title", "Product", "CVE", "Severity", "Stage", "Owner", "Art. 14"]}>
              {cases.map((c) => (
                <tr key={c.id}><td className="font-mono text-xs">{c.id}</td><td>{c.title}</td><td className="text-xs">{c.product}</td><td className="font-mono text-xs text-primary">{c.cve}</td>
                  <td><SevBadge sev={c.sev} /></td><td><Tag tone="intel">{c.stage}</Tag></td><td className="text-xs">{c.owner}</td><td className="font-mono text-xs">{c.art14 ? `${c.art14}h left` : "—"}</td></tr>
              ))}
            </DataTable>
          </Panel>
        </TabsContent>
        <TabsContent value="playbooks" className="mt-4">
          <Panel>
            <DataTable head={["Playbook", "From severity", "Key steps"]}>
              {playbooks.map(([a, b, c]) => <tr key={a}><td className="font-medium">{a}</td><td><SevBadge sev={b as "critical" | "high"} /></td><td className="text-sm text-muted-foreground">{c}</td></tr>)}
            </DataTable>
          </Panel>
        </TabsContent>
        <TabsContent value="flow" className="mt-4">
          <Panel title="Case lifecycle with CRA reporting gates">
            <div className="flex flex-wrap items-center gap-2">
              {["Report intake", "Triage", "Investigate", "Coordinate supplier", "Advisory (CSAF)", "ENISA notification", "Close + lessons"].map((s, i, a) => (
                <div key={s} className="flex items-center gap-2"><div className="rounded border border-intel/30 bg-intel/5 px-3 py-2 text-sm">{s}</div>{i < a.length - 1 && <span className="text-intel">→</span>}</div>
              ))}
            </div>
            <div className="mt-4 grid gap-2 md:grid-cols-3 text-sm">
              <div className="rounded border border-critical/40 p-3"><div className="label-caps">≤ 24h</div>Early warning to ENISA / CSIRT</div>
              <div className="rounded border border-high/40 p-3"><div className="label-caps">≤ 72h</div>Vulnerability notification</div>
              <div className="rounded border border-medium/40 p-3"><div className="label-caps">≤ 14 days</div>Final report after fix available</div>
            </div>
          </Panel>
        </TabsContent>
      </Tabs>
    </>
  );
}
