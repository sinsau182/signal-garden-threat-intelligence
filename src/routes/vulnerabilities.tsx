import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from "recharts";
import { band, findings, products, riskScore } from "@/lib/data";
import { DataTable, PageHeader, Panel, SevBadge, Stat, Tag } from "@/components/vsoc/ui";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";

export const Route = createFileRoute("/vulnerabilities")({
  head: () => ({
    meta: [
      { title: "Vulnerabilities — vSOC" },
      { name: "description", content: "Findings ranked by explainable risk score combining CVSS, EPSS, KEV, exposure and actor links." },
      { property: "og:title", content: "Vulnerabilities — vSOC" },
      { property: "og:description", content: "Explainable risk-ranked vulnerability findings and remediation plan." },
    ],
  }),
  component: Vulns,
});

const lifecycle = ["Open", "Triage", "In remediation", "Not affected (VEX)", "Fixed"];

function Vulns() {
  const [kevOnly, setKevOnly] = useState(false);
  const [sel, setSel] = useState<string | null>("CVE-2021-44228p-ivi-700");
  const rows = useMemo(() => findings.map((f) => ({ ...f, score: riskScore(f) })).filter((f) => !kevOnly || f.kev).sort((a, b) => b.score - a.score), [kevOnly]);
  const selected = rows.find((r) => r.cve + r.product === sel) ?? rows[0];
  const byFix = Object.values(rows.reduce<Record<string, { comp: string; fix: string; cves: string[]; score: number }>>((m, r) => {
    const k = r.component; m[k] ??= { comp: k, fix: r.fix, cves: [], score: 0 }; m[k].cves.push(r.cve); m[k].score += r.score; return m;
  }, {})).sort((a, b) => b.score - a.score);
  return (
    <>
      <PageHeader eyebrow="Exposure" title="Vulnerabilities" desc="Each finding is a component × CVE × release, scored by our explainable risk engine."
        right={<label className="flex items-center gap-2 text-sm"><Switch checked={kevOnly} onCheckedChange={setKevOnly} /> Known exploited only</label>} />
      <div className="mb-4 grid grid-cols-2 gap-2 md:grid-cols-5">
        {lifecycle.map((s) => <Stat key={s} label={s} value={findings.filter((f) => f.status === s).length} tone={s === "Open" ? "critical" : s === "Fixed" ? "ok" : "intel"} />)}
      </div>
      <Tabs defaultValue="cve">
        <TabsList><TabsTrigger value="cve">By CVE</TabsTrigger><TabsTrigger value="fix">By fix (remediation)</TabsTrigger><TabsTrigger value="matrix">EPSS × CVSS</TabsTrigger></TabsList>
        <TabsContent value="cve" className="mt-4 grid gap-4 lg:grid-cols-3">
          <Panel className="lg:col-span-2" title={`${rows.length} findings`}>
            <DataTable head={["Score", "CVE", "Component", "Product", "Signals", "Status"]}>
              {rows.map((f) => (
                <tr key={f.cve + f.product} onClick={() => setSel(f.cve + f.product)} className={"cursor-pointer " + (sel === f.cve + f.product ? "bg-muted/60" : "")}>
                  <td><SevBadge sev={band(f.score)}>{f.score}</SevBadge></td>
                  <td className="font-mono text-xs text-primary">{f.cve}</td>
                  <td className="font-mono text-xs">{f.component}</td>
                  <td className="text-xs">{f.product}</td>
                  <td className="space-x-1">{f.kev && <Tag tone="critical">KEV</Tag>}{f.actor && <Tag tone="intel">actor</Tag>}</td>
                  <td className="text-xs text-muted-foreground">{f.status}</td>
                </tr>
              ))}
            </DataTable>
          </Panel>
          {selected && (
            <Panel title="How this score was reached">
              <div className="font-mono text-xs text-primary">{selected.cve}</div>
              <div className="mt-1 font-display text-4xl font-semibold">{selected.score}<span className="text-base text-muted-foreground">/100</span></div>
              <ul className="mt-4 space-y-2 text-sm">
                {[["CVSS base", selected.cvss.toFixed(1)], ["× (1 + EPSS)", (1 + selected.epss).toFixed(2)], ["× KEV boost", selected.kev ? "1.5" : "1.0"],
                  ["× Exposure", selected.exposure.toFixed(1)], ["× Actor link", selected.actor ? "1.3" : "1.0"], ["× Reachability", selected.reach.toFixed(1)]].map(([k, v]) => (
                  <li key={k} className="flex justify-between border-b pb-1"><span className="text-muted-foreground">{k}</span><span className="font-mono">{v}</span></li>
                ))}
              </ul>
              <div className="mt-4 text-sm"><span className="label-caps">Fix</span><div>Upgrade <span className="font-mono">{selected.component}</span> {selected.version} → <span className="font-mono text-ok">{selected.fix}</span></div></div>
              <div className="mt-3 text-sm"><span className="label-caps">Affects</span><div>{products.find((p) => p.id === selected.product)?.name}</div></div>
            </Panel>
          )}
        </TabsContent>
        <TabsContent value="fix" className="mt-4">
          <Panel title="Remediation plan · one upgrade clears many CVEs">
            <DataTable head={["Component", "Upgrade to", "CVEs cleared", "Risk removed"]}>
              {byFix.map((b) => (
                <tr key={b.comp}><td className="font-mono text-xs">{b.comp}</td><td className="font-mono text-xs text-ok">{b.fix}</td>
                  <td className="space-x-1">{b.cves.map((c) => <Tag key={c}>{c}</Tag>)}</td><td className="font-mono text-xs text-primary">−{b.score}</td></tr>
              ))}
            </DataTable>
          </Panel>
        </TabsContent>
        <TabsContent value="matrix" className="mt-4">
          <Panel title="Exploit likelihood vs severity · bubble = risk score">
            <div className="h-80">
              <ResponsiveContainer>
                <ScatterChart>
                  <CartesianGrid stroke="var(--border)" />
                  <XAxis type="number" dataKey="cvss" name="CVSS" domain={[0, 10]} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                  <YAxis type="number" dataKey="epss" name="EPSS" domain={[0, 1]} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                  <ZAxis dataKey="score" range={[60, 500]} />
                  <Tooltip contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", fontSize: 12 }} />
                  <Scatter data={rows} fill="var(--critical)" fillOpacity={0.6} />
                </ScatterChart>
              </ResponsiveContainer>
            </div>
          </Panel>
        </TabsContent>
      </Tabs>
    </>
  );
}
