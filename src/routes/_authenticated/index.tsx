import { createFileRoute, Link } from "@tanstack/react-router";
import { Area, AreaChart, CartesianGrid, PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { band, cases, craReadiness, findings, products, riskScore, riskTrend, suppliers } from "@/lib/data";
import { Bar, DataTable, PageHeader, Panel, SevBadge, Stat, Tag } from "@/components/vsoc/ui";

export const Route = createFileRoute("/_authenticated/")({
  head: () => ({
    meta: [
      { title: "vSOC — Product Security Operations Center" },
      { name: "description", content: "Command view of product risk, live threat pulse, fleet exposure, PSIRT and EU CRA readiness." },
      { property: "og:title", content: "vSOC — Product Security Operations Center" },
      { property: "og:description", content: "Threat-intel driven product security operations in one command view." },
    ],
  }),
  component: Home,
});

const tip = { contentStyle: { background: "var(--popover)", border: "1px solid var(--border)", fontSize: 12 } };

function Home() {
  const ranked = [...findings].map((f) => ({ ...f, score: riskScore(f) })).sort((a, b) => b.score - a.score);
  const openCases = cases.filter((c) => c.stage !== "Closed");
  return (
    <>
      <PageHeader eyebrow="Command view" title="Product Security Operations Center" desc="Everything below is ranked by the threat-intel risk engine." />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Stat label="Open findings" value={products.reduce((s, p) => s + p.open, 0)} hint="across 4 products" />
        <Stat label="Known exploited" value={findings.filter((f) => f.kev).length} hint="KEV matches" tone="critical" />
        <Stat label="SLA breached" value={findings.filter((f) => f.sla < 0).length} hint="past due date" tone="critical" />
        <Stat label="Active PSIRT cases" value={openCases.length} tone="intel" />
        <Stat label="MTTR (critical)" value="6.2d" hint="▼ 1.4d vs last month" tone="ok" />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="Risk trend · 14 days" className="lg:col-span-2">
          <div className="h-60">
            <ResponsiveContainer>
              <AreaChart data={riskTrend}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <Tooltip {...tip} />
                <Area dataKey="high" stackId="1" stroke="var(--high)" fill="var(--high)" fillOpacity={0.15} />
                <Area dataKey="critical" stackId="1" stroke="var(--critical)" fill="var(--critical)" fillOpacity={0.3} />
                <Area dataKey="kev" stroke="var(--intel)" fill="none" strokeDasharray="4 3" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="EU CRA · readiness">
          <div className="h-60">
            <ResponsiveContainer>
              <RadarChart data={craReadiness}>
                <PolarGrid stroke="var(--border)" />
                <PolarAngleAxis dataKey="area" tick={{ fontSize: 9, fill: "var(--muted-foreground)" }} />
                <Radar dataKey="score" stroke="var(--primary)" fill="var(--primary)" fillOpacity={0.3} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <Panel title="Next actions · ranked by risk engine" className="mt-4" action={<Link to="/vulnerabilities" className="text-xs text-primary">All findings →</Link>}>
        <DataTable head={["Score", "CVE", "Component", "Product", "Why", "Fix", "SLA"]}>
          {ranked.slice(0, 6).map((f) => (
            <tr key={f.cve + f.product}>
              <td><SevBadge sev={band(f.score)}>{f.score}</SevBadge></td>
              <td className="font-mono text-xs text-primary">{f.cve}</td>
              <td className="font-mono text-xs">{f.component}@{f.version}</td>
              <td className="text-xs">{products.find((p) => p.id === f.product)?.name}</td>
              <td className="space-x-1">{f.kev && <Tag tone="critical">KEV</Tag>}{f.actor && <Tag tone="intel">actor</Tag>}<Tag>EPSS {(f.epss * 100).toFixed(0)}%</Tag></td>
              <td className="font-mono text-xs text-ok">{f.fix}</td>
              <td className={f.sla < 0 ? "font-mono text-xs text-critical" : "font-mono text-xs"}>{f.sla < 0 ? `${-f.sla}d over` : `${f.sla}d`}</td>
            </tr>
          ))}
        </DataTable>
      </Panel>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Panel title="Fleet map · product risk">
          <div className="space-y-3">
            {products.map((p) => (
              <Link key={p.id} to="/products/$id" params={{ id: p.id }} className="block">
                <div className="flex justify-between text-sm"><span>{p.name}</span><span className="font-mono text-xs text-muted-foreground">{p.open} open · {p.kev} KEV · risk {p.risk}</span></div>
                <div className="mt-1"><Bar value={p.risk} tone={p.risk > 75 ? "critical" : "primary"} /></div>
              </Link>
            ))}
          </div>
        </Panel>
        <Panel title="Supply chain · suppliers needing attention">
          <DataTable head={["Supplier", "Open CVEs", "KEV", "Reachable", "Score"]}>
            {[...suppliers].sort((a, b) => a.score - b.score).slice(0, 5).map((s) => (
              <tr key={s.name}>
                <td>{s.name}</td><td className="font-mono text-xs">{s.open}</td><td className="font-mono text-xs">{s.kev}</td>
                <td>{s.reachable ? <Tag tone="ok">yes</Tag> : <Tag tone="critical">no</Tag>}</td>
                <td className="font-mono text-xs">{s.score}</td>
              </tr>
            ))}
          </DataTable>
        </Panel>
      </div>
    </>
  );
}
