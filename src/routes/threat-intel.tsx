import { createFileRoute } from "@tanstack/react-router";
import { queryOptions, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Area, AreaChart, Bar as RBar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getLiveIntel, queryOsv } from "@/lib/intel.functions";
import { actors, findings, products, sources, tactics } from "@/lib/data";
import { DataTable, PageHeader, Panel, Stat, Tag } from "@/components/vsoc/ui";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const liveQuery = queryOptions({ queryKey: ["live-intel"], queryFn: () => getLiveIntel(), staleTime: 10 * 60_000 });

export const Route = createFileRoute("/threat-intel")({
  head: () => ({
    meta: [
      { title: "Threat intelligence — vSOC" },
      { name: "description", content: "Live CISA KEV and EPSS intelligence, threat actors, ATT&CK heatmap, threat graph and feed catalog." },
      { property: "og:title", content: "Threat intelligence — vSOC" },
      { property: "og:description", content: "The heart of the vSOC: live exploited-vulnerability intel correlated to your products." },
    ],
  }),
  component: ThreatIntel,
});

const tip = { contentStyle: { background: "var(--popover)", border: "1px solid var(--border)", fontSize: 12 } };

function ThreatIntel() {
  const { data, isLoading } = useQuery(liveQuery);
  const ourCves = new Set(findings.map((f) => f.cve));
  return (
    <>
      <PageHeader
        eyebrow="Core engine"
        title="Threat intelligence"
        desc="Ingest → normalize → enrich → correlate → score. Live public feeds matched against your SBOMs."
        right={<div className="flex items-center gap-2 text-xs text-muted-foreground"><span className="pulse-dot h-2 w-2 rounded-full bg-ok" />{data?.ok ? `KEV ${data.catalogVersion} · fetched ${new Date(data.fetchedAt).toLocaleTimeString()}` : isLoading ? "Fetching live feeds…" : "Live feed unavailable"}</div>}
      />
      <Pipeline />
      <Tabs defaultValue="landscape" className="mt-6">
        <TabsList className="flex-wrap">
          {["landscape", "actors", "attack", "graph", "watchlists", "sources"].map((t) => (
            <TabsTrigger key={t} value={t} className="capitalize">{t === "attack" ? "ATT&CK heatmap" : t}</TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="landscape" className="mt-4 space-y-4">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="KEV catalog" value={data?.ok ? data.total.toLocaleString() : "—"} hint="Known exploited CVEs (CISA)" tone="critical" />
            <Stat label="Ransomware-linked" value={data?.ok ? data.ransomware : "—"} hint="Known campaign use" tone="critical" />
            <Stat label="Matched to you" value={findings.filter((f) => f.kev).length} hint="KEV CVEs in your SBOMs" tone="primary" />
            <Stat label="Actors tracking you" value={actors.filter((a) => a.sector).length} hint="Target your sector" tone="intel" />
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="KEV additions · last 12 months (live)">
              <div className="h-56">
                {data?.ok && (
                  <ResponsiveContainer>
                    <AreaChart data={data.monthly}>
                      <CartesianGrid stroke="var(--border)" vertical={false} />
                      <XAxis dataKey="month" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                      <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                      <Tooltip {...tip} />
                      <Area dataKey="count" stroke="var(--critical)" fill="var(--critical)" fillOpacity={0.2} />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </div>
            </Panel>
            <Panel title="Most-exploited vendors (live)">
              <div className="h-56">
                {data?.ok && (
                  <ResponsiveContainer>
                    <BarChart data={data.topVendors} layout="vertical">
                      <XAxis type="number" hide />
                      <YAxis type="category" dataKey="vendor" width={90} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                      <Tooltip {...tip} />
                      <RBar dataKey="count" fill="var(--intel)" radius={[0, 3, 3, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </Panel>
          </div>
          <Panel title="Newest known-exploited vulnerabilities · KEV + EPSS">
            {!data ? <p className="text-sm text-muted-foreground">Loading live feed…</p> : !data.ok ? <p className="text-sm text-critical">Feed error: {data.error}</p> : (
              <DataTable head={["CVE", "Vendor / product", "Why it matters", "EPSS", "Added", "Due", "You"]}>
                {data.latest.map((v) => (
                  <tr key={v.cveID}>
                    <td className="font-mono text-xs text-primary"><a href={`https://nvd.nist.gov/vuln/detail/${v.cveID}`} target="_blank" rel="noreferrer">{v.cveID}</a></td>
                    <td className="text-xs">{v.vendorProject}<div className="text-muted-foreground">{v.product}</div></td>
                    <td className="max-w-md text-xs text-muted-foreground">{v.vulnerabilityName}{v.knownRansomwareCampaignUse === "Known" && <> <Tag tone="critical">ransomware</Tag></>}</td>
                    <td className="font-mono text-xs">{v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : "—"}</td>
                    <td className="font-mono text-xs">{v.dateAdded}</td>
                    <td className="font-mono text-xs">{v.dueDate}</td>
                    <td>{ourCves.has(v.cveID) ? <Tag tone="critical">affected</Tag> : <Tag>clear</Tag>}</td>
                  </tr>
                ))}
              </DataTable>
            )}
          </Panel>
        </TabsContent>

        <TabsContent value="actors" className="mt-4">
          <Panel title="Threat actors">
            <DataTable head={["Actor", "Origin", "Motivation", "Targets your sector", "Your CVEs linked", "Techniques"]}>
              {actors.map((a) => (
                <tr key={a.name}>
                  <td className="font-medium">{a.name}</td>
                  <td className="font-mono text-xs">{a.origin}</td>
                  <td className="text-xs text-muted-foreground">{a.motivation}</td>
                  <td>{a.sector ? <Tag tone="critical">yes</Tag> : <Tag>no</Tag>}</td>
                  <td className="space-x-1">{a.cves.length ? a.cves.map((c) => <Tag key={c} tone="primary">{c}</Tag>) : <span className="text-xs text-muted-foreground">none</span>}</td>
                  <td className="space-x-1">{a.techniques.map((t) => <Tag key={t} tone="intel">{t}</Tag>)}</td>
                </tr>
              ))}
            </DataTable>
          </Panel>
        </TabsContent>

        <TabsContent value="attack" className="mt-4">
          <Panel title="MITRE ATT&CK · techniques observed against your component stack">
            <div className="grid gap-3 md:grid-cols-3 lg:grid-cols-6">
              {tactics.map((t) => (
                <div key={t.id}>
                  <div className="label-caps mb-2">{t.name}</div>
                  <div className="space-y-1.5">
                    {t.techs.map(([id, name, heat]) => (
                      <div key={id} className="rounded border p-2 text-xs" style={{ background: `color-mix(in oklab, var(--critical) ${heat * 9}%, transparent)` }}>
                        <div className="font-mono text-[10px] text-muted-foreground">{id}</div>
                        {name}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <p className="mt-3 text-xs text-muted-foreground">Heat = number of tracked actors × exploited CVEs in your SBOMs using the technique.</p>
          </Panel>
        </TabsContent>

        <TabsContent value="graph" className="mt-4"><Panel title="Threat graph · actor → CVE → component → product"><ThreatGraph /></Panel></TabsContent>

        <TabsContent value="watchlists" className="mt-4 space-y-4"><Watchlist /></TabsContent>

        <TabsContent value="sources" className="mt-4">
          <Panel title={`Feed catalog · ${sources.length} sources`}>
            <DataTable head={["Source", "Category", "Data", "Access", "Cadence", "Status"]}>
              {sources.map((s) => (
                <tr key={s.name}>
                  <td><a href={s.url} target="_blank" rel="noreferrer" className="font-medium hover:text-primary">{s.name}</a></td>
                  <td className="text-xs text-muted-foreground">{s.category}</td>
                  <td className="text-xs">{s.data}</td>
                  <td><Tag tone={s.access === "Free" ? "ok" : s.access === "Free key" ? "intel" : "primary"}>{s.access}</Tag></td>
                  <td className="font-mono text-xs">{s.cadence}</td>
                  <td>{s.live ? <Tag tone="ok">● live</Tag> : <Tag>planned</Tag>}</td>
                </tr>
              ))}
            </DataTable>
          </Panel>
        </TabsContent>
      </Tabs>
    </>
  );
}

function Pipeline() {
  const steps = [
    ["Fetch", "23 feed adapters"], ["Normalize", "CVE JSON / STIX 2.1"], ["Enrich", "EPSS · KEV · ATT&CK · CWE"],
    ["Correlate", "purl / CPE vs SBOMs"], ["Score", "explainable 0–100"], ["Act", "alerts · PSIRT · VEX"],
  ];
  return (
    <div className="panel grid grid-cols-2 gap-2 p-3 md:grid-cols-6">
      {steps.map(([a, b], i) => (
        <div key={a} className="relative rounded border border-intel/30 bg-intel/5 p-3">
          <div className="font-mono text-[10px] text-intel">0{i + 1}</div>
          <div className="font-display font-semibold">{a}</div>
          <div className="text-[11px] text-muted-foreground">{b}</div>
          {i < steps.length - 1 && <span className="absolute -right-2 top-1/2 hidden -translate-y-1/2 text-intel md:block">›</span>}
        </div>
      ))}
    </div>
  );
}

function ThreatGraph() {
  const linked = actors.filter((a) => a.cves.length);
  const cves = [...new Set(linked.flatMap((a) => a.cves))];
  const comps = [...new Set(findings.filter((f) => cves.includes(f.cve)).map((f) => f.component))];
  const prods = [...new Set(findings.filter((f) => cves.includes(f.cve)).map((f) => f.product))];
  const W = 900, H = 340;
  const col = (items: string[], x: number) => items.map((id, i) => ({ id, x, y: ((i + 1) * H) / (items.length + 1) }));
  const A = col(linked.map((a) => a.name), 90), C = col(cves, 330), K = col(comps, 570), P = col(prods, 810);
  const pos = new Map([...A, ...C, ...K, ...P].map((n) => [n.id, n]));
  const edges: [string, string][] = [];
  linked.forEach((a) => a.cves.forEach((c) => edges.push([a.name, c])));
  findings.filter((f) => cves.includes(f.cve)).forEach((f) => { edges.push([f.cve, f.component]); edges.push([f.component, f.product]); });
  const uniq = [...new Set(edges.map((e) => e.join("|")))].map((e) => e.split("|") as [string, string]);
  const node = (n: { id: string; x: number; y: number }, color: string, label = n.id) => (
    <g key={n.id + color}>
      <circle cx={n.x} cy={n.y} r={7} fill={color} />
      <text x={n.x} y={n.y - 12} textAnchor="middle" fontSize={11} fill="var(--foreground)" fontFamily="var(--font-mono)">{label}</text>
    </g>
  );
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="min-w-[700px]">
        {["Actors", "Exploited CVEs", "Components", "Products"].map((t, i) => (
          <text key={t} x={90 + i * 240} y={16} textAnchor="middle" fontSize={10} fill="var(--muted-foreground)" letterSpacing="2">{t.toUpperCase()}</text>
        ))}
        {uniq.map(([a, b]) => { const p = pos.get(a)!, q = pos.get(b)!; const mx = (p.x + q.x) / 2; return <path key={a + b} d={`M${p.x},${p.y} C${mx},${p.y} ${mx},${q.y} ${q.x},${q.y}`} stroke="var(--intel)" strokeOpacity={0.4} fill="none" />; })}
        {A.map((n) => node(n, "var(--critical)"))}
        {C.map((n) => node(n, "var(--primary)"))}
        {K.map((n) => node(n, "var(--intel)"))}
        {P.map((n) => node(n, "var(--ok)", products.find((p) => p.id === n.id)?.name.split(" ")[0]))}
      </svg>
    </div>
  );
}

function Watchlist() {
  const run = useServerFn(queryOsv);
  const [name, setName] = useState("org.apache.logging.log4j:log4j-core");
  const [version, setVersion] = useState("2.14.1");
  const [eco, setEco] = useState("Maven");
  const [res, setRes] = useState<Awaited<ReturnType<typeof run>> | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <>
      <Panel title="Watched components">
        <div className="flex flex-wrap gap-2">
          {[...new Set(findings.map((f) => `${f.component}@${f.version}`))].map((c) => <Tag key={c} tone="intel">{c}</Tag>)}
        </div>
      </Panel>
      <Panel title="Live OSV.dev lookup · check any package version">
        <form className="flex flex-wrap gap-2" onSubmit={async (e) => { e.preventDefault(); setBusy(true); setRes(await run({ data: { name, version, ecosystem: eco } })); setBusy(false); }}>
          <Input className="w-80" value={name} onChange={(e) => setName(e.target.value)} placeholder="package name" />
          <Input className="w-28" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="version" />
          <select value={eco} onChange={(e) => setEco(e.target.value)} className="rounded border bg-background px-2 text-sm">
            {["Maven", "npm", "PyPI", "Go", "crates.io", "Debian", "Alpine", "NuGet"].map((x) => <option key={x}>{x}</option>)}
          </select>
          <Button type="submit" disabled={busy}>{busy ? "Checking…" : "Check"}</Button>
        </form>
        {res && (
          <div className="mt-4">
            <div className="label-caps mb-2">{res.vulns.length} vulnerabilities found</div>
            <ul className="space-y-1 text-sm">
              {res.vulns.map((v) => <li key={v.id}><span className="font-mono text-xs text-primary">{v.id}</span> {v.aliases?.filter((a) => a.startsWith("CVE")).map((a) => <Tag key={a}>{a}</Tag>)} <span className="text-muted-foreground">{v.summary}</span></li>)}
            </ul>
          </div>
        )}
      </Panel>
    </>
  );
}
