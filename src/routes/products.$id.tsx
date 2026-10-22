import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { band, findings, products, riskScore } from "@/lib/data";
import { DataTable, PageHeader, Panel, SevBadge, Stat, Tag } from "@/components/vsoc/ui";

export const Route = createFileRoute("/products/$id")({
  loader: ({ params }) => {
    const p = products.find((x) => x.id === params.id);
    if (!p) throw notFound();
    return p;
  },
  head: ({ loaderData }) => ({
    meta: [
      { title: `${loaderData?.name ?? "Product"} — vSOC` },
      { name: "description", content: `Risk, SBOM, attack path and findings for ${loaderData?.name ?? "this product"}.` },
      { property: "og:title", content: `${loaderData?.name ?? "Product"} — vSOC` },
      { property: "og:description", content: "Per-product security posture." },
    ],
  }),
  component: Product,
});

const releases = [
  { v: "current", added: 6, removed: 2, newCves: 3 },
  { v: "previous", added: 11, removed: 4, newCves: 7 },
  { v: "older", added: 4, removed: 9, newCves: 1 },
];

function Product() {
  const p = Route.useLoaderData();
  const fs = findings.filter((f) => f.product === p.id).map((f) => ({ ...f, score: riskScore(f) })).sort((a, b) => b.score - a.score);
  return (
    <>
      <Link to="/products" className="text-xs text-muted-foreground hover:text-primary">← Products</Link>
      <PageHeader eyebrow={`${p.type} · firmware ${p.firmware}`} title={p.name} />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Risk" value={p.risk} tone={p.risk > 75 ? "critical" : "primary"} />
        <Stat label="Components" value={p.components} tone="intel" />
        <Stat label="Open findings" value={p.open} tone="critical" />
        <Stat label="CRA readiness" value={`${p.cra}%`} tone="ok" />
      </div>
      <Panel title="Attack path · how an attacker reaches this product" className="mt-4"><AttackPath /></Panel>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="Findings" className="lg:col-span-2">
          <DataTable head={["Score", "CVE", "Component", "Fix", "Status"]}>
            {fs.map((f) => (
              <tr key={f.cve}><td><SevBadge sev={band(f.score)}>{f.score}</SevBadge></td><td className="font-mono text-xs text-primary">{f.cve}</td>
                <td className="font-mono text-xs">{f.component}@{f.version}</td><td className="font-mono text-xs text-ok">{f.fix}</td><td className="text-xs text-muted-foreground">{f.status}</td></tr>
            ))}
          </DataTable>
        </Panel>
        <Panel title="Release-to-release SBOM diff">
          <ul className="space-y-3 text-sm">
            {releases.map((r) => (
              <li key={r.v} className="border-b pb-2"><div className="font-mono text-xs">{r.v}</div>
                <div className="mt-1 space-x-1"><Tag tone="ok">+{r.added} comps</Tag><Tag>−{r.removed}</Tag><Tag tone="critical">{r.newCves} new CVEs</Tag></div></li>
            ))}
          </ul>
        </Panel>
      </div>
    </>
  );
}

function AttackPath() {
  const steps = [
    ["Internet / cellular", "entry"], ["Telematics API", "exposed svc"], ["log4j-core 2.14", "CVE-2021-44228"],
    ["App processor", "code exec"], ["CAN gateway", "lateral"], ["Vehicle bus", "impact"],
  ];
  return (
    <div className="flex flex-wrap items-center gap-2">
      {steps.map(([a, b], i) => (
        <div key={a} className="flex items-center gap-2">
          <div className={"rounded border px-3 py-2 " + (i === 2 ? "border-critical/60 bg-critical/10" : "border-intel/30 bg-intel/5")}>
            <div className="text-sm">{a}</div><div className="font-mono text-[10px] text-muted-foreground">{b}</div>
          </div>
          {i < steps.length - 1 && <span className="text-intel">→</span>}
        </div>
      ))}
    </div>
  );
}
