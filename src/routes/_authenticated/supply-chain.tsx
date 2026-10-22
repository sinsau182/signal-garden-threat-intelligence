import { createFileRoute } from "@tanstack/react-router";
import { findings, products, suppliers } from "@/lib/data";
import { Bar, DataTable, PageHeader, Panel, Stat, Tag } from "@/components/vsoc/ui";

export const Route = createFileRoute("/_authenticated/supply-chain")({
  head: () => ({
    meta: [
      { title: "Supply chain — vSOC" },
      { name: "description", content: "Supplier risk scorecards, dependency graph and SBOM exchange." },
      { property: "og:title", content: "Supply chain — vSOC" },
      { property: "og:description", content: "Know which suppliers carry your risk." },
    ],
  }),
  component: Supply,
});

function Supply() {
  return (
    <>
      <PageHeader eyebrow="Third parties" title="Supply chain" desc="Supplier scorecards combine open CVEs, KEV exposure, reachability and response time." />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Suppliers" value={suppliers.length} tone="intel" />
        <Stat label="Need attention" value={suppliers.filter((s) => s.score < 65).length} tone="critical" />
        <Stat label="Unreachable" value={suppliers.filter((s) => !s.reachable).length} tone="critical" />
        <Stat label="Supplier SBOMs" value="14" tone="ok" />
      </div>
      <Panel title="Dependency graph · supplier → component → product" className="mt-4"><DepGraph /></Panel>
      <Panel title="Supplier scorecards" className="mt-4">
        <DataTable head={["Supplier", "Products", "Components", "Open CVEs", "KEV", "Reachable", "Score"]}>
          {[...suppliers].sort((a, b) => a.score - b.score).map((s) => (
            <tr key={s.name}><td className="font-medium">{s.name}</td><td className="font-mono text-xs">{s.products}</td><td className="font-mono text-xs">{s.components}</td>
              <td className="font-mono text-xs">{s.open}</td><td className="font-mono text-xs">{s.kev}</td><td>{s.reachable ? <Tag tone="ok">yes</Tag> : <Tag tone="critical">no</Tag>}</td>
              <td className="w-40"><div className="font-mono text-xs">{s.score}</div><Bar value={s.score} tone={s.score < 60 ? "critical" : "ok"} /></td></tr>
          ))}
        </DataTable>
      </Panel>
    </>
  );
}

const SUP: Record<string, string> = { "log4j-core": "Apache", openssl: "OpenSSL Project", glibc: "GNU", "linux-kernel": "Linux Foundation", "xz-utils": "Tukaani (xz)", libwebp: "Google", curl: "curl", busybox: "BusyBox" };

const compSupplier = (c: string) => SUP[c] ?? "Other";

function DepGraph() {
  const comps = [...new Set(findings.map((f) => f.component))];
  const sups = [...new Set(comps.map(compSupplier))];
  const W = 900, H = 380;
  const lay = (a: string[], x: number) => new Map(a.map((id, i) => [id, { x, y: ((i + 1) * H) / (a.length + 1) }]));
  const S = lay(sups, 120), C = lay(comps, 450), P = lay(products.map((p) => p.id), 780);
  const edges = new Set<string>();
  findings.forEach((f) => { edges.add(`S:${compSupplier(f.component)}|C:${f.component}`); edges.add(`C:${f.component}|P:${f.product}`); });
  const get = (k: string) => { const [t, id] = [k[0], k.slice(2)]; return (t === "S" ? S : t === "C" ? C : P).get(id)!; };
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="min-w-[700px]">
        {[...edges].map((e) => { const [a, b] = e.split("|").map(get) as [{ x: number; y: number }, { x: number; y: number }]; const mx = (a.x + b.x) / 2; return <path key={e} d={`M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`} stroke="var(--primary)" strokeOpacity={0.35} fill="none" />; })}
        {[...S].map(([id, p]) => <g key={id}><rect x={p.x - 70} y={p.y - 12} width={140} height={24} rx={4} fill="var(--card)" stroke="var(--primary)" /><text x={p.x} y={p.y + 4} textAnchor="middle" fontSize={11} fill="var(--foreground)">{id}</text></g>)}
        {[...C].map(([id, p]) => <g key={id}><rect x={p.x - 60} y={p.y - 12} width={120} height={24} rx={4} fill="var(--card)" stroke="var(--intel)" /><text x={p.x} y={p.y + 4} textAnchor="middle" fontSize={11} fontFamily="var(--font-mono)" fill="var(--foreground)">{id}</text></g>)}
        {[...P].map(([id, p]) => <g key={id}><rect x={p.x - 70} y={p.y - 12} width={140} height={24} rx={4} fill="var(--card)" stroke="var(--ok)" /><text x={p.x} y={p.y + 4} textAnchor="middle" fontSize={11} fill="var(--foreground)">{products.find((x) => x.id === id)?.name.split(" ")[0]}</text></g>)}
      </svg>
    </div>
  );
}
