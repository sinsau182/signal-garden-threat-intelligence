import { createFileRoute, Link, Outlet, useMatchRoute } from "@tanstack/react-router";
import { products } from "@/lib/data";
import { Bar, PageHeader, Tag } from "@/components/vsoc/ui";

export const Route = createFileRoute("/_authenticated/products")({
  head: () => ({
    meta: [
      { title: "Products — vSOC" },
      { name: "description", content: "Your products, firmware releases, SBOMs and per-product risk." },
      { property: "og:title", content: "Products — vSOC" },
      { property: "og:description", content: "Product portfolio with SBOM and risk posture." },
    ],
  }),
  component: Products,
});

function Products() {
  const m = useMatchRoute();
  if (m({ to: "/products/$id", fuzzy: true })) return <Outlet />;
  return (
    <>
      <PageHeader eyebrow="Assets" title="Products" desc="Everything in the vSOC maps back to a product, release and SBOM." />
      <div className="grid gap-4 md:grid-cols-2">
        {products.map((p) => (
          <Link key={p.id} to="/products/$id" params={{ id: p.id }} className="panel block p-5 transition-colors hover:border-primary/60">
            <div className="flex items-start justify-between">
              <div><div className="label-caps">{p.type}</div><h3 className="mt-1 text-lg font-semibold">{p.name}</h3></div>
              <Tag tone="intel">fw {p.firmware}</Tag>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-center">
              <div><div className="font-display text-2xl">{p.components}</div><div className="label-caps">components</div></div>
              <div><div className="font-display text-2xl text-high">{p.open}</div><div className="label-caps">open</div></div>
              <div><div className="font-display text-2xl text-critical">{p.kev}</div><div className="label-caps">KEV</div></div>
            </div>
            <div className="mt-4 space-y-2 text-xs">
              <div>Risk {p.risk}<Bar value={p.risk} tone={p.risk > 75 ? "critical" : "primary"} /></div>
              <div>CRA readiness {p.cra}%<Bar value={p.cra} tone="ok" /></div>
            </div>
          </Link>
        ))}
      </div>
    </>
  );
}
