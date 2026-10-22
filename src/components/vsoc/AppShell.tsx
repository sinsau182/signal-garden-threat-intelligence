import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { Activity, Boxes, Bug, FileBarChart, Home, Plug, Radar, Settings, ShieldAlert, ShieldCheck, Truck } from "lucide-react";

const nav = [
  { to: "/", label: "Home", icon: Home },
  { to: "/threat-intel", label: "Threat intel", icon: Radar, core: true },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { to: "/products", label: "Products", icon: Boxes },
  { to: "/psirt", label: "PSIRT", icon: ShieldAlert },
  { to: "/supply-chain", label: "Supply chain", icon: Truck },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
  { to: "/reports", label: "Reports", icon: FileBarChart },
  { to: "/integrations", label: "Integrations", icon: Plug },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar md:flex">
        <div className="flex items-center gap-2 px-5 py-5">
          <div className="grid h-8 w-8 place-items-center rounded bg-primary font-display font-bold text-primary-foreground">V</div>
          <div>
            <div className="font-display text-sm font-semibold text-sidebar-foreground">vSOC</div>
            <div className="label-caps !text-[9px]">Product Security Ops</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 px-3">
          {nav.map((n) => (
            <Link
              key={n.to}
              to={n.to}
              activeOptions={{ exact: n.to === "/" }}
              className="flex items-center gap-3 rounded px-3 py-2 text-sm text-sidebar-foreground/80 transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              activeProps={{ className: "!bg-sidebar-accent !text-sidebar-primary" }}
            >
              <n.icon className="h-4 w-4" />
              <span className="flex-1">{n.label}</span>
              {"core" in n && <span className="label-caps !text-[9px] !text-intel">core</span>}
            </Link>
          ))}
        </nav>
        <div className="m-3 rounded border border-sidebar-border p-3">
          <div className="flex items-center gap-2 text-xs text-sidebar-foreground"><Activity className="h-3.5 w-3.5 text-ok" /> Feeds operational</div>
          <div className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground"><span className="pulse-dot h-1.5 w-1.5 rounded-full bg-ok" /> KEV · EPSS · OSV live</div>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <div className="flex gap-1 overflow-x-auto border-b px-3 py-2 md:hidden">
          {nav.map((n) => (
            <Link key={n.to} to={n.to} activeOptions={{ exact: n.to === "/" }} className="whitespace-nowrap rounded px-2 py-1 text-xs text-muted-foreground" activeProps={{ className: "!bg-muted !text-primary" }}>{n.label}</Link>
          ))}
        </div>
        <main className="mx-auto max-w-7xl px-4 py-6 md:px-8 md:py-8">{children}</main>
      </div>
    </div>
  );
}
