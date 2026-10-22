import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { sevColor, type Sev } from "@/lib/data";

export function PageHeader({ eyebrow, title, desc, right }: { eyebrow: string; title: string; desc?: string; right?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <div className="label-caps text-primary">{eyebrow}</div>
        <h1 className="mt-1 text-3xl font-semibold">{title}</h1>
        {desc && <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{desc}</p>}
      </div>
      {right}
    </div>
  );
}

export function Panel({ title, action, children, className }: { title?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("panel p-4", className)}>
      {title && (
        <div className="mb-3 flex items-center justify-between">
          <h2 className="label-caps">{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: string; tone?: "critical" | "intel" | "primary" | "ok" }) {
  const t = { critical: "text-critical", intel: "text-intel", primary: "text-primary", ok: "text-ok" }[tone ?? "primary"];
  return (
    <div className="panel p-4">
      <div className="label-caps">{label}</div>
      <div className={cn("mt-2 font-display text-3xl font-semibold", t)}>{value}</div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
    </div>
  );
}

export function SevBadge({ sev, children }: { sev: Sev; children?: ReactNode }) {
  return <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase", sevColor[sev])}>{children ?? sev}</span>;
}

export function Tag({ children, tone = "muted" }: { children: ReactNode; tone?: "muted" | "intel" | "critical" | "ok" | "primary" }) {
  const t = {
    muted: "border-border text-muted-foreground",
    intel: "border-intel/40 text-intel bg-intel/10",
    critical: "border-critical/40 text-critical bg-critical/10",
    ok: "border-ok/40 text-ok bg-ok/10",
    primary: "border-primary/40 text-primary bg-primary/10",
  }[tone];
  return <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px]", t)}>{children}</span>;
}

export function DataTable({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b">
            {head.map((h) => <th key={h} className="label-caps px-2 py-2 text-left font-normal">{h}</th>)}
          </tr>
        </thead>
        <tbody className="[&_tr]:border-b [&_tr:last-child]:border-0 [&_td]:px-2 [&_td]:py-2 [&_tr:hover]:bg-muted/40">{children}</tbody>
      </table>
    </div>
  );
}

export function Bar({ value, tone = "primary" }: { value: number; tone?: "primary" | "critical" | "intel" | "ok" }) {
  const t = { primary: "bg-primary", critical: "bg-critical", intel: "bg-intel", ok: "bg-ok" }[tone];
  return <div className="h-1.5 w-full rounded bg-muted"><div className={cn("h-1.5 rounded", t)} style={{ width: `${Math.min(100, value)}%` }} /></div>;
}
