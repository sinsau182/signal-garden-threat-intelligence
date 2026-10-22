import { createFileRoute } from "@tanstack/react-router";
import { sources } from "@/lib/data";
import { PageHeader, Panel, Tag } from "@/components/vsoc/ui";

export const Route = createFileRoute("/integrations")({
  head: () => ({
    meta: [
      { title: "Integrations — vSOC" },
      { name: "description", content: "Threat feeds, code repos, CI/CD pipelines, ticketing, SIEM and notifications." },
      { property: "og:title", content: "Integrations — vSOC" },
      { property: "og:description", content: "Connect feeds, pipelines and tools." },
    ],
  }),
  component: Integrations,
});

const groups = [
  ["Source control", ["GitHub", "GitLab", "Bitbucket"]],
  ["CI / CD", ["GitHub Actions", "GitLab CI", "Jenkins"]],
  ["Ticketing", ["Jira", "ServiceNow", "Linear"]],
  ["SIEM / SOAR", ["Splunk", "Microsoft Sentinel", "Elastic"]],
  ["Notifications", ["Slack", "Microsoft Teams", "Email", "Webhooks"]],
  ["SBOM formats", ["CycloneDX 1.5", "SPDX 2.3", "CSAF 2.0 / VEX"]],
] as const;

function Integrations() {
  const byCat = sources.reduce<Record<string, typeof sources>>((m, s) => ((m[s.category] ??= []).push(s), m), {});
  return (
    <>
      <PageHeader eyebrow="Connections" title="Integrations" desc="Live public feeds run now; keyed feeds and tools switch on as you add credentials." />
      <Panel title="Threat feeds by category">
        <div className="grid gap-4 md:grid-cols-3">
          {Object.entries(byCat).map(([c, list]) => (
            <div key={c}><div className="label-caps mb-2">{c}</div>
              <ul className="space-y-1 text-sm">{list.map((s) => <li key={s.name} className="flex justify-between"><span>{s.name}</span>{s.live ? <Tag tone="ok">live</Tag> : <Tag>{s.access}</Tag>}</li>)}</ul></div>
          ))}
        </div>
      </Panel>
      <div className="mt-4 grid gap-4 md:grid-cols-3">
        {groups.map(([g, items]) => (
          <Panel key={g} title={g}><ul className="space-y-1 text-sm">{items.map((i) => <li key={i} className="flex justify-between">{i}<Tag>not connected</Tag></li>)}</ul></Panel>
        ))}
      </div>
      <Panel title="CI quick start · upload SBOM from your pipeline" className="mt-4">
        <pre className="overflow-x-auto rounded bg-background p-3 font-mono text-xs text-muted-foreground">{`- name: Generate SBOM
  run: syft . -o cyclonedx-json > sbom.json
- name: Upload to vSOC
  run: curl -X POST $VSOC_URL/api/public/sbom -H "x-api-key: $VSOC_KEY" --data-binary @sbom.json`}</pre>
      </Panel>
    </>
  );
}
