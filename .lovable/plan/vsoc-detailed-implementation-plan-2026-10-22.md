# vSOC — Detailed Implementation Plan

Goal: our own Product Security Operations Center that matches DestroSolutions PSOC (234 pages, ~13k UI elements reviewed) and surpasses it. Friday and every chatbot/AI assistant are out of scope. Threat Intel is the core engine every module reads from.

Current state: all 10 sections exist as working screens on demo data; CISA KEV + FIRST EPSS + OSV lookup are live. This plan takes it to a real, data-backed product.

---

## 1. System overview

```text
 ┌──────────────────────────── EXTERNAL SOURCES (23) ────────────────────────────┐
 │ KEV  EPSS  NVD  OSV  GHSA  cvelistV5  ExploitDB  ATT&CK  abuse.ch  OTX  CSAF  │
 │ CISA-ICS  ENISA-EUVD  CERT-Bund  GreyNoise  VirusTotal  Shodan  RSS  PoC-watch│
 └──────────────────────────────────┬─────────────────────────────────────────────┘
                                    │ cron (15 min – weekly, per feed)
 ┌──────────────────────────────────▼─────────────────────────────────────────────┐
 │                         THREAT INTEL ENGINE                                    │
 │  Adapter → Raw store → Normalizer → Enricher → Correlator → Risk engine → Act   │
 └──────┬───────────┬────────────┬────────────┬────────────┬──────────────┬──────┘
        ▼           ▼            ▼            ▼            ▼              ▼
   Vulnerabilities  PSIRT    Supply chain  Compliance   Reports      Notifications
        └───────────┴─────┬──────┴────────────┴────────────┘
                          ▼
           PRODUCTS · RELEASES · SBOMs · COMPONENTS   ◄── CI/CD, Git, manual upload
```

---

## 2. Feature parity + surpass matrix

| Area | DestroSolutions pages observed | We build (parity) | We add (surpass) |
|---|---|---|---|
| Home | Next actions, Risk detected, Threat pulse, Fleet map, CRA readiness, Tactical intel, Supply chain | All | 24h change diff, MTTR/SLA gauges, risk trend 14/30/90d |
| Products | overview, vulnerabilities, remediation, VEX, releases, suppliers, threat-model (TARA), requirements, verification plan/records, design overview, deployment, controls, components, sources, firmware | All | SBOM diff between releases, attack-path diagram, per-product risk history |
| Vulnerabilities | Overview, Remediation, By CVE, By fix, KEV filter, component filter, decision pages | All | Explainable 0–100 score, EPSS×CVSS matrix, fix-impact simulator, lifecycle Sankey |
| Threat intel | Landscape, Actors, Graph, Watchlists, Sources | All | 23-feed catalog with health, ATT&CK heatmap, IOC store, live package lookup, KEV trend |
| PSIRT | Operations, Cases, Collaboration, Advisories, Playbooks, Triage board, case detail (lifecycle, triage, owner/dates, CVD, advisory, Art.14, ENISA submission, history) | All | Kanban with SLA timers, CSAF 2.0 export, automated Art.14 clocks |
| Supply chain | All / attention / unregistered, graph, requests, supplier SBOMs, open source, supplier detail | All | Supplier risk scorecard, OpenSSF Scorecard health, response-time tracking |
| Compliance | CRA articles/annexes, standards, timeline, RACI, open source, SRP, tools (SBOM builder, license risk, container scan, gate, early signals, steward), gap analysis, checklist, templates, risk/cost calculators, matrix, vuln analyzer, support-period planner, ENISA per product, classification | All | UNECE R155/R156, ISO/SAE 21434, IEC 62443-4-1 mappings, evidence auto-linking |
| Reports | exports | All | Scheduled executive one-pager, CRA technical file bundle |
| Integrations | Tools catalog, threat feeds, code repos, CI builds, API keys, webhooks, CI quick start | All | Per-feed quota/rate-limit view, feed health timeline |
| Settings | members, MFA, trust portal | All | Roles (admin/analyst/viewer), full audit log |
| Friday / chat | inbox, chats, projects, run history, helpers, accuracy | Excluded | — |

---

## 3. Threat intel data sources — full fetch list

### 3.1 Vulnerability & exploit intel

| # | Source | Endpoint | Format | Auth | Cadence | Fills |
|---|---|---|---|---|---|---|
| 1 | CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON | none | 6h | kev flag, due date, ransomware use |
| 2 | FIRST EPSS | `https://api.first.org/data/v1/epss?cve=...` and daily CSV `https://epss.cyentia.com/epss_scores-current.csv.gz` | JSON/CSV | none | 24h | epss, percentile |
| 3 | NVD API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=..&lastModEndDate=..` | JSON | `NVD_API_KEY` (50 req/30s) | 2h incremental | cvss, cwe, cpe, refs |
| 4 | OSV.dev | `POST https://api.osv.dev/v1/querybatch` + GCS dumps per ecosystem | JSON | none | 1h + on SBOM upload | purl matching |
| 5 | GitHub Advisory DB | `https://api.github.com/advisories` (REST) | JSON | `GITHUB_TOKEN` | 1h | GHSA, patched versions |
| 6 | MITRE cvelistV5 | `https://github.com/CVEProject/cvelistV5` delta files | JSON 5.x | none | 1h | CNA data, rejected CVEs |
| 7 | Exploit-DB | `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | CSV | none | 24h | public exploit flag |
| 8 | VulnCheck KEV | `https://api.vulncheck.com/v3/index/vulncheck-kev` | JSON | `VULNCHECK_API_KEY` | 6h | extended exploited list |
| 9 | Debian / Ubuntu / Red Hat / Alpine trackers | `security-tracker.debian.org/tracker/data/json`, Ubuntu OVAL, Red Hat CSAF, `secdb.alpinelinux.org` | JSON/XML | none | 12h | distro fix status |

### 3.2 Advisories (ICS / automotive / vendor)

| # | Source | Endpoint | Format | Auth | Cadence |
|---|---|---|---|---|---|
| 10 | CISA ICS advisories | `https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml` + CSAF repo `github.com/cisagov/CSAF` | RSS/CSAF | none | 6h |
| 11 | ENISA EUVD | `https://euvdservices.enisa.europa.eu/api/...` | JSON | none | 6h |
| 12 | BSI CERT-Bund / CERT/CC | `wid.cert-bund.de` CSAF provider, CERT/CC VINCE | CSAF | none | 12h |
| 13 | Vendor CSAF trusted providers (Siemens, Bosch, Cisco, Red Hat, SICK…) | `provider-metadata.json` discovery per vendor | CSAF 2.0 / VEX | none | 6h |
| 14 | Auto-ISAC | member portal / STIX-TAXII | STIX | membership | 24h |

### 3.3 Actors, TTPs, IOCs

| # | Source | Endpoint | Format | Auth | Cadence |
|---|---|---|---|---|---|
| 15 | MITRE ATT&CK Enterprise + ICS | `github.com/mitre-attack/attack-stix-data` | STIX 2.1 | none | weekly |
| 16 | AlienVault OTX | `https://otx.alienvault.com/api/v1/pulses/subscribed` | JSON | `OTX_API_KEY` | 1h |
| 17 | abuse.ch ThreatFox / URLhaus / MalwareBazaar / Feodo | `threatfox-api.abuse.ch`, `urlhaus-api.abuse.ch`, `mb-api.abuse.ch`, `feodotracker.abuse.ch` | JSON/CSV | `ABUSECH_AUTH_KEY` (free) | 15m |
| 18 | MISP / CIRCL OSINT | `https://www.circl.lu/doc/misp/feed-osint/manifest.json` | MISP JSON | none | 1h |
| 19 | GreyNoise Community | `https://api.greynoise.io/v3/community/{ip}` + tag/CVE activity | JSON | `GREYNOISE_API_KEY` | 1h |
| 20 | VirusTotal | `https://www.virustotal.com/api/v3/...` | JSON | `VIRUSTOTAL_API_KEY` | on demand |
| 21 | Shodan / Censys | `api.shodan.io/shodan/host/search` | JSON | `SHODAN_API_KEY` (paid) | 24h |

### 3.4 Early signals

| # | Source | Endpoint | Cadence |
|---|---|---|---|
| 22 | Security news RSS | BleepingComputer, The Record, SecurityWeek, Krebs feeds | 15m |
| 23 | GitHub PoC watch | `api.github.com/search/repositories?q=CVE-YYYY-NNNN` for tracked CVEs | 1h |

Rollout: #1–4, 6, 7, 10, 15, 17, 18, 22 first (no paid keys). Keyed feeds switch on as secrets are added.

### 3.5 Ingestion pipeline (per feed)

```text
 pg_cron ──► POST /api/public/cron/feed/{source}   (verifies CRON_SECRET header)
                  │
                  ▼
          Adapter.fetch(since = feed_runs.last_cursor)
                  │  rate-limit + retry with backoff, ETag/If-Modified-Since
                  ▼
          raw_items (source, external_id, payload jsonb, hash)  ── dedupe by hash
                  │
                  ▼
          Normalizer → cves / advisories / iocs / actors / techniques (upsert)
                  │
                  ▼
          Enricher  → attach epss, kev, cwe, attack technique, actor links
                  │
                  ▼
          Correlator → match purl (OSV/GHSA) and CPE (NVD) against components
                  │      → create/update findings (component × cve × release)
                  ▼
          Risk engine → recompute findings.score + explanation jsonb
                  │
                  ▼
          Actions → notifications, watchlist hits, auto PSIRT case if KEV & score ≥ 70
                  │
                  ▼
          feed_runs (started, finished, items_in, items_new, error, cursor)
```

### 3.6 Risk engine

```text
raw   = CVSS × (1 + EPSS) × KEV(1.5|1) × Exposure(0.5–1.5) × Actor(1.3|1) × Reachability(0.3–1)
score = min(100, round(raw / 58.5 × 100))
band  : ≥70 critical (SLA 7d) · 45–69 high (30d) · 20–44 medium (90d) · <20 low (next release)
VEX "not_affected" → score 0, finding hidden from queues but kept for audit
```
Exposure comes from product deployment (internet-facing, cellular, local bus). Reachability from analyst input or call-graph evidence. Every score stores its factor breakdown for the UI.

---

## 4. Data model (Lovable Cloud)

```text
 organizations 1─* products 1─* releases 1─* sboms 1─* components(purl, cpe, version, license, supplier_id)
                                                          │
 suppliers 1─────────────────────────────────────────────┘
 cves(id, cvss, vector, cwe, epss, epss_pct, kev, kev_due, ransomware, exploit_public, published, modified)
 findings(component_id, cve_id, release_id, status, score, factors jsonb, sla_due, owner)
 vex_statements(finding_id, status, justification, author, created_at)
 threat_actors(id, name, origin, motivation, sectors[])   actor_cves(actor, cve)   actor_techniques(actor, technique)
 attack_techniques(id, tactic, name, platform)            iocs(type, value, source, first_seen, tags[])
 advisories_ext(source, external_id, title, cves[], csaf jsonb)
 watchlists(user_id, kind: component|cve|vendor|actor, value)
 psirt_cases(id, title, product_id, severity, stage, owner, reported_at, art14_warning_due, art14_notice_due, art14_final_due)
 case_events(case_id, type, body, author, at)              advisories(case_id, csaf jsonb, status, published_at)
 playbooks(name, min_severity, steps jsonb)
 supplier_requests(supplier_id, kind, status, due, answer)
 compliance_requirements(framework, ref, text)             evidence(requirement_id, entity_type, entity_id, status)
 sources(id, name, category, access, cadence, enabled)     feed_runs(source_id, started, finished, items_in, items_new, error, cursor)
 raw_items(source_id, external_id, hash, payload jsonb, fetched_at)
 api_keys(org, name, hash, last_used)   webhooks(org, url, events[], secret)   notifications(user_id, kind, body, read)
 profiles(user_id, display_name)        user_roles(user_id, role: admin|analyst|viewer)   audit_log(actor, action, entity, diff, at)
```

Rules: roles only in `user_roles` with `has_role()` security-definer; RLS on every table scoped by organization; every table gets explicit GRANTs; audit trigger on findings, vex, cases, evidence.

---

## 5. App structure

```text
src/routes/
  index.tsx                       Home
  auth.tsx                        sign in / sign up
  reset-password.tsx
  _authenticated/route.tsx        session gate
  threat-intel.tsx                tabs: landscape | actors | attack | graph | watchlists | iocs | sources
  threat-intel.cve.$id.tsx        CVE detail (all sources merged, timeline, affected builds)
  threat-intel.actor.$id.tsx      actor profile
  vulnerabilities.tsx             by CVE | by fix | matrix | lifecycle
  findings.$id.tsx                decision page (score breakdown, VEX, history)
  products.tsx / products.$id.tsx  + sub-tabs: overview, findings, releases, sbom, suppliers, tara,
                                    requirements, verification, deployment, controls, vex
  psirt.tsx                       board | cases | advisories | playbooks | operations
  psirt.$caseId.tsx               case detail with Art.14 clocks
  supply-chain.tsx / supply-chain.$supplier.tsx / supply-chain.requests.tsx
  compliance.tsx + compliance.cra.tsx, compliance.r155.tsx, compliance.21434.tsx, compliance.62443.tsx,
    compliance.tools.$tool.tsx (gap analysis, checklist, cost, support period, classification)
  reports.tsx  integrations.tsx  settings.tsx  settings.members.tsx  settings.audit.tsx
  trust.$org.tsx                  public trust portal (no auth)
  api/public/cron/feed.$source.ts feed jobs (secret-verified)
  api/public/sbom.ts              CI SBOM upload (API key verified)
  api/public/webhooks.$provider.ts
src/lib/
  feeds/{kev,epss,nvd,osv,ghsa,cvelist,exploitdb,cisa-ics,attack,abusech,misp,otx,greynoise,rss}.ts
  normalize.ts  correlate.ts  risk.ts  sbom-parse.ts  csaf.ts
  *.functions.ts                  server functions per module
```

---

## 6. Key flows

```text
SBOM INTAKE
 Upload / CI POST / Git repo ─► parse CycloneDX 1.5 or SPDX 2.3 ─► components (purl, cpe)
   ─► OSV querybatch + local cves table ─► findings ─► risk engine ─► diff vs previous release

VULNERABILITY LIFECYCLE
 Open ─► Triage ─┬─► Not affected ─► VEX statement ─► (closed, kept for audit)
                 └─► Affected ─► Remediation planned ─► Fix released ─► Verified ─► Closed
 KEV or score ≥70 ─► auto PSIRT case + Art.14 clocks

PSIRT CASE
 Intake ─► Triage ─► Investigate ─► Coordinate supplier ─► Advisory (CSAF) ─► ENISA notice ─► Close
            clocks: early warning ≤24h · notification ≤72h · final report ≤14d after fix

SUPPLIER LOOP
 Finding on supplier component ─► request (SBOM / VEX / fix ETA) ─► reminder ─► answer ─► scorecard update
```

```text
CRA ARTICLE 14 TIMELINE (per case)
 t0 aware ──24h──► early warning ──72h──► notification ──(fix)──14d──► final report
```

---

## 7. Diagrams to ship in the app

| Diagram | Where | Library |
|---|---|---|
| Ingestion pipeline strip | Threat intel header | custom |
| KEV additions trend, top vendors | Threat intel landscape | Recharts |
| ATT&CK tactic × technique heatmap | Threat intel | custom grid |
| Threat graph actor→CVE→component→product | Threat intel graph | React Flow |
| Feed health timeline | Sources tab | Recharts |
| Risk trend, readiness radar, SLA gauges | Home | Recharts |
| Fleet map (product risk bars / grid) | Home | custom |
| EPSS × CVSS bubble matrix | Vulnerabilities | Recharts |
| Lifecycle Sankey (open→triaged→fixed) | Vulnerabilities | Recharts Sankey |
| Score factor waterfall | Finding detail | Recharts |
| Attack path per product | Product overview | React Flow |
| SBOM release diff | Product releases | custom |
| Dependency graph supplier→component→product | Supply chain | React Flow |
| PSIRT kanban + Art.14 timeline | PSIRT | custom |
| CRA timeline, framework bars, Annex I matrix | Compliance | custom |

---

## 8. Step-by-step phases

### Phase 1 — Accounts & database (1 week)
- Enable Lovable Cloud; email + Google sign-in; profiles; `user_roles` + `has_role`
- `_authenticated` layout; auth page; reset-password page
- Organizations, members page, audit log trigger
- Done when: sign up → land on Home → see own org only

### Phase 2 — Threat intel storage & jobs (2 weeks)
- Tables: sources, feed_runs, raw_items, cves, iocs, threat_actors, attack_techniques, advisories_ext
- Adapters #1, 2, 4, 6, 7, 10, 15, 17, 18, 22; cron routes with `CRON_SECRET`
- Sources tab reads `feed_runs` (health, last run, counts, errors)
- CVE detail page merging all sources with a timeline
- Done when: KEV/EPSS/ATT&CK refresh on schedule and Sources tab shows green runs

### Phase 3 — Products, releases, SBOM (2 weeks)
- CRUD for products/releases; SBOM upload (CycloneDX/SPDX) to storage, parser, components
- CI endpoint `/api/public/sbom` with hashed API keys; GitHub Actions / GitLab snippets
- Release diff view
- Done when: uploading a real SBOM lists its components and versions

### Phase 4 — Correlation & risk engine (2 weeks)
- purl/CPE matching, findings creation, score + factors, SLA due dates
- Vulnerabilities page on real data; finding detail with factor waterfall; VEX statements; by-fix grouping
- Unit tests for every score factor and band
- Done when: a log4j-core 2.14.1 component produces CVE-2021-44228 scored critical with breakdown

### Phase 5 — Home & notifications (1 week)
- Live KPIs, risk trend from daily snapshots table, 24h change diff
- In-app notifications + email/Slack webhooks for KEV matches and SLA breaches

### Phase 6 — PSIRT (2 weeks)
- Cases, events, kanban drag between stages, playbooks, Art.14 clocks with due timestamps
- Advisory editor with CSAF 2.0 JSON export; collaboration notes; auto-case from KEV match
- Done when: KEV finding auto-opens case with 24h/72h/14d deadlines visible

### Phase 7 — Supply chain (2 weeks)
- Suppliers from SBOM components; scorecard; requests with due dates and reminders
- Dependency graph; supplier SBOM upload; OpenSSF Scorecard lookup for open-source packages

### Phase 8 — Compliance (2 weeks)
- Requirement library: CRA Annex I + articles, R155, R156, ISO/SAE 21434, IEC 62443-4-1
- Evidence auto-links (SBOM per release, VEX, advisories, SLA metrics); gap analysis, checklist, calculators, support-period planner, ENISA brief per product

### Phase 9 — Reports, integrations, trust portal (2 weeks)
- CSV/PDF exports, scheduled reports; Jira/ServiceNow ticket push; webhooks
- Keyed feeds (#3, 5, 8, 16, 19, 20, 21, 23) as secrets arrive
- Public trust portal: security.txt, disclosure policy, published advisories

```text
 Week  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
 P1   ██
 P2      ████
 P3            ████
 P4                  ████
 P5                        ██
 P6                           ████
 P7                                 ████
 P8                                       ████
 P9                                             ████
```

---

## 9. Quality & security
- RLS + GRANTs on every table; roles via `has_role`; no admin client for normal reads
- All feed and third-party calls in server functions/routes; keys only as secrets
- Public routes (cron, SBOM upload, webhooks, trust portal) verify secrets/keys and never return private data
- Tests: risk score, SBOM parsing, purl matching, Art.14 deadline math, CSAF export shape
- Feed resilience: backoff, last-good cache, per-feed error surfacing

## 10. What is needed from you
1. Go-ahead for Phase 1 (accounts & database) and whether to keep Google sign-in
2. Free API keys when ready: NVD, GitHub, abuse.ch, AlienVault OTX, GreyNoise, VirusTotal; optional paid Shodan / VulnCheck
3. Real product list and one sample SBOM
4. Auto-ISAC membership details, if any

## Technical details
- Stack: TanStack Start, Lovable Cloud (Postgres, auth, storage, pg_cron + pg_net calling server routes)
- Libraries to add: `@xyflow/react` (graphs, client-only), `@cyclonedx/cyclonedx-library` or custom parser, `packageurl-js`
- Workers runtime: no Node-only libs in server code; large dumps (EPSS CSV, ATT&CK STIX) streamed and chunked per run
