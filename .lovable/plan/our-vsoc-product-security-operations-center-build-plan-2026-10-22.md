# Our vSOC — Product Security Operations Center (Build Plan)

Reference studied: 234 pages / ~13k UI elements of DestroSolutions PSOC. Friday and all chatbot features are excluded. Threat Intel is the core engine every other module reads from.

## 1. What we are building

```text
                    +--------------------------------------+
                    |          THREAT INTEL ENGINE         |
                    |  (ingest -> normalize -> enrich ->   |
                    |   correlate -> score -> alert)       |
                    +---+-------+-------+-------+-------+--+
                        |       |       |       |       |
              +---------+  +----+---+ +-+-----+ +-------+--+ +--------+
              |Vulns &  |  | PSIRT  | |Supply | |Compliance| |Reports |
              |Remediat.|  | Cases  | |Chain  | | CRA/ENISA| |& Trust |
              +----+----+  +----+---+ +---+---+ +----+-----+ +----+---+
                   |            |         |          |            |
                   +------------+----+----+----------+------------+
                                     |
                      +--------------+---------------+
                      |  PRODUCTS / SBOM / FIRMWARE  |
                      |  (assets everything maps to) |
                      +------------------------------+
```

## 2. Module map (parity + surpass)

| Module | Destro has | We add (surpass) |
|---|---|---|
| Home | Next actions, risk, threat pulse, fleet map, CRA readiness, supply chain | Live risk trend chart, MTTR/SLA gauges, "what changed in 24h" diff |
| Products | Overview, vulns, VEX, releases, suppliers, TARA, requirements, verification, deployment, controls | Release-to-release SBOM diff, attack-path diagram per product |
| Vulnerabilities | By CVE / by fix, remediation, KEV filter, decision pages | Unified risk score (CVSS+EPSS+KEV+exposure+actor link), fix-impact simulator |
| Threat Intel | Landscape, actors, graph, watchlists, sources | Full feed catalog (below), IOC store, MITRE ATT&CK heatmap, timeline, feed health |
| PSIRT | Operations, cases, collaboration, advisories, playbooks, triage | Kanban + SLA timers, CSAF advisory export, Article 14 24h/72h countdown |
| Supply chain | Suppliers, graph, requests, supplier SBOMs, open source | Supplier risk scorecard, package-maintainer health (OpenSSF Scorecard) |
| Compliance | CRA articles/annexes, gap analysis, checklist, calculators, ENISA SRP | Evidence auto-linking, UNECE R155/R156, ISO 21434, IEC 62443 mappings |
| Reports | Exports | Scheduled PDF/CSV, executive one-pager |
| Integrations | Tools, feeds, repos, CI, API keys, webhooks | Feed health monitor, per-feed rate-limit/quota view |
| Settings | Members, MFA, trust portal | Roles (admin/analyst/viewer), audit log |

## 3. Threat Intel data sources (the heart)

### Vulnerability & exploit intelligence
| Source | Data | Access |
|---|---|---|
| NVD API 2.0 | CVE, CVSS, CPE, CWE | Free, API key recommended |
| CISA KEV | Known exploited CVEs | Free JSON |
| FIRST EPSS | Exploit probability score | Free API |
| OSV.dev | Open-source package vulns (npm, PyPI, Maven, Go, Debian...) | Free API |
| GitHub Advisory DB (GHSA) | Package advisories | Free GraphQL (token) |
| MITRE CVE List (cvelistV5) | Authoritative CVE records | Free GitHub |
| Exploit-DB | Public exploits | Free CSV |
| Vulncheck KEV / NVD++ | Extended KEV | Free tier, key |
| Linux distro trackers (Debian, Ubuntu, Red Hat, Alpine) | Distro fix status | Free |

### Vendor / ICS / automotive / embedded advisories
| Source | Data |
|---|---|
| CISA ICS advisories (ICSA) | ICS / OT advisories |
| CERT/CC VINCE, BSI CERT-Bund, ENISA EUVD | National CERT advisories |
| Auto-ISAC (if member), Upstream / VicOne public reports | Automotive threats |
| Vendor CSAF feeds (Siemens, Bosch, Cisco, Microsoft, Red Hat) | Machine-readable advisories (CSAF 2.0) |

### Threat actors, TTPs & IOCs
| Source | Data | Access |
|---|---|---|
| MITRE ATT&CK (Enterprise + ICS) STIX | Actors, techniques, software | Free |
| AlienVault OTX | Pulses, IOCs | Free key |
| abuse.ch (URLhaus, MalwareBazaar, ThreatFox, Feodo) | URLs, hashes, C2 | Free |
| MISP community feeds / CIRCL | Shared IOCs | Free |
| GreyNoise Community | Mass-scanning IPs, CVE exploitation activity | Free key |
| Shodan / Censys | Internet exposure of devices | Paid key |
| VirusTotal | File/URL reputation | Free key (rate-limited) |

### News & early signals
| Source | Data |
|---|---|
| Security RSS (BleepingComputer, The Record, SecurityWeek, Krebs) | Headlines |
| GitHub PoC search, Reddit r/netsec | Early exploit chatter |

Phase 1 uses the free/no-key feeds (NVD, KEV, EPSS, OSV, ATT&CK, abuse.ch, CISA ICS). Keyed feeds are added once you supply keys.

### Ingestion pipeline

```text
 [Scheduler every 15m-24h per feed]
          |
          v
 +-----------+   +-------------+   +--------------+   +-------------+
 |  Fetch    |-->|  Normalize  |-->|   Enrich     |-->| Correlate   |
 | (per-feed |   | to common   |   | EPSS, KEV,   |   | match CVE / |
 |  adapter) |   | schema STIX |   | ATT&CK, CWE  |   | CPE / purl  |
 +-----------+   | / CVE JSON  |   +--------------+   | vs our SBOMs|
                 +-------------+                      +------+------+
                                                             |
                    +----------------------------------------+
                    v
          +-------------------+     +------------------+
          | Risk score engine | --> | Alerts, cases,   |
          | CVSS*EPSS*KEV*    |     | watchlist hits,  |
          | exposure*actor    |     | dashboard pulse  |
          +-------------------+     +------------------+
```

### Risk score formula (our differentiator)

```text
score = CVSS_base x (1 + EPSS) x KEV_boost(1.5) x exposure(0.5-1.5)
        x actor_link(1.3 if a tracked actor uses it) x reachability(0.3-1)
-> 0..100, banded Critical / High / Medium / Low, with explanation shown
```

## 4. Core data model

```text
 Product 1--* Release 1--* SBOM 1--* Component(purl, version)
                                         |
                                         *--* CVE *--* ThreatActor
                                         |      |
                         Supplier 1--*---+      +--* IOC
                                                |
 Finding (Component x CVE x Release) --> Decision/VEX --> PSIRT Case --> Advisory
                                                                  |
                                               ComplianceEvidence-+
```

## 5. Key flows

```text
Vulnerability lifecycle
 New CVE in feed -> matched to SBOM -> Finding (Open)
   -> Triage (affected? VEX) -> Not affected | Affected
   -> Affected -> Remediation plan -> Fix released -> Verified -> Closed
   -> if KEV/actively exploited -> PSIRT case + CRA Art.14 24h clock

PSIRT case
 Report intake -> Triage -> Investigate -> Coordinate (supplier)
   -> Advisory (CSAF) -> ENISA notification -> Close + lessons learned

SBOM intake
 Upload / CI pipeline / Git repo -> parse CycloneDX/SPDX -> components
   -> instant match vs intel -> diff vs previous release
```

## 6. Step-by-step roadmap

```text
Phase 0  Foundation        design system, app shell, sidebar, auth, roles
Phase 1  Threat Intel core feeds (free), ingestion jobs, landscape, actors,
                           ATT&CK heatmap, graph, watchlists, sources health
Phase 2  Products & SBOM   products, releases, SBOM upload/parse, components
Phase 3  Vulnerabilities   matching, findings, risk score, remediation, VEX
Phase 4  Home dashboard    risk trend, threat pulse, next actions, fleet map
Phase 5  PSIRT             cases, kanban triage, playbooks, advisories (CSAF)
Phase 6  Supply chain      suppliers, dependency graph, requests, scorecards
Phase 7  Compliance        CRA articles/annexes, gap analysis, checklist,
                           calculators, ENISA SRP, R155/ISO 21434 mapping
Phase 8  Reports & Integr. exports, scheduled reports, API keys, webhooks, CI
Phase 9  Settings & trust  members, MFA, audit log, public trust portal
```

Each phase ships working screens with realistic sample data seeded so the app is "alive" from day one, then switches to live feed data as jobs run.

## 7. Diagrams included in the app
- Threat graph (actor -> technique -> CVE -> component -> product), interactive
- MITRE ATT&CK heatmap of techniques hitting our components
- Supply-chain dependency graph
- Risk trend line, severity donut, SLA gauges, EPSS vs CVSS scatter
- Per-product attack-path / architecture diagram
- Vulnerability lifecycle Sankey (open -> triaged -> fixed)
- CRA readiness radar and ENISA deadline timeline
- Feed health timeline on Sources tab

## 8. Design direction
Dark operations-room look: deep graphite background, signal-amber primary, cyan for intel, red only for critical. Monospace for CVE IDs and hashes, condensed sans for headings. Dense tables, collapsible sidebar, keyboard search (Cmd+K).

## Technical details
- Stack: TanStack Start + Lovable Cloud (database, auth, storage, scheduled jobs).
- Feed adapters run as server routes triggered by cron (`/api/public/cron/*`, secret-verified); one adapter per source, common normalized schema.
- Matching on purl/CPE; SBOM parsing for CycloneDX 1.5 and SPDX 2.3 JSON.
- Charts: Recharts; graphs: React Flow (client-only); ATT&CK heatmap custom grid.
- Roles in a separate `user_roles` table with RLS; audit log table.
- API keys for keyed feeds (NVD, OTX, GreyNoise, Shodan, VirusTotal, GitHub) stored as secrets, requested when that phase starts.
