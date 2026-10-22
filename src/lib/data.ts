// Seed data so the vSOC is alive before live feeds/database are wired.
export type Sev = "critical" | "high" | "medium" | "low";

export const products = [
  { id: "p-ivi-700", name: "IVI-700 Infotainment", type: "Head unit", firmware: "4.2.1", components: 412, open: 38, kev: 3, risk: 88, cra: 62 },
  { id: "p-tcu-200", name: "TCU-200 Telematics", type: "Telematics", firmware: "2.9.0", components: 287, open: 24, kev: 2, risk: 76, cra: 71 },
  { id: "p-bms-050", name: "BMS-050 Battery Mgmt", type: "ECU", firmware: "1.14.3", components: 96, open: 11, kev: 1, risk: 59, cra: 80 },
  { id: "p-evse-310", name: "EVSE-310 Charger", type: "Charging", firmware: "3.0.7", components: 198, open: 17, kev: 1, risk: 64, cra: 55 },
];

export type Finding = {
  cve: string; component: string; version: string; product: string; cvss: number; epss: number;
  kev: boolean; actor: boolean; exposure: number; reach: number; fix: string; status: string; sla: number;
};

export const findings: Finding[] = [
  { cve: "CVE-2021-44228", component: "log4j-core", version: "2.14.1", product: "p-ivi-700", cvss: 10, epss: 0.975, kev: true, actor: true, exposure: 1.3, reach: 1, fix: "2.17.1", status: "In remediation", sla: -2 },
  { cve: "CVE-2021-45046", component: "log4j-core", version: "2.14.1", product: "p-ivi-700", cvss: 9, epss: 0.97, kev: true, actor: false, exposure: 1.3, reach: 0.9, fix: "2.17.1", status: "Triage", sla: 3 },
  { cve: "CVE-2014-0160", component: "openssl", version: "1.0.1f", product: "p-tcu-200", cvss: 7.5, epss: 0.97, kev: true, actor: true, exposure: 1.5, reach: 1, fix: "1.0.1g", status: "Open", sla: 1 },
  { cve: "CVE-2023-4911", component: "glibc", version: "2.35", product: "p-tcu-200", cvss: 7.8, epss: 0.7, kev: true, actor: false, exposure: 0.8, reach: 0.7, fix: "2.38-4", status: "Open", sla: 9 },
  { cve: "CVE-2016-5195", component: "linux-kernel", version: "4.4.0", product: "p-bms-050", cvss: 7.8, epss: 0.96, kev: true, actor: true, exposure: 0.6, reach: 0.8, fix: "4.8.3", status: "Not affected (VEX)", sla: 14 },
  { cve: "CVE-2021-22555", component: "linux-kernel", version: "4.4.0", product: "p-bms-050", cvss: 7.8, epss: 0.4, kev: false, actor: false, exposure: 0.6, reach: 0.5, fix: "5.12", status: "Open", sla: 21 },
  { cve: "CVE-2024-3094", component: "xz-utils", version: "5.6.0", product: "p-evse-310", cvss: 10, epss: 0.86, kev: false, actor: true, exposure: 1.2, reach: 1, fix: "5.4.6", status: "In remediation", sla: 0 },
  { cve: "CVE-2023-4863", component: "libwebp", version: "1.3.1", product: "p-ivi-700", cvss: 8.8, epss: 0.6, kev: true, actor: false, exposure: 1.1, reach: 0.6, fix: "1.3.2", status: "Open", sla: 5 },
  { cve: "CVE-2023-38545", component: "curl", version: "8.3.0", product: "p-tcu-200", cvss: 9.8, epss: 0.3, kev: false, actor: false, exposure: 1.4, reach: 0.5, fix: "8.4.0", status: "Triage", sla: 6 },
  { cve: "CVE-2022-1271", component: "busybox", version: "1.33", product: "p-bms-050", cvss: 8.8, epss: 0.05, kev: false, actor: false, exposure: 0.6, reach: 0.3, fix: "1.35", status: "Open", sla: 30 },
];

/** Our differentiator: explainable composite risk score (0-100). */
export function riskScore(f: Pick<Finding, "cvss" | "epss" | "kev" | "actor" | "exposure" | "reach">) {
  const raw = f.cvss * (1 + f.epss) * (f.kev ? 1.5 : 1) * f.exposure * (f.actor ? 1.3 : 1) * f.reach;
  // Max theoretical raw ≈ 10*2*1.5*1.5*1.3*1 = 58.5
  return Math.min(100, Math.round((raw / 58.5) * 100));
}
export function band(score: number): Sev {
  if (score >= 70) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "medium";
  return "low";
}

export const actors = [
  { name: "APT41", origin: "CN", motivation: "Espionage / financial", sector: true, cves: ["CVE-2021-44228", "CVE-2014-0160"], techniques: ["T1190", "T1059", "T1505", "T1078"] },
  { name: "Lazarus Group", origin: "KP", motivation: "Financial", sector: true, cves: ["CVE-2021-44228", "CVE-2024-3094"], techniques: ["T1190", "T1195", "T1566", "T1486"] },
  { name: "Sandworm", origin: "RU", motivation: "Sabotage", sector: true, cves: ["CVE-2016-5195"], techniques: ["T1068", "T0866", "T0831", "T1485"] },
  { name: "FIN7", origin: "—", motivation: "Financial", sector: false, cves: [], techniques: ["T1566", "T1059", "T1055"] },
];

export const tactics = [
  { id: "TA0001", name: "Initial Access", techs: [["T1190", "Exploit public app", 9], ["T1195", "Supply chain compromise", 7], ["T1566", "Phishing", 3], ["T1078", "Valid accounts", 4]] },
  { id: "TA0002", name: "Execution", techs: [["T1059", "Command interpreter", 6], ["T1203", "Client exploitation", 4]] },
  { id: "TA0003", name: "Persistence", techs: [["T1505", "Server component", 5], ["T1542", "Pre-OS boot", 6]] },
  { id: "TA0004", name: "Priv. Escalation", techs: [["T1068", "Exploit for priv-esc", 8], ["T1055", "Process injection", 2]] },
  { id: "TA0040", name: "Impact", techs: [["T1486", "Data encrypted", 3], ["T1485", "Data destruction", 2], ["T0831", "Manipulation of control", 5]] },
  { id: "TA0108", name: "ICS Lateral", techs: [["T0866", "Exploit remote services", 6], ["T0886", "Remote services", 3]] },
] as const;

export type FeedSource = { name: string; category: string; data: string; access: "Free" | "Free key" | "Paid key" | "Membership"; cadence: string; live?: boolean; url: string };

export const sources: FeedSource[] = [
  { name: "CISA KEV", category: "Vulnerability", data: "Known exploited CVEs", access: "Free", cadence: "6h", live: true, url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
  { name: "FIRST EPSS", category: "Vulnerability", data: "Exploit probability", access: "Free", cadence: "24h", live: true, url: "https://www.first.org/epss/" },
  { name: "NVD API 2.0", category: "Vulnerability", data: "CVE, CVSS, CPE, CWE", access: "Free key", cadence: "2h", live: true, url: "https://nvd.nist.gov/developers" },
  { name: "OSV.dev", category: "Vulnerability", data: "Open-source package vulns", access: "Free", cadence: "1h", live: true, url: "https://osv.dev" },
  { name: "GitHub Advisory DB", category: "Vulnerability", data: "GHSA package advisories", access: "Free key", cadence: "1h", url: "https://github.com/advisories" },
  { name: "MITRE cvelistV5", category: "Vulnerability", data: "Authoritative CVE records", access: "Free", cadence: "1h", url: "https://github.com/CVEProject/cvelistV5" },
  { name: "Exploit-DB", category: "Vulnerability", data: "Public exploits", access: "Free", cadence: "24h", url: "https://www.exploit-db.com" },
  { name: "VulnCheck KEV", category: "Vulnerability", data: "Extended KEV", access: "Free key", cadence: "6h", url: "https://vulncheck.com" },
  { name: "Distro trackers", category: "Vulnerability", data: "Debian/Ubuntu/RHEL/Alpine fix status", access: "Free", cadence: "12h", url: "https://security-tracker.debian.org" },
  { name: "CISA ICS advisories", category: "Advisories", data: "ICS / OT advisories", access: "Free", cadence: "6h", url: "https://www.cisa.gov/news-events/cybersecurity-advisories" },
  { name: "ENISA EUVD", category: "Advisories", data: "EU vulnerability database", access: "Free", cadence: "6h", url: "https://euvd.enisa.europa.eu" },
  { name: "BSI CERT-Bund / CERT/CC", category: "Advisories", data: "National CERT advisories", access: "Free", cadence: "12h", url: "https://wid.cert-bund.de" },
  { name: "Vendor CSAF feeds", category: "Advisories", data: "Siemens, Bosch, Cisco, Red Hat CSAF 2.0", access: "Free", cadence: "6h", url: "https://csaf.io" },
  { name: "Auto-ISAC", category: "Advisories", data: "Automotive threat sharing", access: "Membership", cadence: "24h", url: "https://automotiveisac.com" },
  { name: "MITRE ATT&CK STIX", category: "Actors & TTPs", data: "Actors, techniques, software", access: "Free", cadence: "weekly", url: "https://attack.mitre.org" },
  { name: "AlienVault OTX", category: "Actors & TTPs", data: "Pulses, IOCs", access: "Free key", cadence: "1h", url: "https://otx.alienvault.com" },
  { name: "abuse.ch", category: "IOCs", data: "URLhaus, MalwareBazaar, ThreatFox, Feodo", access: "Free", cadence: "15m", url: "https://abuse.ch" },
  { name: "MISP / CIRCL feeds", category: "IOCs", data: "Shared community IOCs", access: "Free", cadence: "1h", url: "https://www.circl.lu/doc/misp/feed-osint/" },
  { name: "GreyNoise Community", category: "IOCs", data: "Scanning IPs & CVE exploitation", access: "Free key", cadence: "1h", url: "https://www.greynoise.io" },
  { name: "Shodan / Censys", category: "Exposure", data: "Internet-exposed devices", access: "Paid key", cadence: "24h", url: "https://www.shodan.io" },
  { name: "VirusTotal", category: "IOCs", data: "File/URL reputation", access: "Free key", cadence: "on demand", url: "https://www.virustotal.com" },
  { name: "Security news RSS", category: "Early signals", data: "BleepingComputer, The Record, SecurityWeek", access: "Free", cadence: "15m", url: "https://www.bleepingcomputer.com/feed/" },
  { name: "GitHub PoC watch", category: "Early signals", data: "New exploit repos per CVE", access: "Free key", cadence: "1h", url: "https://github.com/search" },
];

export const cases = [
  { id: "PS-7", title: "xz-utils backdoor in EVSE build image", product: "p-evse-310", cve: "CVE-2024-3094", sev: "critical" as Sev, stage: "Investigate", owner: "A. Singh", art14: 14 },
  { id: "PS-5", title: "Log4Shell exposure via IVI telemetry service", product: "p-ivi-700", cve: "CVE-2021-44228", sev: "critical" as Sev, stage: "Coordinate", owner: "R. Mehta", art14: 40 },
  { id: "PS-4", title: "Researcher report: CAN gateway auth bypass", product: "p-tcu-200", cve: "—", sev: "high" as Sev, stage: "Triage", owner: "Unassigned", art14: 66 },
  { id: "PS-3", title: "libwebp heap overflow in media player", product: "p-ivi-700", cve: "CVE-2023-4863", sev: "high" as Sev, stage: "Advisory", owner: "K. Iyer", art14: 0 },
  { id: "PS-2", title: "Heartbleed in legacy TCU modem stack", product: "p-tcu-200", cve: "CVE-2014-0160", sev: "high" as Sev, stage: "Closed", owner: "A. Singh", art14: 0 },
  { id: "PS-6", title: "Dirty COW on BMS diagnostics shell", product: "p-bms-050", cve: "CVE-2016-5195", sev: "medium" as Sev, stage: "Intake", owner: "Unassigned", art14: 70 },
];

export const suppliers = [
  { name: "Apache", products: 2, components: 14, open: 9, kev: 2, reachable: true, score: 72 },
  { name: "OpenSSL Project", products: 3, components: 6, open: 5, kev: 1, reachable: true, score: 81 },
  { name: "Linux Foundation", products: 4, components: 41, open: 12, kev: 1, reachable: false, score: 64 },
  { name: "GNU", products: 4, components: 22, open: 6, kev: 1, reachable: false, score: 58 },
  { name: "Wind River", products: 2, components: 31, open: 7, kev: 0, reachable: true, score: 77 },
  { name: "Vector Informatik", products: 3, components: 18, open: 3, kev: 0, reachable: true, score: 85 },
  { name: "Tukaani (xz)", products: 1, components: 1, open: 1, kev: 0, reachable: false, score: 22 },
];

export const riskTrend = Array.from({ length: 14 }, (_, i) => ({
  day: `D-${13 - i}`,
  critical: [9, 9, 10, 11, 12, 12, 11, 10, 10, 9, 8, 8, 7, 7][i],
  high: [22, 23, 23, 25, 24, 26, 25, 24, 22, 21, 21, 20, 19, 18][i],
  kev: [5, 5, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8][i],
}));

export const craReadiness = [
  { area: "Secure by design", score: 72 },
  { area: "Vuln handling", score: 81 },
  { area: "SBOM", score: 88 },
  { area: "Updates", score: 64 },
  { area: "Reporting (Art.14)", score: 57 },
  { area: "Documentation", score: 49 },
];

export const sevColor: Record<Sev, string> = {
  critical: "text-critical border-critical/40 bg-critical/10",
  high: "text-high border-high/40 bg-high/10",
  medium: "text-medium border-medium/40 bg-medium/10",
  low: "text-low border-low/40 bg-low/10",
};
