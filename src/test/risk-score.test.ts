import { describe, expect, it } from "vitest";
import { band, riskScore } from "@/lib/data";

describe("risk score", () => {
  it("max signals reach 100", () => {
    expect(riskScore({ cvss: 10, epss: 1, kev: true, actor: true, exposure: 1.5, reach: 1 })).toBe(100);
  });
  it("KEV boosts score by 1.5x", () => {
    const base = { cvss: 5, epss: 0, actor: false, exposure: 1, reach: 1 };
    expect(riskScore({ ...base, kev: true })).toBe(13);
    expect(riskScore({ ...base, kev: false })).toBe(9);
  });
  it("bands at 70/45/20", () => {
    expect(band(70)).toBe("critical");
    expect(band(45)).toBe("high");
    expect(band(20)).toBe("medium");
    expect(band(19)).toBe("low");
  });
});
