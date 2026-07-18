import {
  isSlitherAvailable,
  runSlither,
  mapSeverity,
  filterDetectors,
  buildFindingFromDetector,
  mergeSlitherFindings,
} from "../slither";
import type { Finding } from "../../types";

describe("isSlitherAvailable", () => {
  it("returns a boolean without throwing", () => {
    const result = isSlitherAvailable();
    expect(typeof result).toBe("boolean");
  });
});

describe("runSlither", () => {
  it("returns an empty array for a non-existent file", () => {
    const findings = runSlither("/tmp/does-not-exist-chainproof.sol");
    expect(Array.isArray(findings)).toBe(true);
    expect(findings).toHaveLength(0);
  });

  it("returns an empty array when slither is unavailable", () => {
    if (isSlitherAvailable()) {
      // Skip — slither is actually present in this environment
      return;
    }
    const findings = runSlither("any.sol");
    expect(findings).toEqual([]);
  });
});

describe("mapSeverity (confidence-weighted)", () => {
  it("matches the documented impact x confidence table", () => {
    expect(mapSeverity("High", "High")).toBe("critical");
    expect(mapSeverity("High", "Medium")).toBe("high");
    expect(mapSeverity("High", "Low")).toBe("medium");
    expect(mapSeverity("Medium", "High")).toBe("high");
    expect(mapSeverity("Medium", "Medium")).toBe("medium");
  });

  it("discounts severity further as confidence drops, never upgrades it", () => {
    expect(mapSeverity("Medium", "Low")).toBe("low");
    expect(mapSeverity("Low", "High")).toBe("medium");
    expect(mapSeverity("Low", "Medium")).toBe("low");
    expect(mapSeverity("Low", "Low")).toBe("info");
  });

  it("maps Informational impact to info regardless of confidence", () => {
    expect(mapSeverity("Informational", "High")).toBe("info");
    expect(mapSeverity("Informational", "Low")).toBe("info");
  });

  it("is case-insensitive", () => {
    expect(mapSeverity("HIGH", "HIGH")).toBe("critical");
    expect(mapSeverity("high", "high")).toBe("critical");
  });

  it("defaults to high confidence for an unrecognized confidence string", () => {
    // Preserves the old impact-only mapping when confidence is missing/unknown.
    expect(mapSeverity("High", "unknown")).toBe("critical");
    expect(mapSeverity("Medium", "")).toBe("high");
  });

  it("defaults to low impact for an unrecognized impact string", () => {
    expect(mapSeverity("unknown", "High")).toBe("medium");
  });
});

function fakeDetector(overrides: Partial<Parameters<typeof buildFindingFromDetector>[0]> = {}) {
  return {
    check: "reentrancy-eth",
    impact: "High",
    confidence: "High",
    description: "  Reentrancy in Vault.withdraw()  ",
    elements: [
      {
        name: "withdraw",
        source_mapping: { filename_short: "contracts/Vault.sol", lines: [10, 11, 12] },
      },
    ],
    ...overrides,
  };
}

describe("buildFindingFromDetector", () => {
  it("enriches a mapped detector with title, SWC id, and category-aware severity", () => {
    const finding = buildFindingFromDetector(fakeDetector(), "contracts/Vault.sol");
    expect(finding.id).toBe("SLITHER-REENTRANCY-ETH");
    expect(finding.title).toBe("Reentrancy (ETH transfer)");
    expect(finding.swcId).toBe("SWC-107");
    expect(finding.severity).toBe("critical");
    expect(finding.line).toBe(10);
    expect(finding.lineEnd).toBe(12);
    expect(finding.description).toBe("Reentrancy in Vault.withdraw()");
  });

  it("falls back to a humanized title and no SWC id for an unmapped detector", () => {
    const finding = buildFindingFromDetector(
      fakeDetector({ check: "some-brand-new-detector", impact: "Medium", confidence: "Medium" }),
      "contracts/Vault.sol",
    );
    expect(finding.id).toBe("SLITHER-SOME-BRAND-NEW-DETECTOR");
    expect(finding.title).toBe("some brand new detector");
    expect(finding.swcId).toBeUndefined();
    expect(finding.severity).toBe("medium");
  });

  it("honors a detector's severityOverride regardless of impact/confidence", () => {
    const finding = buildFindingFromDetector(
      fakeDetector({ check: "suicidal", impact: "Medium", confidence: "Low" }),
      "contracts/Vault.sol",
    );
    expect(finding.severity).toBe("critical");
  });

  it("omits lineEnd when the detector only touches a single line", () => {
    const finding = buildFindingFromDetector(
      fakeDetector({
        elements: [{ source_mapping: { filename_short: "a.sol", lines: [42] } }],
      }),
      "a.sol",
    );
    expect(finding.line).toBe(42);
    expect(finding.lineEnd).toBeUndefined();
  });
});

describe("filterDetectors", () => {
  const detectors = [
    fakeDetector({ check: "reentrancy-eth" }),
    fakeDetector({ check: "assembly" }),
    fakeDetector({ check: "low-level-calls" }),
  ];

  it("returns every detector when no config is given (backward-compatible default)", () => {
    expect(filterDetectors(detectors)).toEqual(detectors);
    expect(filterDetectors(detectors, {})).toEqual(detectors);
  });

  it("excludes only the listed detectors", () => {
    const result = filterDetectors(detectors, { exclude: ["assembly", "low-level-calls"] });
    expect(result.map((d) => d.check)).toEqual(["reentrancy-eth"]);
  });

  it("includes only the listed detectors, ignoring exclude", () => {
    const result = filterDetectors(detectors, {
      include: ["reentrancy-eth"],
      exclude: ["reentrancy-eth"],
    });
    expect(result.map((d) => d.check)).toEqual(["reentrancy-eth"]);
  });

  it("is case-insensitive on detector names", () => {
    const result = filterDetectors(detectors, { exclude: ["ASSEMBLY"] });
    expect(result.map((d) => d.check)).toEqual(["reentrancy-eth", "low-level-calls"]);
  });
});

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "CP-107",
    title: "Reentrancy vulnerability",
    description: "desc",
    recommendation: "rec",
    severity: "critical",
    file: "/repo/contracts/Vault.sol",
    line: 10,
    ...overrides,
  };
}

describe("mergeSlitherFindings", () => {
  it("drops a Slither finding that overlaps a built-in finding of the same category", () => {
    const existing = [finding({ id: "CP-107", line: 11 })];
    const slither = [
      finding({
        id: "SLITHER-REENTRANCY-ETH",
        file: "/repo/contracts/Vault.sol",
        line: 10,
        lineEnd: 12,
      }),
    ];
    const merged = mergeSlitherFindings(existing, slither);
    expect(merged).toHaveLength(1);
    expect(merged[0].id).toBe("CP-107");
  });

  it("keeps a Slither finding when line ranges do not overlap", () => {
    const existing = [finding({ id: "CP-107", line: 11 })];
    const slither = [
      finding({ id: "SLITHER-REENTRANCY-ETH", file: "/repo/contracts/Vault.sol", line: 90 }),
    ];
    const merged = mergeSlitherFindings(existing, slither);
    expect(merged).toHaveLength(2);
  });

  it("keeps a Slither finding when the file differs", () => {
    const existing = [finding({ id: "CP-107", file: "/repo/contracts/Other.sol", line: 10 })];
    const slither = [
      finding({ id: "SLITHER-REENTRANCY-ETH", file: "/repo/contracts/Vault.sol", line: 10 }),
    ];
    const merged = mergeSlitherFindings(existing, slither);
    expect(merged).toHaveLength(2);
  });

  it("keeps a Slither finding when the category differs, even on the same line", () => {
    const existing = [finding({ id: "CP-115", file: "/repo/contracts/Vault.sol", line: 10 })];
    const slither = [
      finding({ id: "SLITHER-REENTRANCY-ETH", file: "/repo/contracts/Vault.sol", line: 10 }),
    ];
    const merged = mergeSlitherFindings(existing, slither);
    expect(merged).toHaveLength(2);
  });

  it("keeps an unmapped Slither detector's finding (own id never collides with a CP- category)", () => {
    const existing = [finding({ id: "CP-107", file: "/repo/contracts/Vault.sol", line: 10 })];
    const slither = [
      finding({
        id: "SLITHER-SOME-BRAND-NEW-DETECTOR",
        file: "/repo/contracts/Vault.sol",
        line: 10,
      }),
    ];
    const merged = mergeSlitherFindings(existing, slither);
    expect(merged).toHaveLength(2);
  });

  it("normalizes file paths (basename) so relative vs. absolute paths still dedupe", () => {
    const existing = [finding({ id: "CP-107", file: "/repo/contracts/Vault.sol", line: 10 })];
    const slither = [finding({ id: "SLITHER-REENTRANCY-ETH", file: "contracts/Vault.sol", line: 10 })];
    const merged = mergeSlitherFindings(existing, slither);
    expect(merged).toHaveLength(1);
  });

  it("dedupes Slither findings against each other (e.g. reported once per inheritance level)", () => {
    const slither = [
      finding({ id: "SLITHER-REENTRANCY-ETH", file: "/repo/contracts/Child.sol", line: 20 }),
      finding({ id: "SLITHER-REENTRANCY-ETH", file: "/repo/contracts/Child.sol", line: 20 }),
    ];
    const merged = mergeSlitherFindings([], slither);
    expect(merged).toHaveLength(1);
  });
});
