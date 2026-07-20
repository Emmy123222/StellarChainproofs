import {
  diffScans,
  computeFingerprint,
  generateMarkdownDiffReport,
  generateJSONDiffReport,
  generateTableDiffReport,
} from "../index";
import type { ScanResult, Finding } from "../types";

function createMockScanResult(findings: Finding[]): ScanResult {
  const fileMap = new Map<string, Finding[]>();
  findings.forEach((f) => {
    if (!fileMap.has(f.file)) fileMap.set(f.file, []);
    fileMap.get(f.file)!.push(f);
  });

  const files = Array.from(fileMap.entries()).map(([file, fileFindings]) => ({
    file,
    findings: fileFindings,
    gasHints: [],
    slitherRan: false,
  }));

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

  return {
    version: "0.1.0",
    timestamp: new Date().toISOString(),
    files,
    summary: {
      critical,
      high,
      medium: 0,
      low: 0,
      info: 0,
      gas: 0,
      total: findings.length,
    },
  };
}

describe("diffScans engine", () => {
  const finding1: Finding = {
    id: "CP-107",
    title: "Reentrancy",
    description: "Reentrancy vulnerability",
    recommendation: "Use ReentrancyGuard",
    severity: "critical",
    file: "contracts/Vault.sol",
    line: 42,
    snippet: "msg.sender.call{value: amount}(\"\")",
  };

  const finding2: Finding = {
    id: "CP-115",
    title: "tx.origin authentication",
    description: "tx.origin used for auth",
    recommendation: "Use msg.sender",
    severity: "high",
    file: "contracts/Auth.sol",
    line: 18,
    snippet: "require(tx.origin == owner)",
  };

  const finding3: Finding = {
    id: "CP-104",
    title: "Unchecked call return value",
    description: "Unchecked return value",
    recommendation: "Check return value",
    severity: "medium",
    file: "contracts/Token.sol",
    line: 100,
    snippet: "token.transfer(to, val)",
  };

  it("computes deterministic SHA-256 fingerprints", () => {
    const fp1 = computeFingerprint(finding1);
    const fp2 = computeFingerprint(finding1);
    const fp3 = computeFingerprint(finding2);

    expect(fp1).toEqual(fp2);
    expect(fp1).not.toEqual(fp3);
    expect(fp1).toHaveLength(64);
  });

  it("correctly identifies introduced, resolved, and persisted findings", () => {
    const oldResult = createMockScanResult([finding1, finding2]);
    const newResult = createMockScanResult([finding1, finding3]);

    const diff = diffScans(oldResult, newResult);

    expect(diff.persisted).toHaveLength(1);
    expect(diff.persisted[0].id).toBe("CP-107");

    expect(diff.introduced).toHaveLength(1);
    expect(diff.introduced[0].id).toBe("CP-104");

    expect(diff.resolved).toHaveLength(1);
    expect(diff.resolved[0].id).toBe("CP-115");

    expect(diff.summary).toEqual({
      newCritical: 0,
      newHigh: 0,
      resolvedTotal: 1,
    });
  });

  it("handles line tolerance (±3 lines) for line movements", () => {
    const movedFinding: Finding = {
      ...finding1,
      line: 44, // Shifted 2 lines down
    };

    const oldResult = createMockScanResult([finding1]);
    const newResult = createMockScanResult([movedFinding]);

    const diff = diffScans(oldResult, newResult);

    expect(diff.persisted).toHaveLength(1);
    expect(diff.introduced).toHaveLength(0);
    expect(diff.resolved).toHaveLength(0);
  });

  it("generates markdown diff report matching expected format", () => {
    const oldResult = createMockScanResult([finding2]);
    const newResult = createMockScanResult([finding1]);

    const diff = diffScans(oldResult, newResult);
    const md = generateMarkdownDiffReport(diff);

    expect(md).toContain("## ChainProof Diff Report");
    expect(md).toContain("### Newly Introduced (1)");
    expect(md).toContain("| CP-107 | contracts/Vault.sol | 42 | Critical |");
    expect(md).toContain("### Resolved Since Last Scan (1)");
    expect(md).toContain("| CP-115 | contracts/Auth.sol | 18 | High |");
  });

  it("generates JSON diff report", () => {
    const oldResult = createMockScanResult([finding2]);
    const newResult = createMockScanResult([finding1]);

    const diff = diffScans(oldResult, newResult);
    const jsonStr = generateJSONDiffReport(diff);
    const parsed = JSON.parse(jsonStr);

    expect(parsed.summary.newCritical).toBe(1);
    expect(parsed.summary.resolvedTotal).toBe(1);
  });

  it("generates table diff report", () => {
    const oldResult = createMockScanResult([finding2]);
    const newResult = createMockScanResult([finding1]);

    const diff = diffScans(oldResult, newResult);
    const table = generateTableDiffReport(diff);

    expect(table).toContain("CHAINPROOF SCAN DIFF REPORT");
    expect(table).toContain("Newly Introduced : 1 critical, 0 high");
  });
});
