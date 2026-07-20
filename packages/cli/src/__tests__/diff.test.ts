import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import type { ScanResult } from "@chainproof/core";

const CLI_BIN = path.resolve(__dirname, "../../dist/cli.js");
const TEMP_DIR = path.resolve(__dirname, "../../__tests_temp__");

function createMockResult(findingsCount: number, severity: "critical" | "high" | "low" = "high"): ScanResult {
  return {
    version: "0.1.0",
    timestamp: new Date().toISOString(),
    files: [
      {
        file: "contracts/Vault.sol",
        findings: Array.from({ length: findingsCount }).map((_, i) => ({
          id: `CP-10${i}`,
          title: `Test Vulnerability ${i}`,
          description: "Test description",
          recommendation: "Fix it",
          severity,
          file: "contracts/Vault.sol",
          line: 10 + i,
        })),
        gasHints: [],
        slitherRan: false,
      },
    ],
    summary: {
      critical: severity === "critical" ? findingsCount : 0,
      high: severity === "high" ? findingsCount : 0,
      medium: 0,
      low: severity === "low" ? findingsCount : 0,
      info: 0,
      gas: 0,
      total: findingsCount,
    },
  };
}

describe("CLI diff command", () => {
  beforeAll(() => {
    fs.mkdirSync(TEMP_DIR, { recursive: true });
  });

  afterAll(() => {
    fs.rmSync(TEMP_DIR, { recursive: true, force: true });
  });

  it("diffs two scan results and exits 0 when no new critical/high findings introduced", () => {
    const oldJson = path.join(TEMP_DIR, "old.json");
    const newJson = path.join(TEMP_DIR, "new.json");

    const baseResult = createMockResult(1, "high");
    fs.writeFileSync(oldJson, JSON.stringify(baseResult), "utf-8");
    fs.writeFileSync(newJson, JSON.stringify(baseResult), "utf-8");

    const output = execSync(`node ${CLI_BIN} diff ${oldJson} ${newJson} --format markdown`, {
      encoding: "utf-8",
    });

    expect(output).toContain("## ChainProof Diff Report");
    expect(output).toContain("Newly Introduced (0)");
  });

  it("exits with status 1 when high/critical findings are introduced", () => {
    const oldJson = path.join(TEMP_DIR, "old_clean.json");
    const newJson = path.join(TEMP_DIR, "new_vuln.json");

    fs.writeFileSync(oldJson, JSON.stringify(createMockResult(0)), "utf-8");
    fs.writeFileSync(newJson, JSON.stringify(createMockResult(1, "critical")), "utf-8");

    try {
      execSync(`node ${CLI_BIN} diff ${oldJson} ${newJson}`, { encoding: "utf-8" });
      fail("Expected command to exit with non-zero code");
    } catch (err: any) {
      expect(err.status).toBe(1);
      const combinedOutput = (err.stdout || "") + (err.stderr || "");
      expect(combinedOutput).toContain("newly introduced");
    }
  });
});
