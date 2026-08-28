import { execFileSync, spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const CLI = path.resolve(__dirname, "../../dist/cli.js");
const FIXTURES = path.resolve(__dirname, "../../../../examples/contracts/governance");

describe("governance CLI", () => {
  beforeAll(() => {
    execFileSync("npm", ["run", "build", "--workspace=packages/core"], { cwd: path.resolve(__dirname, "../../../..") });
    execFileSync("npm", ["run", "build", "--workspace=packages/server"], { cwd: path.resolve(__dirname, "../../../..") });
    execFileSync("npm", ["run", "build", "--workspace=packages/cli"], { cwd: path.resolve(__dirname, "../../../..") });
  }, 60_000);

  it("prints machine-readable deterministic JSON without a banner", () => {
    const result = spawnSync(process.execPath, [
      CLI, "governance", path.join(FIXTURES, "VulnerableGovernor.sol"),
      "--format", "json", "--fail-on", "none", "--include-rule", "CP-GOV-001",
    ], { encoding: "utf8" });
    expect(result.status).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report.schemaVersion).toBe("1.0.0");
    expect(report.files[0].findings.map((finding: { ruleId: string }) => finding.ruleId))
      .toEqual(["CP-GOV-001"]);
    expect(result.stdout).not.toContain("████");
  });

  it("uses the configured fail threshold for CI", () => {
    const result = spawnSync(process.execPath, [
      CLI, "governance", path.join(FIXTURES, "VulnerableTimelock.sol"),
      "--format", "json", "--fail-on", "high",
    ], { encoding: "utf8" });
    expect(result.status).toBe(1);
    expect(JSON.parse(result.stdout).summary.total).toBeGreaterThan(0);
  });

  it("writes Markdown to a requested artifact", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-governance-cli-"));
    const output = path.join(directory, "report.md");
    const result = spawnSync(process.execPath, [
      CLI, "governance", path.join(FIXTURES, "SecureGovernor.sol"),
      "--output", output, "--fail-on", "none",
    ], { encoding: "utf8" });
    expect(result.status).toBe(0);
    expect(fs.readFileSync(output, "utf8")).toContain("# Governance Safety Analysis");
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("rejects corrupt rule configuration with a sanitized usage error", () => {
    const result = spawnSync(process.execPath, [
      CLI, "governance", path.join(FIXTURES, "SecureGovernor.sol"),
      "--format", "json", "--include-rule", "CP-GOV-999",
    ], { encoding: "utf8" });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("unknown rule CP-GOV-999");
    expect(result.stderr).not.toContain(vulnerableSourceMarker());
  });
});

function vulnerableSourceMarker(): string {
  return "Intentionally vulnerable fixture";
}
