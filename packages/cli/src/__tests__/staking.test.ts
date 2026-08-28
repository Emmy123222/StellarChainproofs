import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const CLI = path.resolve(__dirname, "../../dist/cli.js");
const FIXTURES = path.resolve(__dirname, "../../../../examples/contracts/staking");

function run(args: string[], allowFailure: boolean = false): string {
  try {
    return execFileSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  } catch (error) {
    if (allowFailure) return (error as { stdout?: string }).stdout ?? "";
    throw error;
  }
}

describe("CLI staking command", () => {
  it("emits parseable versioned JSON with deterministic rule filtering", () => {
    const output = run([
      "staking",
      path.join(FIXTURES, "VulnerableStakingAccounting.sol"),
      "--format", "json",
      "--include-rule", "CP-STK-006",
      "--fail-on", "none",
    ]);
    const report = JSON.parse(output);
    expect(report.schemaVersion).toBe("1.0.0");
    expect(report.files[0].findings.map((finding: { ruleId: string }) => finding.ruleId))
      .toEqual(["CP-STK-006"]);
  });

  it("uses the configured failure threshold for CI", () => {
    expect(() => run([
      "staking",
      path.join(FIXTURES, "VulnerableVesting.sol"),
      "--format", "json",
      "--fail-on", "high",
    ])).toThrow();
    const output = run([
      "staking",
      path.join(FIXTURES, "VulnerableVesting.sol"),
      "--format", "json",
      "--fail-on", "high",
    ], true);
    expect(JSON.parse(output).summary.high).toBe(2);
  });

  it("loads a migrated configuration and writes a report artifact", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-staking-cli-"));
    const config = path.join(dir, "config.json");
    const output = path.join(dir, "report.json");
    fs.writeFileSync(config, JSON.stringify({ version: 0, rules: ["CP-STK-009"] }));
    run([
      "staking",
      path.join(FIXTURES, "VulnerableVesting.sol"),
      "--format", "json",
      "--config", config,
      "--output", output,
      "--fail-on", "none",
    ]);
    const report = JSON.parse(fs.readFileSync(output, "utf8"));
    expect(report.files[0].findings.map((finding: { ruleId: string }) => finding.ruleId))
      .toEqual(["CP-STK-009"]);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
