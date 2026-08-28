import * as fs from "fs";
import * as path from "path";
import { analyzeStakingSource } from "../api";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/staking");

function analyzeFixture(name: string) {
  const file = path.join(FIXTURES, name);
  return analyzeStakingSource({ file, source: fs.readFileSync(file, "utf8") }, { includeModels: true });
}

describe("staking accounting analyzer", () => {
  it("models accumulated-index state and detects vulnerable staking transitions", () => {
    const report = analyzeFixture("VulnerableStakingAccounting.sol");
    const ids = new Set(report.files[0].findings.map((finding) => finding.ruleId));

    expect(ids).toEqual(new Set([
      "CP-STK-001",
      "CP-STK-002",
      "CP-STK-003",
      "CP-STK-004",
      "CP-STK-005",
      "CP-STK-006",
      "CP-STK-007",
      "CP-STK-008",
      "CP-STK-011",
      "CP-STK-012",
    ]));
    expect(report.files[0].models?.[0]).toMatchObject({
      name: "VulnerableStakingAccounting",
      adapter: "synthetix-staking-rewards",
      rewardTokens: ["rewardTokenA", "rewardTokenB"],
      stakeTokens: ["stakingToken"],
    });
    expect(report.files[0].findings.every((finding) => finding.evidence.length > 0)).toBe(true);
    expect(report.files[0].findings.every((finding) => finding.location.line > 0)).toBe(true);
  });

  it("recognizes checkpoint, balance-delta, coverage, recovery, and zero-supply protections", () => {
    const report = analyzeFixture("SecureStakingRewards.sol");
    expect(report.files[0].models?.[0].adapter).toBe("synthetix-staking-rewards");
    expect(report.files[0].findings).toEqual([]);
  });

  it("detects cliff bypass and vesting state updates after interactions", () => {
    const report = analyzeFixture("VulnerableVesting.sol");
    const ids = report.files[0].findings.map((finding) => finding.ruleId);
    expect(ids).toContain("CP-STK-009");
    expect(ids).toContain("CP-STK-010");
  });

  it("does not flag a boundary-enforced checks-effects-interactions vesting flow", () => {
    const report = analyzeFixture("SecureVesting.sol");
    expect(report.files[0].findings).toEqual([]);
  });

  it("supports deterministic rule inclusion and exclusion", () => {
    const file = path.join(FIXTURES, "VulnerableStakingAccounting.sol");
    const input = { file, source: fs.readFileSync(file, "utf8") };
    const included = analyzeStakingSource(input, { includeRules: ["CP-STK-006"] });
    const excluded = analyzeStakingSource(input, { excludeRules: ["CP-STK-006"] });
    expect(included.files[0].findings.map((finding) => finding.ruleId)).toEqual(["CP-STK-006"]);
    expect(excluded.files[0].findings.some((finding) => finding.ruleId === "CP-STK-006")).toBe(false);
  });

  it("detects nominal accounting for explicit rebasing assets and accepts share accounting", () => {
    const vulnerable = analyzeFixture("VulnerableRebasingStake.sol");
    const secure = analyzeFixture("SecureRebasingShares.sol");
    expect(vulnerable.files[0].findings.map((finding) => finding.ruleId)).toContain("CP-STK-013");
    expect(secure.files[0].findings.map((finding) => finding.ruleId)).not.toContain("CP-STK-013");
  });
});
