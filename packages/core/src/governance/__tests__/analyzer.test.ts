import * as fs from "fs";
import * as path from "path";
import { analyzeGovernanceFiles, analyzeGovernanceSource } from "../api";
import type { GovernanceRuleId } from "../types";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/governance");

function fixture(name: string) {
  return analyzeGovernanceFiles([path.join(FIXTURES, `${name}.sol`)], { includeModels: true });
}

function rules(name: string): GovernanceRuleId[] {
  return fixture(name).files.flatMap((file) => file.findings.map((finding) => finding.ruleId));
}

describe("governance safety analyzer", () => {
  it("models live-balance, same-block, lifecycle, quorum, identity, execution, replay and guardian risks", () => {
    const ids = new Set(rules("VulnerableGovernor"));
    for (const expected of [
      "CP-GOV-001", "CP-GOV-002", "CP-GOV-003", "CP-GOV-004", "CP-GOV-005",
      "CP-GOV-006", "CP-GOV-007", "CP-GOV-008", "CP-GOV-009", "CP-GOV-014",
    ] satisfies GovernanceRuleId[]) {
      expect(ids).toContain(expected);
    }
  });

  it("recognizes checkpointed voting and an external timelock boundary", () => {
    const report = fixture("SecureGovernor");
    expect(report.files[0].findings).toEqual([]);
    expect(report.files[0].models?.[0].adapter).toBe("openzeppelin-governor");
    expect(report.files[0].models?.[0].transitions.find((item) => item.name === "castVote")?.calls)
      .toContain("getPastVotes");
  });

  it("detects unsafe timelock identity, delay, ordering, role, readiness and replay behavior", () => {
    const ids = new Set(rules("VulnerableTimelock"));
    for (const expected of [
      "CP-GOV-005", "CP-GOV-006", "CP-GOV-008", "CP-GOV-010", "CP-GOV-011",
      "CP-GOV-012", "CP-GOV-013",
    ] satisfies GovernanceRuleId[]) {
      expect(ids).toContain(expected);
    }
  });

  it("recognizes ordered, salted, predecessor-aware TimelockController behavior", () => {
    const report = fixture("SecureTimelockController");
    expect(report.files[0].findings).toEqual([]);
    expect(report.files[0].models?.[0].adapter).toBe("openzeppelin-timelock-controller");
    const execute = report.files[0].models?.[0].transitions.find((item) => item.name === "execute");
    const call = execute?.operations.find((item) => item.kind === "call" && item.name === "call");
    const consumption = execute?.operations.find((item) =>
      item.kind === "write" && item.expression.includes("_timestamps"));
    expect(consumption!.order).toBeLessThan(call!.order);
  });

  it("separates incomplete multisig validation from Safe-style validation", () => {
    expect(new Set(rules("VulnerableMultisig"))).toEqual(new Set(["CP-GOV-006", "CP-GOV-016"]));
    const secure = fixture("SecureMultisig");
    expect(secure.files[0].findings).toEqual([]);
    expect(secure.files[0].models?.[0].adapter).toBe("safe-multisig");
  });

  it("detects cross-chain replay/domain gaps and recognizes their secure ordering", () => {
    expect(rules("VulnerableCrossChainGovernor")).toContain("CP-GOV-015");
    const secure = fixture("SecureCrossChainGovernor");
    expect(secure.files[0].findings).toEqual([]);
    expect(secure.files[0].models?.[0].adapter).toBe("cross-chain-governor");
  });

  it("attaches bounded evidence, assumptions, confidence, and precise locations", () => {
    const finding = fixture("VulnerableGovernor").files[0].findings.find((item) =>
      item.ruleId === "CP-GOV-008");
    expect(finding).toMatchObject({ severity: "critical", confidence: "high", category: "execution" });
    expect(finding?.evidence[0]).toMatchObject({ kind: "taint-flow" });
    expect(finding?.evidence[0].description).toContain("target");
    expect(finding?.assumptions.length).toBeGreaterThan(0);
    expect(finding?.location.line).toBeGreaterThan(1);
  });

  it("supports deterministic include/exclude selection", () => {
    const source = fs.readFileSync(path.join(FIXTURES, "VulnerableGovernor.sol"), "utf8");
    const included = analyzeGovernanceSource(source, "Governor.sol", {
      includeRules: ["CP-GOV-001", "CP-GOV-008"],
    });
    expect(new Set(included.files[0].findings.map((finding) => finding.ruleId)))
      .toEqual(new Set(["CP-GOV-001", "CP-GOV-008"]));
    const excluded = analyzeGovernanceSource(source, "Governor.sol", {
      excludeRules: ["CP-GOV-001"],
    });
    expect(excluded.files[0].findings.some((finding) => finding.ruleId === "CP-GOV-001")).toBe(false);
  });

  it("reports only structural implementation safety, not proposal preferences", () => {
    const source = `pragma solidity ^0.8.20; contract PoliticalText {
      string public proposalOutcome = "unpopular";
      string public voterPreference = "against";
    }`;
    expect(analyzeGovernanceSource(source).summary.total).toBe(0);
  });
});
