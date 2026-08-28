import * as os from "os";
import * as path from "path";
import { analyzeGovernanceFiles, analyzeGovernanceSource } from "../api";

describe("governance adversarial and performance safeguards", () => {
  it("preflights excessive contract counts before building an AST model", () => {
    const source = Array.from({ length: 30 }, (_, index) => `contract Governor${index} {}`).join("\n");
    const report = analyzeGovernanceSource(source, "many.sol", { limits: { maxContracts: 4 } });
    expect(report.files[0].diagnostics[0]).toMatchObject({ code: "GOV_CONTRACT_LIMIT" });
    expect(report.summary.total).toBe(0);
    expect(report.summary.truncated).toBe(true);
  });

  it("bounds operation modeling for a syntactically valid oversized function", () => {
    const statements = Array.from({ length: 200 }, () => "proposalCount += 1;").join("\n");
    const source = `pragma solidity ^0.8.20; contract OversizedGovernor {
      uint256 public proposalCount;
      uint256 public proposalThreshold;
      uint256 public votingDelay;
      uint256 public votingPeriod;
      function propose() external { ${statements} }
    }`;
    const started = Date.now();
    const report = analyzeGovernanceSource(source, "oversized.sol", {
      includeModels: true,
      limits: { maxOperationsPerFunction: 8 },
    });
    expect(report.files[0].diagnostics.some((item) => item.code === "GOV_OPERATION_LIMIT")).toBe(true);
    expect(report.files[0].models?.[0].transitions[0].operations.length).toBeLessThanOrEqual(8);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("detects statically duplicated proposal actions", () => {
    const source = `pragma solidity ^0.8.20; contract DuplicateGovernor {
      uint256 public proposalCount; uint256 public proposalThreshold;
      uint256 public votingDelay; uint256 public votingPeriod;
      mapping(uint256 => bool) public executed;
      function execute(uint256 id, address target, bytes calldata data) external {
        require(!executed[id]); executed[id] = true;
        target.call(data);
        target.call(data);
      }
    }`;
    const report = analyzeGovernanceSource(source, "duplicate.sol", {
      includeRules: ["CP-GOV-007"],
    });
    expect(report.files[0].findings).toHaveLength(1);
    expect(report.files[0].findings[0].title).toContain("duplicate action");
    expect(report.files[0].findings[0].evidence).toHaveLength(2);
  });

  it("returns an actionable diagnostic for a missing filesystem target", () => {
    const missing = path.join(os.tmpdir(), `chainproof-governance-missing-${process.pid}.sol`);
    const report = analyzeGovernanceFiles([missing]);
    expect(report.summary.total).toBe(0);
    expect(report.files[0].diagnostics[0]).toMatchObject({
      code: "GOV_FILE_UNREADABLE",
      message: "Solidity target could not be read (ENOENT)",
    });
    expect(report.files[0].diagnostics[0].message).not.toContain(missing);
  });
});
