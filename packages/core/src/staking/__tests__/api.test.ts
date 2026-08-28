import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  analyzeStakingFiles,
  analyzeStakingSource,
  analyzeStakingSources,
  collectStakingSolidityFiles,
} from "../api";
import {
  loadStakingConfigFile,
  migrateStakingConfig,
  StakingAnalysisCancelledError,
  StakingConfigError,
  validateStakingConfig,
} from "../config";
import { serializeStakingReportJSON, serializeStakingReportMarkdown } from "../serialize";

const MINIMAL = `
pragma solidity ^0.8.20;
contract StakeFixture {
  uint totalSupply;
  mapping(address => uint) balances;
  uint rewardPerTokenStored;
  mapping(address => uint) userRewardPerTokenPaid;
  function stake(uint amount) external { totalSupply += amount; balances[msg.sender] += amount; }
  function withdraw(uint amount) external { balances[msg.sender] -= amount; totalSupply -= amount; }
}`;

describe("staking public API", () => {
  it("serializes deterministically regardless of source input order", () => {
    const left = analyzeStakingSources([
      { file: "b.sol", source: MINIMAL },
      { file: "a.sol", source: MINIMAL },
    ]);
    const right = analyzeStakingSources([
      { file: "a.sol", source: MINIMAL },
      { file: "b.sol", source: MINIMAL },
    ]);
    expect(serializeStakingReportJSON(left)).toBe(serializeStakingReportJSON(right));
    expect(left.files.map((file) => file.file)).toEqual(["a.sol", "b.sol"]);
  });

  it("returns structured diagnostics for malformed and over-budget source", () => {
    const malformed = analyzeStakingSource({ file: "broken.sol", source: "contract {" });
    expect(malformed.files[0].diagnostics[0].code).toBe("STK_PARSE_ERROR");
    expect(malformed.files[0].diagnostics[0].message).not.toContain(process.cwd());

    const bounded = analyzeStakingSource(
      { file: "large.sol", source: MINIMAL },
      { limits: { maxSourceBytes: 8 } },
    );
    expect(bounded.files[0].diagnostics[0].code).toBe("STK_SOURCE_LIMIT");
    expect(bounded.summary.truncated).toBe(true);
  });

  it("bounds files and findings and reports truncation", () => {
    const inputs = Array.from({ length: 4 }, (_, index) => ({ file: `${index}.sol`, source: MINIMAL }));
    const report = analyzeStakingSources(inputs, { limits: { maxFiles: 2, maxFindings: 1 } });
    expect(report.summary.files).toBe(2);
    expect(report.summary.truncated).toBe(true);
    expect(report.summary.total).toBeLessThanOrEqual(1);
    expect(report.files.some((file) => file.file === "<analysis>")).toBe(true);
  });

  it("enforces project contract, per-contract function, and per-function operation budgets", () => {
    const crowded = `pragma solidity ^0.8.20;
      contract A { uint totalSupply; mapping(address=>uint) balances; uint rewardPerTokenStored;
        mapping(address=>uint) userRewardPerTokenPaid;
        function stake(uint x) external { totalSupply += x; balances[msg.sender] += x; }
        function withdraw(uint x) external { balances[msg.sender] -= x; totalSupply -= x; }
      }
      contract B { uint totalSupply; mapping(address=>uint) balances; uint rewardPerTokenStored;
        mapping(address=>uint) userRewardPerTokenPaid;
        function stake(uint x) external { totalSupply += x; balances[msg.sender] += x; }
        function withdraw(uint x) external { balances[msg.sender] -= x; totalSupply -= x; }
      }`;
    const contractBound = analyzeStakingSource(
      { file: "crowded.sol", source: crowded },
      { limits: { maxContracts: 1 } },
    );
    expect(contractBound.files[0].diagnostics.map((diagnostic) => diagnostic.code))
      .toContain("STK_CONTRACT_LIMIT");

    const oneContract = crowded.slice(0, crowded.indexOf("contract B"));
    const operationBound = analyzeStakingSource(
      { file: "operations.sol", source: oneContract },
      { limits: { maxFunctionsPerContract: 1, maxOperationsPerFunction: 1 } },
    );
    const operationCodes = operationBound.files[0].diagnostics.map((diagnostic) => diagnostic.code);
    expect(operationCodes).toContain("STK_FUNCTION_LIMIT");
    expect(operationCodes).toContain("STK_OPERATION_LIMIT");
    expect(contractBound.summary.truncated).toBe(true);
    expect(operationBound.summary.truncated).toBe(true);
  });

  it("supports cooperative cancellation", () => {
    expect(() => analyzeStakingSource(
      { file: "cancelled.sol", source: MINIMAL },
      { signal: { aborted: true } },
    )).toThrow(StakingAnalysisCancelledError);
  });

  it("migrates v0 config and rejects invalid or corrupt artifacts", () => {
    const migrated = migrateStakingConfig({ version: 0, maxFileSize: 1000, maxIssues: 5, rules: ["CP-STK-001"] });
    expect(migrated.config).toMatchObject({
      schemaVersion: 1,
      limits: { maxSourceBytes: 1000, maxFindings: 5 },
      includeRules: ["CP-STK-001"],
    });
    expect(migrated.diagnostics).toHaveLength(1);
    expect(() => validateStakingConfig({ schemaVersion: 99 })).toThrow(StakingConfigError);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-staking-"));
    const corrupt = path.join(dir, "config.json");
    fs.writeFileSync(corrupt, "{not-json", "utf8");
    expect(() => loadStakingConfigFile(corrupt)).toThrow("invalid JSON");
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("handles unreadable files without leaking the host path in the error message", () => {
    const missing = path.join(os.tmpdir(), "not-present-staking.sol");
    const report = analyzeStakingFiles([missing]);
    expect(report.files[0].diagnostics[0]).toMatchObject({ code: "STK_FILE_UNREADABLE" });
    expect(report.files[0].diagnostics[0].message).not.toContain(missing);
  });

  it("collects only regular Solidity files and renders source evidence", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-targets-"));
    fs.writeFileSync(path.join(dir, "A.sol"), MINIMAL);
    fs.writeFileSync(path.join(dir, "skip.txt"), "ignored");
    fs.mkdirSync(path.join(dir, "nested"));
    fs.writeFileSync(path.join(dir, "nested", "B.sol"), MINIMAL);
    expect(collectStakingSolidityFiles([dir])).toEqual([
      path.join(dir, "A.sol"),
      path.join(dir, "nested", "B.sol"),
    ]);
    const markdown = serializeStakingReportMarkdown(analyzeStakingFiles([path.join(dir, "A.sol")]));
    expect(markdown).toContain("Report schema: `1.0.0`");
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
