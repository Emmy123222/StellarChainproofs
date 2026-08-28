import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  analyzeGovernanceFiles,
  analyzeGovernanceSource,
  analyzeGovernanceSources,
  collectGovernanceSolidityFiles,
} from "../api";
import { GovernanceAnalysisCancelledError } from "../config";
import { generateGovernanceMarkdown, serializeGovernanceReport } from "../serialize";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/governance");
const vulnerable = fs.readFileSync(path.join(FIXTURES, "VulnerableGovernor.sol"), "utf8");
const secure = fs.readFileSync(path.join(FIXTURES, "SecureGovernor.sol"), "utf8");

describe("governance analysis API", () => {
  it("sorts sources and serialized object keys deterministically", () => {
    const first = analyzeGovernanceSources([
      { file: "z.sol", source: vulnerable },
      { file: "a.sol", source: secure },
    ]);
    const second = analyzeGovernanceSources([
      { file: "a.sol", source: secure },
      { file: "z.sol", source: vulnerable },
    ]);
    expect(serializeGovernanceReport(first)).toBe(serializeGovernanceReport(second));
    expect(first.files.map((file) => file.file)).toEqual(["a.sol", "z.sol"]);
    expect(serializeGovernanceReport(first)).toMatch(/^\{\n  "engineVersion"/);
  });

  it("produces a versioned Markdown artifact with evidence and scope", () => {
    const markdown = generateGovernanceMarkdown(analyzeGovernanceSource(vulnerable, "Gov.sol"));
    expect(markdown).toContain("# Governance Safety Analysis");
    expect(markdown).toContain("CP-GOV-001");
    expect(markdown).toContain("**Evidence:**");
    expect(markdown).toContain("does not rate political legitimacy");
  });

  it("emits a parse diagnostic instead of throwing or leaking internals", () => {
    const report = analyzeGovernanceSource("contract Broken { function x( ", "broken.sol");
    expect(report.files[0].diagnostics[0]).toMatchObject({ code: "GOV_PARSE_ERROR", severity: "error" });
    expect(report.files[0].diagnostics[0].message).not.toContain(process.cwd());
  });

  it("enforces source, file, operation, evidence and finding bounds", () => {
    const sourceLimited = analyzeGovernanceSource(vulnerable, "large.sol", { limits: { maxSourceBytes: 20 } });
    expect(sourceLimited.files[0].diagnostics[0].code).toBe("GOV_SOURCE_LIMIT");
    expect(sourceLimited.summary.truncated).toBe(true);

    const findingLimited = analyzeGovernanceSource(vulnerable, "governor.sol", {
      limits: { maxFindings: 2, maxEvidencePerFinding: 1, maxOperationsPerFunction: 500 },
    });
    expect(findingLimited.summary.total).toBe(2);
    expect(findingLimited.summary.truncated).toBe(true);
    expect(findingLimited.files[0].findings.every((finding) => finding.evidence.length <= 1)).toBe(true);

    const fileLimited = analyzeGovernanceSources([
      { file: "a.sol", source: vulnerable }, { file: "b.sol", source: vulnerable },
    ], { limits: { maxFiles: 1 } });
    expect(fileLimited.files.some((file) => file.file === "<project>")).toBe(true);
  });

  it("honors cancellation before expensive parsing", () => {
    expect(() => analyzeGovernanceSource(vulnerable, "cancelled.sol", {
      signal: { aborted: true, reason: "test" },
    })).toThrow(GovernanceAnalysisCancelledError);
  });

  it("collects files in stable order, skips symlinks and ignores non-Solidity files", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-governance-"));
    fs.mkdirSync(path.join(directory, "nested"));
    fs.writeFileSync(path.join(directory, "b.sol"), "contract B {}", "utf8");
    fs.writeFileSync(path.join(directory, "nested", "a.sol"), "contract A {}", "utf8");
    fs.writeFileSync(path.join(directory, "notes.txt"), "ignored", "utf8");
    fs.symlinkSync(path.join(directory, "b.sol"), path.join(directory, "linked.sol"));
    const files = collectGovernanceSolidityFiles([directory]);
    expect(files).toEqual([...files].sort());
    expect(files.map((file) => path.basename(file))).toEqual(["b.sol", "a.sol"]);
    expect(files.some((file) => file.endsWith("linked.sol"))).toBe(false);
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("analyzes a directory as one deterministic report", () => {
    const report = analyzeGovernanceFiles([FIXTURES], { includeModels: true });
    expect(report.summary.files).toBe(8);
    expect(report.summary.contracts).toBe(8);
    expect(report.files.map((file) => file.file)).toEqual([...report.files.map((file) => file.file)].sort());
  });
});
