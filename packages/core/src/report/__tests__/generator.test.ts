import {
  generateMarkdownReport,
  generateJSONReport,
  generateTableReport,
} from "../generator";
import type { ScanResult } from "../../types";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const MOCK_RESULT: ScanResult = {
  version: "0.1.0",
  timestamp: "2026-01-01T00:00:00.000Z",
  files: [
    {
      file: "contracts/test.sol",
      findings: [
        {
          id: "CP-107",
          swcId: "SWC-107",
          title: "Reentrancy vulnerability",
          description: "External call before state update.",
          recommendation: "Use Checks-Effects-Interactions pattern.",
          severity: "critical",
          file: "contracts/test.sol",
          line: 42,
          snippet: "msg.sender.call{value: amount}(\"\");",
        },
        {
          id: "CP-115",
          swcId: "SWC-115",
          title: "Use of tx.origin for authentication",
          description: "tx.origin used as auth guard.",
          recommendation: "Replace with msg.sender.",
          severity: "high",
          file: "contracts/test.sol",
          line: 20,
        },
      ],
      gasHints: [
        {
          file: "contracts/test.sol",
          line: 10,
          description: "Potential storage read inside a loop. Cache in memory.",
          estimatedSaving: "~2000 gas per iteration",
          snippet: "for (uint256 i = 0; i < arr.length; i++)",
        },
      ],
      slitherRan: false,
    },
  ],
  summary: {
    critical: 1,
    high: 1,
    medium: 0,
    low: 0,
    info: 0,
    gas: 1,
    total: 3,
  },
};

const CLEAN_RESULT: ScanResult = {
  version: "0.1.0",
  timestamp: "2026-01-01T00:00:00.000Z",
  files: [],
  summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, gas: 0, total: 0 },
};

const PARSE_ERROR_RESULT: ScanResult = {
  version: "0.1.0",
  timestamp: "2026-01-01T00:00:00.000Z",
  files: [
    {
      file: "contracts/broken.sol",
      findings: [],
      gasHints: [],
      slitherRan: false,
      parseError: "Parse error in contracts/broken.sol: unexpected token",
    },
  ],
  summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, gas: 0, total: 0 },
};

// ─── generateMarkdownReport ───────────────────────────────────────────────────

describe("generateMarkdownReport", () => {
  it("returns a non-empty string", () => {
    const md = generateMarkdownReport(MOCK_RESULT);
    expect(typeof md).toBe("string");
    expect(md.length).toBeGreaterThan(0);
  });

  it("includes the executive summary table", () => {
    const md = generateMarkdownReport(MOCK_RESULT);
    expect(md).toContain("Executive Summary");
    expect(md).toContain("Critical");
    expect(md).toContain("High");
  });

  it("includes the finding title and ID", () => {
    const md = generateMarkdownReport(MOCK_RESULT);
    expect(md).toContain("Reentrancy vulnerability");
    expect(md).toContain("CP-107");
  });

  it("includes the SWC registry link", () => {
    const md = generateMarkdownReport(MOCK_RESULT);
    expect(md).toContain("SWC-107");
    expect(md).toContain("swcregistry.io");
  });

  it("warns about critical or high severity findings", () => {
    const md = generateMarkdownReport(MOCK_RESULT);
    expect(md).toContain("critical or high severity");
  });

  it("renders call path, confidence, evidence, and assumptions when present", () => {
    const withEvidence: ScanResult = {
      ...CLEAN_RESULT,
      files: [
        {
          file: "vault.sol",
          findings: [
            {
              id: "CP-CB-CEI",
              title: "Incomplete state update before ERC-721 callback",
              description: "d",
              recommendation: "r",
              severity: "critical",
              file: "vault.sol",
              line: 5,
              callPath: ["safeMint", "_checkOnERC721Received"],
              confidence: "high",
              evidence: [{ description: "Direct call to onERC721Received(...)", line: 12 }],
              assumptions: ["Assumed satisfied: recipient is untrusted"],
            },
          ],
          gasHints: [],
          slitherRan: false,
        },
      ],
      summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, gas: 0, total: 1 },
    };
    const md = generateMarkdownReport(withEvidence);
    expect(md).toContain("safeMint → _checkOnERC721Received");
    expect(md).toContain("**Confidence:** high");
    expect(md).toContain("Direct call to onERC721Received(...)");
    expect(md).toContain("Assumed satisfied: recipient is untrusted");
  });

  it("does not render evidence/assumptions/call-path sections when absent", () => {
    const md = generateMarkdownReport(MOCK_RESULT);
    expect(md).not.toContain("**Evidence**");
    expect(md).not.toContain("**Assumptions**");
    expect(md).not.toContain("**Call path:**");
  });

  it("does not warn when there are no critical/high findings", () => {
    const safe: ScanResult = {
      ...CLEAN_RESULT,
      files: [
        {
          file: "safe.sol",
          findings: [
            {
              id: "CP-LOW",
              title: "Minor issue",
              description: "d",
              recommendation: "r",
              severity: "low",
              file: "safe.sol",
              line: 1,
            },
          ],
          gasHints: [],
          slitherRan: false,
        },
      ],
      summary: { critical: 0, high: 0, medium: 0, low: 1, info: 0, gas: 0, total: 1 },
    };
    const md = generateMarkdownReport(safe);
    expect(md).not.toContain("critical or high severity");
  });

  it("renders parse errors with an error notice", () => {
    const md = generateMarkdownReport(PARSE_ERROR_RESULT);
    expect(md).toContain("Parse error");
    expect(md).toContain("contracts/broken.sol");
  });

  it("includes the gas hints section when hints are present", () => {
    const md = generateMarkdownReport(MOCK_RESULT);
    expect(md).toContain("Gas Optimization Hints");
    expect(md).toContain("storage read inside a loop");
  });

  it("renders correctly for a clean result with no files", () => {
    const md = generateMarkdownReport(CLEAN_RESULT);
    expect(md).toContain("ChainProof Security Audit Report");
    expect(md).toContain("0");
  });
});

// ─── generateJSONReport ───────────────────────────────────────────────────────

describe("generateJSONReport", () => {
  it("produces valid JSON", () => {
    const json = generateJSONReport(MOCK_RESULT);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("round-trips the scan result without data loss", () => {
    const json = generateJSONReport(MOCK_RESULT);
    const parsed: ScanResult = JSON.parse(json);
    expect(parsed.version).toBe("0.1.0");
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.files[0].findings[0].id).toBe("CP-107");
  });

  it("serialises the empty result to valid JSON", () => {
    const json = generateJSONReport(CLEAN_RESULT);
    const parsed = JSON.parse(json);
    expect(parsed.summary.total).toBe(0);
  });
});

// ─── generateTableReport ─────────────────────────────────────────────────────

describe("generateTableReport", () => {
  it("returns a non-empty string", () => {
    const table = generateTableReport(MOCK_RESULT);
    expect(typeof table).toBe("string");
    expect(table.length).toBeGreaterThan(0);
  });

  it("contains the audit report header", () => {
    const table = generateTableReport(MOCK_RESULT);
    expect(table).toContain("CHAINPROOF AUDIT REPORT");
  });

  it("includes the finding title", () => {
    const table = generateTableReport(MOCK_RESULT);
    expect(table).toContain("Reentrancy vulnerability");
  });

  it("shows summary counts", () => {
    const table = generateTableReport(MOCK_RESULT);
    expect(table).toContain("Critical");
    expect(table).toContain("1");
  });
});
