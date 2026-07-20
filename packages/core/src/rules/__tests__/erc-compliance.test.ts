import * as path from "path";
import * as fs from "fs";
import { parseSolidity } from "../../ast/parser";
import {
  detectERCStandard,
  checkERC20Compliance,
  checkERC721Compliance,
  checkERC1155Compliance,
} from "../erc-compliance";
import { scan } from "../../scanner";

const EXAMPLES_DIR = path.resolve(__dirname, "../../../../../examples/contracts/erc");

describe("ERC Compliance Rules", () => {
  describe("detectERCStandard", () => {
    it("detects ERC20 standard", () => {
      const source = fs.readFileSync(path.join(EXAMPLES_DIR, "NonCompliantERC20.sol"), "utf-8");
      const { ast } = parseSolidity(source, "NonCompliantERC20.sol");
      expect(ast).not.toBeNull();
      expect(detectERCStandard(ast!)).toBe("ERC20");
    });

    it("detects ERC721 standard", () => {
      const source = fs.readFileSync(path.join(EXAMPLES_DIR, "NonCompliantERC721.sol"), "utf-8");
      const { ast } = parseSolidity(source, "NonCompliantERC721.sol");
      expect(ast).not.toBeNull();
      expect(detectERCStandard(ast!)).toBe("ERC721");
    });

    it("detects ERC1155 standard", () => {
      const source = fs.readFileSync(path.join(EXAMPLES_DIR, "NonCompliantERC1155.sol"), "utf-8");
      const { ast } = parseSolidity(source, "NonCompliantERC1155.sol");
      expect(ast).not.toBeNull();
      expect(detectERCStandard(ast!)).toBe("ERC1155");
    });
  });

  describe("checkERC20Compliance", () => {
    it("identifies non-compliant ERC20 issues", () => {
      const file = path.join(EXAMPLES_DIR, "NonCompliantERC20.sol");
      const source = fs.readFileSync(file, "utf-8");
      const { ast } = parseSolidity(source, file);
      const findings = checkERC20Compliance(ast!, source, file);

      const ruleIds = findings.map((f) => f.id);
      expect(ruleIds).toContain("CP-ERC20-EVENTS");
      expect(ruleIds).toContain("CP-ERC20-RETURN");
      expect(ruleIds).toContain("CP-ERC20-DECIMALS");
      expect(ruleIds).toContain("CP-ERC20-APPROVE-RACE");
    });
  });

  describe("checkERC721Compliance", () => {
    it("identifies non-compliant ERC721 issues", () => {
      const file = path.join(EXAMPLES_DIR, "NonCompliantERC721.sol");
      const source = fs.readFileSync(file, "utf-8");
      const { ast } = parseSolidity(source, file);
      const findings = checkERC721Compliance(ast!, source, file);

      const ruleIds = findings.map((f) => f.id);
      expect(ruleIds).toContain("CP-ERC721-UNRESTRICTED-MINT");
      expect(ruleIds).toContain("CP-ERC721-REENTRANCY");
      expect(ruleIds).toContain("CP-ERC721-ERC165");
    });
  });

  describe("checkERC1155Compliance", () => {
    it("identifies non-compliant ERC1155 issues", () => {
      const file = path.join(EXAMPLES_DIR, "NonCompliantERC1155.sol");
      const source = fs.readFileSync(file, "utf-8");
      const { ast } = parseSolidity(source, file);
      const findings = checkERC1155Compliance(ast!, source, file);

      const ruleIds = findings.map((f) => f.id);
      expect(ruleIds).toContain("CP-ERC1155-EVENTS");
      expect(ruleIds).toContain("CP-ERC1155-REENTRANCY");
    });
  });

  describe("scanner integration", () => {
    it("scans non-compliant ERC directory and reports findings", async () => {
      const result = await scan({
        targets: [EXAMPLES_DIR],
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      });

      expect(result.files.length).toBeGreaterThanOrEqual(3);
      expect(result.summary.total).toBeGreaterThan(0);
    });
  });
});
