import * as path from "path";
import * as fs from "fs";
import {
  generateThreatModel,
  extractThreatModel,
  prioritizeThreats,
  loadAssumptions,
  mergeAssumptions,
  generateMarkdownThreatModel,
  generateJSONThreatModel,
} from "../index";

const fixturePath = path.resolve(__dirname, "../../../../../examples/contracts/DeFiSystemFixture.sol");

describe("Smart Contract Threat Modeling Engine", () => {
  
  test("Should extract assets, agents, entrypoints, and threats from DeFiSystemFixture AST", () => {
    const model = extractThreatModel([fixturePath]);

    expect(model.assets.length).toBeGreaterThan(0);
    expect(model.agents.length).toBeGreaterThan(0);
    expect(model.attackSurface.entryPoints.length).toBeGreaterThan(0);
    expect(model.threats.length).toBeGreaterThan(0);

    // Verify Asset Identification
    const logicAsset = model.assets.find((a) => a.id === "asset-logic-defisystemfixture");
    const oracleAsset = model.assets.find((a) => a.type === "oracle");
    const tokenAsset = model.assets.find((a) => a.type === "token");

    expect(logicAsset).toBeDefined();
    expect(oracleAsset).toBeDefined();
    expect(tokenAsset).toBeDefined();
    expect(logicAsset!.definedIn).toBe("DeFiSystemFixture");

    // Verify Attack Surface & Trust Boundaries
    const entrySignatures = model.attackSurface.entryPoints.map((ep) => ep.signature);
    expect(entrySignatures).toContain("deposit()");
    expect(entrySignatures).toContain("withdraw(uint256)");
    expect(entrySignatures).toContain("initialize(address)");

    const extBoundary = model.attackSurface.trustBoundaries.find((b) => b.id === "tb-external-boundary");
    expect(extBoundary).toBeDefined();
    expect(extBoundary!.components).toContain("DeFiSystemFixture.deposit");
  });

  test("Should calculate risk priorities and sort threats descending by risk score", () => {
    const rawModel = extractThreatModel([fixturePath]);
    const prioritized = prioritizeThreats(rawModel.threats);

    expect(prioritized.length).toBeGreaterThan(0);
    
    // The list should be sorted from highest score to lowest score
    for (let i = 0; i < prioritized.length - 1; i++) {
      expect(prioritized[i].riskScore).toBeGreaterThanOrEqual(prioritized[i + 1].riskScore);
    }

    // High risk threats (e.g. Oracle / AccessControl / Reentrancy) should rank high
    const topThreat = prioritized[0];
    expect(["critical", "high"]).toContain(topThreat.severity);
  });

  test("Should load and merge team assumptions and track mitigation statuses", () => {
    const rawModel = extractThreatModel([fixturePath]);
    const baseModel = {
      version: "0.1.0",
      timestamp: new Date().toISOString(),
      targets: [fixturePath],
      assets: rawModel.assets,
      agents: rawModel.agents,
      attackSurface: rawModel.attackSurface,
      threats: prioritizeThreats(rawModel.threats),
      summary: {
        totalThreats: rawModel.threats.length,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        mitigatedCount: 0,
        unmitigatedCount: rawModel.threats.length,
      },
    };

    const mockAssumptions = {
      customAssets: [
        {
          id: "asset-custom-reserve",
          name: "Liquidity Pool Custom Reserve",
          type: "token" as const,
          description: "Custom token reserves for system liquidity.",
          value: "high" as const,
          definedIn: "DeFiSystemFixture",
        },
      ],
      threatStatuses: {
        "thr-reentrancy-defisystemfixture": "mitigated" as const,
      },
      mitigations: {
        "thr-reentrancy-defisystemfixture": ["Implemented OpenZeppelin ReentrancyGuard."],
      },
    };

    const merged = mergeAssumptions(baseModel, mockAssumptions);

    // Verify custom asset was added
    expect(merged.assets.some((a) => a.id === "asset-custom-reserve")).toBe(true);

    // Verify threat status was updated
    const targetThreat = merged.threats.find((t) => t.id === "thr-reentrancy-defisystemfixture");
    expect(targetThreat).toBeDefined();
    expect(targetThreat!.status).toBe("mitigated");
    expect(targetThreat!.mitigations).toContain("Implemented OpenZeppelin ReentrancyGuard.");

    // Verify summary counts updated
    expect(merged.summary.mitigatedCount).toBe(1);
  });

  test("Should handle edge cases like invalid target input paths gracefully", async () => {
    const invalidPath = path.resolve(__dirname, "./non_existent_file.sol");
    await expect(generateThreatModel({ targets: [invalidPath] })).rejects.toThrow();
  });

  test("Should generate markdown and json report outputs correctly", async () => {
    const model = await generateThreatModel({ targets: [fixturePath] });

    const mdReport = generateMarkdownThreatModel(model);
    expect(mdReport).toContain("# ChainProof Smart Contract Threat Model");
    expect(mdReport).toContain("DeFiSystemFixture");
    expect(mdReport).toContain("Executive Summary");
    expect(mdReport).toContain("flowchart TB"); // Mermaid verification
    expect(mdReport).toContain("=== Threat Model Architecture Map ==="); // ASCII verification

    const jsonReport = generateJSONThreatModel(model);
    const parsed = JSON.parse(jsonReport);
    expect(parsed.version).toBe("0.1.0");
    expect(parsed.summary).toBeDefined();
  });
});
