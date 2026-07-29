import * as fs from "fs";
import * as path from "path";
import { parseSolidity } from "../../ast/parser";
import { scan } from "../../scanner";
import { detectVaultInflation } from "../cp122-vault-inflation";

const FIXTURES_DIR = path.resolve(__dirname, "../../../../../examples/contracts");

function detectInFixture(fileName: string) {
  const file = path.join(FIXTURES_DIR, fileName);
  const source = fs.readFileSync(file, "utf-8");
  const { ast, error } = parseSolidity(source, file);
  expect(error).toBeUndefined();
  expect(ast).not.toBeNull();
  return detectVaultInflation(ast!, source, file);
}

describe("CP-122 vault share-price inflation", () => {
  it("flags a live-balance vault with naive first-depositor share math", () => {
    const findings = detectInFixture("VulnerableInflationVault.sol");

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "CP-122",
      severity: "high",
    });
    expect(findings[0].recommendation).toContain("dead shares");
    expect(findings[0].recommendation).toContain("internal accounting");
    expect(findings[0].snippet).toContain("assets * totalSupply / totalAssets()");
  });

  it("does not flag a vault protected by minimum-liquidity dead shares", () => {
    expect(detectInFixture("ProtectedInflationVault.sol")).toEqual([]);
  });

  it("does not flag unrelated proportional arithmetic", () => {
    expect(detectInFixture("UnrelatedRatioMath.sol")).toEqual([]);
  });

  it("is enabled in the built-in scanner", async () => {
    const file = path.join(FIXTURES_DIR, "VulnerableInflationVault.sol");
    const result = await scan({
      targets: [file],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });

    const finding = result.files[0].findings.find((item) => item.id === "CP-122");
    expect(finding?.severity).toBe("high");
  });
});
