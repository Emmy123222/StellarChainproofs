import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

const CLI_BIN = path.resolve(__dirname, "../../dist/cli.js");
const FIXTURE_PATH = path.resolve(__dirname, "../../../../examples/contracts/DeFiSystemFixture.sol");
const TEMP_DIR = path.resolve(__dirname, "../../__tests_temp_tm__");

describe("CLI threat-model command", () => {
  beforeAll(() => {
    fs.mkdirSync(TEMP_DIR, { recursive: true });
  });

  afterAll(() => {
    fs.rmSync(TEMP_DIR, { recursive: true, force: true });
  });

  it("should generate threat model in markdown format", () => {
    const output = execSync(`node ${CLI_BIN} threat-model ${FIXTURE_PATH} --format markdown`, {
      encoding: "utf-8",
    });

    expect(output).toContain("# ChainProof Smart Contract Threat Model");
    expect(output).toContain("DeFiSystemFixture");
    expect(output).toContain("Executive Summary");
  });

  it("should generate threat model in json format", () => {
    const output = execSync(`node ${CLI_BIN} threat-model ${FIXTURE_PATH} --format json`, {
      encoding: "utf-8",
    });

    const parsed = JSON.parse(output);
    expect(parsed.version).toBe("0.1.0");
    expect(parsed.summary).toBeDefined();
    expect(parsed.threats.length).toBeGreaterThan(0);
  });

  it("should support user-provided assumptions overrides", () => {
    const assumptionsFile = path.join(TEMP_DIR, "assumptions.json");
    const assumptionsData = {
      threatStatuses: {
        "thr-reentrancy-defisystemfixture": "mitigated",
      },
    };

    fs.writeFileSync(assumptionsFile, JSON.stringify(assumptionsData), "utf-8");

    const output = execSync(
      `node ${CLI_BIN} threat-model ${FIXTURE_PATH} --assumptions ${assumptionsFile} --format json`,
      { encoding: "utf-8" }
    );

    const parsed = JSON.parse(output);
    const targetThreat = parsed.threats.find((t: any) => t.id === "thr-reentrancy-defisystemfixture");
    expect(targetThreat).toBeDefined();
    expect(targetThreat.status).toBe("mitigated");
  });
});
