import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  GovernanceConfigError,
  loadGovernanceConfigFile,
  migrateGovernanceConfig,
  resolveGovernanceLimits,
  validateGovernanceConfig,
} from "../config";

describe("governance configuration", () => {
  it("migrates legacy v0 names to the versioned v1 shape", () => {
    const migrated = migrateGovernanceConfig({
      version: 0,
      maxFileSize: 1234,
      maxIssues: 9,
      detectors: ["CP-GOV-008", "CP-GOV-001", "CP-GOV-008"],
      includeModels: true,
    });
    expect(migrated.config).toEqual({
      schemaVersion: 1,
      limits: { maxSourceBytes: 1234, maxFindings: 9 },
      includeModels: true,
      includeRules: ["CP-GOV-001", "CP-GOV-008"],
    });
    expect(migrated.diagnostics[0].message).toContain("v0 to v1");
  });

  it("validates rule IDs, overlap, booleans and positive bounded integers", () => {
    expect(() => validateGovernanceConfig({ schemaVersion: 1, includeRules: ["CP-GOV-999"] }))
      .toThrow(GovernanceConfigError);
    expect(() => validateGovernanceConfig({
      schemaVersion: 1, includeRules: ["CP-GOV-001"], excludeRules: ["CP-GOV-001"],
    })).toThrow(/overlap/);
    expect(() => validateGovernanceConfig({ schemaVersion: 1, includeModels: "yes" }))
      .toThrow(/boolean/);
    expect(() => resolveGovernanceLimits({ maxFiles: 0 })).toThrow(/positive safe integer/);
    expect(() => resolveGovernanceLimits({ maxFiles: Number.MAX_VALUE })).toThrow(/positive safe integer/);
    expect(() => validateGovernanceConfig({ schemaVersion: 1, secretToken: "not echoed" }))
      .toThrow("configuration contains unknown field secretToken");
    expect(() => validateGovernanceConfig({ schemaVersion: 1, limits: { maxDepth: 3 } }))
      .toThrow("limits contains unknown field maxDepth");
  });

  it("distinguishes malformed JSON and unreadable files without including file contents", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-config-"));
    const corrupt = path.join(directory, "corrupt.json");
    fs.writeFileSync(corrupt, '{"schemaVersion": 1, "secret": "TOKEN",', "utf8");
    expect(() => loadGovernanceConfigFile(corrupt)).toThrow("configuration file contains invalid JSON");
    try {
      loadGovernanceConfigFile(path.join(directory, "missing.json"));
    } catch (error) {
      expect(error).toBeInstanceOf(GovernanceConfigError);
      expect((error as Error).message).toMatch(/could not be read \(ENOENT\)/);
      expect((error as Error).message).not.toContain(directory);
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("rejects unsupported future schemas", () => {
    expect(() => validateGovernanceConfig({ schemaVersion: 2 })).toThrow(/unsupported/);
  });
});
