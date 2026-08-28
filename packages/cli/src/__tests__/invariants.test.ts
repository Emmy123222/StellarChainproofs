import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

const CLI_BIN = path.resolve(__dirname, "../../dist/cli.js");
const SPEC_PATH = path.resolve(__dirname, "../../../../examples/invariant-specs/vault.cpinv.json");
const SECURE_CONTRACT = path.resolve(
  __dirname,
  "../../../../examples/contracts/invariants/SecureVaultInvariants.sol",
);
const VULNERABLE_CONTRACT = path.resolve(
  __dirname,
  "../../../../examples/contracts/invariants/VulnerableVaultInvariants.sol",
);
const TEMP_DIR = path.resolve(__dirname, "../../__tests_temp_invariants__");

function run(cmd: string, opts: { allowFailure?: boolean } = {}): string {
  try {
    return execSync(`node ${CLI_BIN} ${cmd}`, { encoding: "utf-8" });
  } catch (err) {
    if (opts.allowFailure) {
      return (err as { stdout?: string }).stdout ?? "";
    }
    throw err;
  }
}

describe("CLI invariants command", () => {
  beforeAll(() => {
    fs.mkdirSync(TEMP_DIR, { recursive: true });
  });

  afterAll(() => {
    fs.rmSync(TEMP_DIR, { recursive: true, force: true });
  });

  it("validate: reports a well-formed spec as valid", () => {
    const output = run(`invariants validate ${SPEC_PATH} --format json`);
    const parsed = JSON.parse(output);
    expect(parsed.valid).toBe(true);
    expect(parsed.diagnostics).toEqual([]);
  });

  it("validate: reports a malformed spec as invalid with a non-zero exit code", () => {
    const badSpec = path.join(TEMP_DIR, "bad.cpinv.json");
    fs.writeFileSync(badSpec, JSON.stringify({ name: "x" }), "utf-8");

    expect(() => run(`invariants validate ${badSpec} --format json`)).toThrow();
    const output = run(`invariants validate ${badSpec} --format json`, { allowFailure: true });
    const parsed = JSON.parse(output);
    expect(parsed.valid).toBe(false);
    expect(parsed.diagnostics.length).toBeGreaterThan(0);
  });

  it("check: passes every invariant against the secure fixture (JSON output, deterministic)", () => {
    const output = run(`invariants check ${SPEC_PATH} ${SECURE_CONTRACT} --format json`);
    const report = JSON.parse(output);
    expect(report.summary.fail).toBe(0);
    expect(report.summary.pass).toBe(report.summary.total);
    expect(report.resultSchemaVersion).toBe("1.0.0");
  });

  it("check: fails and returns exit code 1 against the vulnerable fixture", () => {
    expect(() => run(`invariants check ${SPEC_PATH} ${VULNERABLE_CONTRACT} --format json`)).toThrow();
    const output = run(`invariants check ${SPEC_PATH} ${VULNERABLE_CONTRACT} --format json`, {
      allowFailure: true,
    });
    const report = JSON.parse(output);
    expect(report.summary.fail).toBeGreaterThan(0);
  });

  it("explain: prints the resolved condition for a known invariant id", () => {
    const output = run(`invariants explain ${SPEC_PATH} VAULT-ACCESS-001`);
    expect(output).toContain("VAULT-ACCESS-001");
    expect(output).toContain("owner");
  });

  it("init: scaffolds a spec that validates cleanly", () => {
    const target = path.join(TEMP_DIR, "scaffold.cpinv.json");
    run(`invariants init ${target} --contract Vault`);
    expect(fs.existsSync(target)).toBe(true);

    const output = run(`invariants validate ${target} --format json`);
    expect(JSON.parse(output).valid).toBe(true);
  });

  it("init: refuses to overwrite an existing file without --force", () => {
    const target = path.join(TEMP_DIR, "no-overwrite.cpinv.json");
    fs.writeFileSync(target, "{}", "utf-8");
    expect(() => run(`invariants init ${target}`)).toThrow();
  });

  it("migrate: reports a current-schema spec as already up to date", () => {
    const output = run(`invariants migrate ${SPEC_PATH}`);
    expect(output).toContain("already on schema");
  });

  it("migrate: upgrades a legacy spec and writes it with --output", () => {
    const legacy = path.join(TEMP_DIR, "legacy.json");
    fs.writeFileSync(
      legacy,
      JSON.stringify({
        version: "0.9",
        name: "legacy",
        rules: [
          {
            id: "R1",
            kind: "access",
            title: "t",
            severity: "high",
            contract: "Foo",
            function: "bar",
            expr: "msg.sender == owner",
          },
        ],
      }),
      "utf-8",
    );
    const migrated = path.join(TEMP_DIR, "migrated.cpinv.json");
    run(`invariants migrate ${legacy} --output ${migrated}`);

    const output = run(`invariants validate ${migrated} --format json`);
    expect(JSON.parse(output).valid).toBe(true);
  });
});
