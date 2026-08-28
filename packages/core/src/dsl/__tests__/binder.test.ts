import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { parseInvariantSpecFile } from "../spec-parser";
import { checkInvariants } from "../evaluator";

function writeTemp(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf-8");
  return file;
}

const MULTI_FILE_DIR = path.resolve(__dirname, "../../../../../examples/contracts/multi-file");

const OVERLOADED_CONTRACT = `
pragma solidity ^0.8.20;
contract Token {
  function transfer(address to) public returns (bool) {
    return true;
  }

  function transfer(address to, uint256 amount) public returns (bool) {
    require(amount > 0, "zero amount");
    return true;
  }
}
`;

function specFor(invariant: Record<string, unknown>): string {
  return JSON.stringify({
    schemaVersion: "1.0.0",
    name: "overload-test",
    invariants: [invariant],
  });
}

describe("binder — overloaded functions", () => {
  let dir: string;
  let contractFile: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpinv-overload-"));
    contractFile = writeTemp(dir, "Token.sol", OVERLOADED_CONTRACT);
  });

  it("reports DSL014 (ambiguous overload) when scope.signature is omitted", async () => {
    const specFile = writeTemp(
      dir,
      "ambiguous.cpinv.json",
      specFor({
        id: "INV-1",
        kind: "arithmetic",
        title: "amount positive",
        severity: "medium",
        scope: { contract: "Token", function: "transfer" },
        condition: "amount > 0",
      }),
    );
    const { spec } = parseInvariantSpecFile(specFile);
    const report = await checkInvariants(spec!, { targets: [contractFile] });
    expect(report.diagnostics.some((d) => d.code === "DSL014")).toBe(true);
    expect(report.results[0].status).toBe("error");
  });

  it("resolves the correct overload when scope.signature disambiguates it", async () => {
    const specFile = writeTemp(
      dir,
      "disambiguated.cpinv.json",
      specFor({
        id: "INV-2",
        kind: "arithmetic",
        title: "amount positive",
        severity: "medium",
        scope: { contract: "Token", function: "transfer", signature: "transfer(address,uint256)" },
        condition: "amount > 0",
      }),
    );
    const { spec } = parseInvariantSpecFile(specFile);
    const report = await checkInvariants(spec!, { targets: [contractFile] });
    expect(report.diagnostics.some((d) => d.code === "DSL014")).toBe(false);
    expect(report.results[0].status).toBe("pass");
  });

  it("reports DSL014 with the available signatures when given an unknown signature", async () => {
    const specFile = writeTemp(
      dir,
      "bad-signature.cpinv.json",
      specFor({
        id: "INV-3",
        kind: "arithmetic",
        title: "x",
        severity: "medium",
        scope: { contract: "Token", function: "transfer", signature: "transfer(uint256)" },
        condition: "true",
      }),
    );
    const { spec } = parseInvariantSpecFile(specFile);
    const report = await checkInvariants(spec!, { targets: [contractFile] });
    const diag = report.diagnostics.find((d) => d.code === "DSL014");
    expect(diag?.message).toContain("transfer(address)");
    expect(diag?.message).toContain("transfer(address,uint256)");
  });

  it("reports DSL012 for an unknown contract", async () => {
    const specFile = writeTemp(
      dir,
      "unknown-contract.cpinv.json",
      specFor({
        id: "INV-4",
        kind: "access",
        title: "x",
        severity: "medium",
        scope: { contract: "DoesNotExist", function: "foo" },
        condition: "true",
      }),
    );
    const { spec } = parseInvariantSpecFile(specFile);
    const report = await checkInvariants(spec!, { targets: [contractFile] });
    expect(report.diagnostics.some((d) => d.code === "DSL012")).toBe(true);
  });

  it("reports DSL013 for an unknown function", async () => {
    const specFile = writeTemp(
      dir,
      "unknown-function.cpinv.json",
      specFor({
        id: "INV-5",
        kind: "access",
        title: "x",
        severity: "medium",
        scope: { contract: "Token", function: "doesNotExist" },
        condition: "true",
      }),
    );
    const { spec } = parseInvariantSpecFile(specFile);
    const report = await checkInvariants(spec!, { targets: [contractFile] });
    expect(report.diagnostics.some((d) => d.code === "DSL013")).toBe(true);
  });
});

describe("binder — multi-file inheritance", () => {
  it("resolves a function only present via inheritance and reports its true source file", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpinv-inherit-"));
    const specFile = writeTemp(
      dir,
      "authorize.cpinv.json",
      specFor({
        id: "INV-UPGRADE-001",
        kind: "access",
        title: "Upgrade authorization must be owner-gated",
        severity: "critical",
        scope: { contract: "UpgradeableVault", function: "_authorizeUpgrade" },
        condition: "msg.sender == _owner",
      }),
    );
    const { spec } = parseInvariantSpecFile(specFile);
    const report = await checkInvariants(spec!, {
      targets: [path.join(MULTI_FILE_DIR, "UpgradeableVault.sol")],
    });

    // BaseVault's _authorizeUpgrade hook is empty — no guard exists anywhere,
    // even though the function is only reachable through inheritance.
    expect(report.results[0].status).toBe("fail");
    expect(report.diagnostics.some((d) => d.code === "DSL012" || d.code === "DSL013")).toBe(false);
  });
});
