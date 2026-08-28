import * as path from "path";
import { parseInvariantSpecFile } from "../spec-parser";
import { checkInvariants } from "../evaluator";
import type { InvariantResult, InvariantSpec } from "../types";

const FIXTURES_DIR = path.resolve(__dirname, "../../../../../examples/contracts/invariants");
const SPEC_PATH = path.resolve(__dirname, "../../../../../examples/invariant-specs/vault.cpinv.json");

function statusOf(results: InvariantResult[], id: string): string {
  return results.find((r) => r.id === id)?.status ?? "<missing>";
}

describe("invariant DSL evaluator — vault fixture pair", () => {
  let spec: InvariantSpec;

  beforeAll(() => {
    const { spec: parsed, diagnostics } = parseInvariantSpecFile(SPEC_PATH);
    expect(diagnostics.filter((d) => d.severity === "error")).toEqual([]);
    expect(parsed).toBeDefined();
    spec = parsed!;
  });

  it("passes every invariant against the secure fixture", async () => {
    const report = await checkInvariants(spec, {
      targets: [path.join(FIXTURES_DIR, "SecureVaultInvariants.sol")],
    });

    const failing = report.results.filter((r) => r.status !== "pass");
    expect(failing).toEqual([]);
    expect(report.summary.pass).toBe(spec.invariants.length);
    expect(report.summary.fail).toBe(0);
  });

  it("fails every invariant against the vulnerable fixture", async () => {
    const report = await checkInvariants(spec, {
      targets: [path.join(FIXTURES_DIR, "VulnerableVaultInvariants.sol")],
    });

    for (const decl of spec.invariants) {
      expect(statusOf(report.results, decl.id)).toBe("fail");
    }
    expect(report.summary.fail).toBe(spec.invariants.length);
  });

  it("produces byte-identical reports across repeated runs (determinism)", async () => {
    const targets = [path.join(FIXTURES_DIR, "SecureVaultInvariants.sol")];
    const [a, b] = await Promise.all([
      checkInvariants(spec, { targets }),
      checkInvariants(spec, { targets }),
    ]);

    // Strip fields that legitimately vary run-to-run (timestamps/durations).
    const normalize = (r: typeof a) => ({
      ...r,
      generatedAt: "",
      results: r.results.map((res) => ({ ...res, durationMs: 0 })),
    });
    expect(normalize(a)).toEqual(normalize(b));
  });

  it("results are always ordered by invariant id, not declaration order", async () => {
    const report = await checkInvariants(spec, {
      targets: [path.join(FIXTURES_DIR, "SecureVaultInvariants.sol")],
    });
    const ids = report.results.map((r) => r.id);
    const sorted = [...ids].sort();
    expect(ids).toEqual(sorted);
  });

  it("evidence and counterexamples carry concrete source locations", async () => {
    const passReport = await checkInvariants(spec, {
      targets: [path.join(FIXTURES_DIR, "SecureVaultInvariants.sol")],
    });
    const accessPass = passReport.results.find((r) => r.id === "VAULT-ACCESS-001")!;
    expect(accessPass.evidence[0].locations[0].line).toBeGreaterThan(0);
    expect(accessPass.evidence[0].locations[0].file).toContain("SecureVaultInvariants.sol");

    const failReport = await checkInvariants(spec, {
      targets: [path.join(FIXTURES_DIR, "VulnerableVaultInvariants.sol")],
    });
    const orderFail = failReport.results.find((r) => r.id === "VAULT-ORDER-001")!;
    expect(orderFail.counterexample).toBeDefined();
  });

  it("respects a tiny step budget by reporting a bounded timeout instead of hanging", async () => {
    const report = await checkInvariants(spec, {
      targets: [path.join(FIXTURES_DIR, "SecureVaultInvariants.sol")],
      budget: { maxStepsPerInvariant: 1 },
    });
    expect(report.results.length).toBe(spec.invariants.length);
    expect(report.results.some((r) => r.status === "timeout")).toBe(true);
  });

  it("throws for an empty target list rather than silently no-op'ing", async () => {
    await expect(checkInvariants(spec, { targets: [] })).rejects.toThrow();
  });
});
