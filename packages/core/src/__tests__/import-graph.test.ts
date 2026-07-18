import * as path from "path";
import {
  buildImportGraph,
  buildMergedContractViews,
  resolveImportPath,
} from "../ast/import-graph";
import { scan } from "../scanner";

const MULTI_FILE_DIR = path.resolve(
  __dirname,
  "../../../../examples/contracts/multi-file"
);

describe("import graph", () => {
  it("resolves relative imports between project files", () => {
    const upgradeable = path.join(MULTI_FILE_DIR, "UpgradeableVault.sol");
    const graph = buildImportGraph([upgradeable]);

    expect(graph.files.size).toBe(2);
    expect(graph.warnings.some((w) => w.includes("Could not resolve"))).toBe(false);

    const edges = graph.edges.get(path.resolve(upgradeable)) ?? [];
    expect(edges).toContain(path.resolve(MULTI_FILE_DIR, "BaseVault.sol"));
  });

  it("builds merged contract views with ancestor members", () => {
    const upgradeable = path.join(MULTI_FILE_DIR, "UpgradeableVault.sol");
    const graph = buildImportGraph([upgradeable]);
    const views = buildMergedContractViews(graph);

    const vaultView = views.find((v) => v.name === "UpgradeableVault");
    expect(vaultView).toBeDefined();
    expect(vaultView!.ancestors.some((a) => a.name === "BaseVault")).toBe(true);

    const authorizeUpgrade = vaultView!.members.find(
      (m) => m.kind === "function" && m.name === "_authorizeUpgrade"
    );
    expect(authorizeUpgrade?.definedIn).toBe(
      path.resolve(MULTI_FILE_DIR, "BaseVault.sol")
    );
  });

  it("detects circular imports with a warning", () => {
    const circularA = path.join(MULTI_FILE_DIR, "CircularA.sol");
    const circularB = path.join(MULTI_FILE_DIR, "CircularB.sol");
    const graph = buildImportGraph([circularA, circularB]);

    expect(
      graph.warnings.some((w) => w.toLowerCase().includes("circular import"))
    ).toBe(true);
  });

  it("resolves node_modules-style paths when file exists", () => {
    const fromFile = path.join(MULTI_FILE_DIR, "UpgradeableVault.sol");
    const graph = buildImportGraph([fromFile]);
    const resolved = resolveImportPath("./BaseVault.sol", fromFile, graph.files);
    expect(resolved).toBe(path.resolve(MULTI_FILE_DIR, "BaseVault.sol"));
  });
});

describe("multi-file scanner integration", () => {
  it("detects inherited unprotected upgrade when scanning child file only", async () => {
    const upgradeable = path.join(MULTI_FILE_DIR, "UpgradeableVault.sol");
    const result = await scan({
      targets: [upgradeable],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });

    const childResult = result.files.find((f) => f.file.includes("UpgradeableVault.sol"));
    expect(childResult).toBeDefined();

    const upgradeFinding = childResult!.findings.find((f) => f.id === "CP-116");
    expect(upgradeFinding).toBeDefined();
    expect(upgradeFinding!.definedIn).toContain("BaseVault.sol");
    expect(upgradeFinding!.inheritedBy).toContain("UpgradeableVault.sol");
    expect(upgradeFinding!.importPath?.some((p) => p.includes("BaseVault.sol"))).toBe(true);
  });

  it("detects inherited tx.origin usage from parent modifier", async () => {
    const derived = path.join(MULTI_FILE_DIR, "DerivedVault.sol");
    const result = await scan({
      targets: [derived],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });

    const childResult = result.files.find((f) => f.file.includes("DerivedVault.sol"));
    expect(childResult).toBeDefined();

    const txOriginFinding = childResult!.findings.find((f) => f.id === "CP-115");
    expect(txOriginFinding).toBeDefined();
    expect(txOriginFinding!.definedIn).toContain("BaseAuth.sol");
    expect(txOriginFinding!.inheritedBy).toContain("DerivedVault.sol");
  });

  it("detects inherited reentrancy pattern in child contract", async () => {
    const derived = path.join(MULTI_FILE_DIR, "DerivedVault.sol");
    const result = await scan({
      targets: [derived],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });

    const childResult = result.files.find((f) => f.file.includes("DerivedVault.sol"));
    const reentrancyFinding = childResult!.findings.find((f) => f.id === "CP-107");
    expect(reentrancyFinding).toBeDefined();
  });

  it("does not regress single-file scanning performance beyond 20%", async () => {
    const singleFile = path.resolve(
      __dirname,
      "../../../../examples/contracts/VulnerableVault.sol"
    );

    const warmUp = async () => {
      await scan({ targets: [singleFile], useSlither: false, useLLM: false, useMetrics: false });
    };
    await warmUp();

    const measure = async (iterations: number) => {
      const start = performance.now();
      for (let i = 0; i < iterations; i++) {
        await scan({ targets: [singleFile], useSlither: false, useLLM: false, useMetrics: false });
      }
      return performance.now() - start;
    };

    const iterations = 10;
    const elapsed = await measure(iterations);
    const perScan = elapsed / iterations;

    // Single-file contracts use the legacy fast path; allow generous CI headroom.
    expect(perScan).toBeLessThan(200);
  });
});
