import * as path from "path";
import { scan } from "../../../scanner";
import { parseSolidity } from "../../../ast/parser";
import { detectCallbackReentrancy } from "../rule";
import { buildFunctionCallGraph } from "../../call-graph";
import { buildCallbackGraph } from "../callback-graph";
import { detectInFixture, FIXTURES_DIR, viewFromFixture } from "./helpers";

describe("detectCallbackReentrancy — CP-CB-CEI (incomplete state before callback)", () => {
  it("flags a receiver-hook callback fired before the accounted balance is finalized", () => {
    const findings = detectInFixture("VulnerableERC721Vault.sol", "VulnerableERC721Vault");
    const cei = findings.filter((f) => f.id === "CP-CB-CEI");

    expect(cei).toHaveLength(1);
    expect(cei[0].severity).toBe("critical");
    expect(cei[0].description).toContain("balanceOf");
    expect(cei[0].description).toContain("ERC-721");
    expect(cei[0].callPath).toEqual(["safeMint", "_checkOnERC721Received"]);
    expect(cei[0].confidence).toBeDefined();
    expect(cei[0].evidence?.length).toBeGreaterThan(0);
  });

  it("does not flag the same shape when state is finalized before the callback", () => {
    const findings = detectInFixture("GuardedERC721Vault.sol", "GuardedERC721Vault");
    expect(findings.filter((f) => f.id === "CP-CB-CEI")).toHaveLength(0);
  });

  it("flags a flash-mint callback with no post-callback repayment invariant", () => {
    const findings = detectInFixture("FlashMintVulnerable.sol", "FlashMintVulnerable");
    const cei = findings.filter((f) => f.id === "CP-CB-CEI");

    expect(cei).toHaveLength(1);
    expect(cei[0].title).toContain("Flash-loan");
  });

  it("does not flag a flash-mint callback guarded by a repayment invariant check", () => {
    const findings = detectInFixture("FlashMintGuarded.sol", "FlashMintGuarded");
    expect(findings.filter((f) => f.id === "CP-CB-CEI")).toHaveLength(0);
  });
});

describe("detectCallbackReentrancy — CP-CB-CROSSFN (cross-function reentrancy via callback)", () => {
  it("flags a sibling function reading state left stale across the callback", () => {
    const findings = detectInFixture("ERC721CrossFunctionVault.sol", "ERC721CrossFunctionVault");
    const crossFn = findings.filter((f) => f.id === "CP-CB-CROSSFN");

    expect(crossFn.length).toBeGreaterThan(0);
    expect(crossFn[0].description).toContain("claimBonus");
    expect(crossFn[0].callPath).toContain("claimBonus");
  });
});

describe("detectCallbackReentrancy — CP-CB-READONLY (read-only reentrancy via callback)", () => {
  it("flags view functions exposing a share price finalized only after the callback", () => {
    const findings = detectInFixture("ERC777VaultDeposit.sol", "ERC777VaultDeposit");
    const readOnly = findings.filter((f) => f.id === "CP-CB-READONLY");

    const sibNames = readOnly.map((f) => f.callPath?.[f.callPath.length - 1]);
    expect(sibNames).toContain("pricePerShare");
    expect(sibNames).toContain("bonus");
    expect(readOnly.every((f) => f.severity === "high")).toBe(true);
  });
});

describe("detectCallbackReentrancy — CP-CB-BATCH (unbounded batch callback)", () => {
  it("flags a batch callback loop with no explicit length cap", () => {
    const findings = detectInFixture("UnboundedBatchMint.sol", "UnboundedBatchMint");
    const batch = findings.filter((f) => f.id === "CP-CB-BATCH");

    expect(batch).toHaveLength(1);
    expect(batch[0].severity).toBe("medium");
    expect(batch[0].description).toContain("batchMint");
  });

  it("does not flag a batch loop guarded by an explicit length cap", () => {
    const findings = detectInFixture("BoundedBatchMint.sol", "BoundedBatchMint");
    expect(findings.filter((f) => f.id === "CP-CB-BATCH")).toHaveLength(0);
  });
});

describe("detectCallbackReentrancy — CP-CB-SPOOF (callback spoofing)", () => {
  it("flags a receiver-hook implementation that trusts msg.sender-less input", () => {
    const findings = detectInFixture("SpoofableERC1155Receiver.sol", "SpoofableERC1155Receiver");
    const spoof = findings.filter((f) => f.id === "CP-CB-SPOOF");

    expect(spoof).toHaveLength(1);
    expect(spoof[0].severity).toBe("high");
    expect(spoof[0].confidence).toBe("high");
  });

  it("does not flag a receiver-hook implementation that checks the caller", () => {
    const findings = detectInFixture("SecureERC1155Receiver.sol", "SecureERC1155Receiver");
    expect(findings.filter((f) => f.id === "CP-CB-SPOOF")).toHaveLength(0);
  });
});

describe("detectCallbackReentrancy — nested, multi-standard callbacks", () => {
  it("produces zero findings when both callbacks are guarded and CEI-ordered", () => {
    const findings = detectInFixture("NestedCallbackVault.sol", "NestedCallbackVault");
    expect(findings).toHaveLength(0);
  });

  it("still resolves both distinct callback edges from the shared entry function", () => {
    const view = viewFromFixture("NestedCallbackVault.sol", "NestedCallbackVault");
    const callGraph = buildFunctionCallGraph(view);
    const callbackGraph = buildCallbackGraph(view, callGraph);
    const edges = callbackGraph.byEntryFunction.get("depositAndMintReceipt") ?? [];

    expect(edges.map((e) => e.standard).sort()).toEqual(["ERC721", "ERC777"]);
  });
});

describe("detectCallbackReentrancy — degenerate input", () => {
  it("returns no findings without a contractView", () => {
    const source = `pragma solidity ^0.8.0; contract Empty {}`;
    const { ast } = parseSolidity(source, "empty.sol");
    expect(detectCallbackReentrancy(ast!, source, "empty.sol")).toEqual([]);
  });

  it("returns no findings for a contract with no functions", () => {
    const view = viewFromFixture("SecureERC1155Receiver.sol", "SecureERC1155Receiver");
    const emptyView = { ...view, members: view.members.filter((m) => m.kind !== "function") };
    expect(detectCallbackReentrancy(emptyView.node, emptyView.source, emptyView.file, { contractView: emptyView })).toEqual([]);
  });
});

describe("detectCallbackReentrancy — determinism", () => {
  it("produces identical, deterministically-ordered output across repeated runs", () => {
    const view = viewFromFixture("VulnerableERC721Vault.sol", "VulnerableERC721Vault");
    const first = detectCallbackReentrancy(view.node, view.source, view.file, { contractView: view });
    const second = detectCallbackReentrancy(view.node, view.source, view.file, { contractView: view });
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

describe("detectCallbackReentrancy — scanner integration", () => {
  // The callback analysis needs a MergedContractView (built from the
  // import graph), which @chainproof/core's scanner only constructs for
  // files that use import directives — so the scanner-level fixture here
  // is the imported-interface variant, not the single-file one used by
  // the direct-API tests above.
  it("is enabled in the built-in scanner and surfaces CP-CB-CEI end to end", async () => {
    const file = path.join(FIXTURES_DIR, "VaultWithImportedReceiver.sol");
    const result = await scan({
      targets: [file],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });

    const fileResult = result.files.find((f) => f.file.endsWith("VaultWithImportedReceiver.sol"));
    const finding = fileResult?.findings.find((f) => f.id === "CP-CB-CEI");
    expect(finding?.severity).toBe("critical");
  });

  it("does not regress parsing when scanning a directory containing the callback fixtures", async () => {
    const result = await scan({
      targets: [FIXTURES_DIR],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });

    expect(result.files.every((f) => !f.parseError)).toBe(true);
  });
});
