import * as path from "path";
import { buildFunctionCallGraph } from "../../call-graph";
import { buildCallbackGraph } from "../callback-graph";
import { buildImportGraph, buildMergedContractViews } from "../../../ast/import-graph";
import { parseSolidity } from "../../../ast/parser";
import { viewFromFixture } from "./helpers";

describe("buildCallbackGraph", () => {
  it("resolves a multi-hop callback edge with the correct viaPath and standard/kind", () => {
    const view = viewFromFixture("VulnerableERC721Vault.sol", "VulnerableERC721Vault");
    const callGraph = buildFunctionCallGraph(view);
    const graph = buildCallbackGraph(view, callGraph);

    const edges = graph.byEntryFunction.get("safeMint") ?? [];
    expect(edges).toHaveLength(1);
    expect(edges[0].triggerFunction).toBe("_checkOnERC721Received");
    expect(edges[0].viaPath).toEqual(["safeMint", "_checkOnERC721Received"]);
    expect(edges[0].standard).toBe("ERC721");
    expect(edges[0].kind).toBe("receiver-hook");
    expect(edges[0].isBatch).toBe(false);
  });

  it("marks a loop-wrapped indirect callback as batch and unbounded when uncapped", () => {
    const view = viewFromFixture("UnboundedBatchMint.sol", "UnboundedBatchMint");
    const callGraph = buildFunctionCallGraph(view);
    const graph = buildCallbackGraph(view, callGraph);

    const edges = graph.byEntryFunction.get("batchMint") ?? [];
    expect(edges).toHaveLength(1);
    expect(edges[0].isBatch).toBe(true);
    expect(edges[0].isUnboundedBatch).toBe(true);
  });

  it("marks the same batch shape as bounded once an explicit length cap is present", () => {
    const view = viewFromFixture("BoundedBatchMint.sol", "BoundedBatchMint");
    const callGraph = buildFunctionCallGraph(view);
    const graph = buildCallbackGraph(view, callGraph);

    const edges = graph.byEntryFunction.get("batchMint") ?? [];
    expect(edges).toHaveLength(1);
    expect(edges[0].isBatch).toBe(true);
    expect(edges[0].isUnboundedBatch).toBe(false);
  });

  it("produces no edges for a contract with no callback-shaped functions", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract PlainToken {
        mapping(address => uint256) public balances;
        function transfer(address to, uint256 amount) external returns (bool) {
          balances[msg.sender] -= amount;
          balances[to] += amount;
          return true;
        }
      }
    `;
    const filePath = path.resolve("plain-token.sol");
    const { ast } = parseSolidity(source, filePath);
    const graphInput = buildImportGraph([filePath]);
    graphInput.files.set(filePath, { filePath, absolutePath: filePath, source, ast: ast! });
    const [view] = buildMergedContractViews(graphInput);

    const callGraph = buildFunctionCallGraph(view);
    const graph = buildCallbackGraph(view, callGraph);
    expect(graph.edges).toHaveLength(0);
  });

  it("does not report truncation for an ordinary, small contract", () => {
    const view = viewFromFixture("VulnerableERC721Vault.sol", "VulnerableERC721Vault");
    const callGraph = buildFunctionCallGraph(view);
    const graph = buildCallbackGraph(view, callGraph);
    expect(graph.truncated).toBe(false);
  });
});
