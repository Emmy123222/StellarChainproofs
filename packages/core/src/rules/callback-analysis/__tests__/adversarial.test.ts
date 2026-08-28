import * as fc from "fast-check";
import * as path from "path";
import { buildImportGraph, buildMergedContractViews } from "../../../ast/import-graph";
import { parseSolidity } from "../../../ast/parser";
import { detectCallbackReentrancy } from "../rule";
import { walkWithLoopContext } from "../ast-walk";

function viewFromSource(source: string, fileName: string, contractName: string) {
  const filePath = path.resolve(fileName);
  const { ast, error } = parseSolidity(source, filePath);
  if (error || !ast) return null;
  const graph = buildImportGraph([filePath]);
  graph.files.set(filePath, { filePath, absolutePath: filePath, source, ast });
  return buildMergedContractViews(graph).find((v) => v.name === contractName) ?? null;
}

describe("walkWithLoopContext — bounded traversal", () => {
  it("stops within the given node budget and reports incompletion", () => {
    const wide = { type: "Block", statements: Array.from({ length: 50 }, () => ({ type: "ExpressionStatement" })) };
    let visited = 0;
    const completed = walkWithLoopContext(wide as never, () => {
      visited += 1;
    }, 10);

    expect(completed).toBe(false);
    expect(visited).toBeLessThanOrEqual(10);
  });

  it("completes normally when the budget is not exceeded", () => {
    const small = { type: "Block", statements: [{ type: "ExpressionStatement" }] };
    let visited = 0;
    const completed = walkWithLoopContext(small as never, () => {
      visited += 1;
    }, 1000);

    expect(completed).toBe(true);
    expect(visited).toBeGreaterThan(0);
  });

  it("is cycle-safe against a self-referential node", () => {
    const cyclic: Record<string, unknown> = { type: "Block" };
    cyclic.self = cyclic;

    let visited = 0;
    const completed = walkWithLoopContext(cyclic as never, () => {
      visited += 1;
    });

    expect(completed).toBe(true);
    expect(visited).toBe(1);
  });
});

describe("detectCallbackReentrancy — adversarial / bounded input", () => {
  it("completes quickly on a synthetically large contract with many functions and loops", () => {
    const fnCount = 150;
    const functions = Array.from({ length: fnCount }, (_, i) => `
      function batch${i}(address to, uint256[] calldata ids) external {
        for (uint256 j = 0; j < ids.length; j++) {
          ownerOf[ids[j]] = to;
          _checkOnERC721Received(msg.sender, address(0), to, ids[j]);
        }
      }
    `).join("\n");

    const source = `
      pragma solidity ^0.8.0;
      interface IERC721Receiver {
        function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
      }
      contract Large {
        mapping(uint256 => address) public ownerOf;
        ${functions}
        function _checkOnERC721Received(address operator, address from, address to, uint256 tokenId) internal {
          IERC721Receiver(to).onERC721Received(operator, from, tokenId, "");
        }
      }
    `;

    const view = viewFromSource(source, "large.sol", "Large");
    expect(view).not.toBeNull();

    const start = Date.now();
    const findings = detectCallbackReentrancy(view!.node, view!.source, view!.file, { contractView: view! });
    const elapsedMs = Date.now() - start;

    expect(elapsedMs).toBeLessThan(15_000);
    // Every batchN function loops over an uncapped array while triggering the callback.
    expect(findings.filter((f) => f.id === "CP-CB-BATCH").length).toBe(fnCount);
  });

  it("does not throw on deeply nested loops around a callback trigger", () => {
    const source = `
      pragma solidity ^0.8.0;
      interface IERC721Receiver {
        function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
      }
      contract Nested {
        mapping(uint256 => address) public ownerOf;
        function batch(address to, uint256[] calldata outer, uint256[] calldata inner) external {
          for (uint256 i = 0; i < outer.length; i++) {
            for (uint256 j = 0; j < inner.length; j++) {
              ownerOf[inner[j]] = to;
              _checkOnERC721Received(msg.sender, address(0), to, inner[j]);
            }
          }
        }
        function _checkOnERC721Received(address operator, address from, address to, uint256 tokenId) internal {
          IERC721Receiver(to).onERC721Received(operator, from, tokenId, "");
        }
      }
    `;
    const view = viewFromSource(source, "nested.sol", "Nested");
    expect(view).not.toBeNull();

    expect(() =>
      detectCallbackReentrancy(view!.node, view!.source, view!.file, { contractView: view! }),
    ).not.toThrow();
  });
});

describe("detectCallbackReentrancy — property: never throws, always deterministic", () => {
  it("[property] randomized guard/ordering combinations never crash and are order-independent across repeated runs", () => {
    fc.assert(
      fc.property(
        fc.boolean(), // hasGuardModifier
        fc.boolean(), // writeBeforeCall
        fc.boolean(), // writeAfterCall
        (hasGuardModifier, writeBeforeCall, writeAfterCall) => {
          const source = `
            pragma solidity ^0.8.0;
            interface IERC721Receiver {
              function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
            }
            contract Fuzzed {
              mapping(address => uint256) public balanceOf;
              ${hasGuardModifier ? 'modifier nonReentrant() { _; }' : ""}
              function safeMint(address to, uint256 tokenId) external ${hasGuardModifier ? "nonReentrant" : ""} {
                ${writeBeforeCall ? "balanceOf[to] += 1;" : ""}
                _checkOnERC721Received(msg.sender, address(0), to, tokenId);
                ${writeAfterCall ? "balanceOf[to] += 1;" : ""}
              }
              function _checkOnERC721Received(address operator, address from, address to, uint256 tokenId) internal {
                IERC721Receiver(to).onERC721Received(operator, from, tokenId, "");
              }
            }
          `;

          const view = viewFromSource(source, "fuzzed.sol", "Fuzzed");
          if (!view) return true;

          const first = detectCallbackReentrancy(view.node, view.source, view.file, { contractView: view });
          const second = detectCallbackReentrancy(view.node, view.source, view.file, { contractView: view });
          return JSON.stringify(first) === JSON.stringify(second);
        },
      ),
      { numRuns: 30 },
    );
  });
});
