import { parseSolidity } from "../../../ast/parser";
import { visit } from "../../../ast/parser";
import type { ASTNode } from "../../../types";
import {
  detectERC165Support,
  detectImplementedReceiverHooks,
  findCallSiteLoopContext,
  findCallbackTriggerSites,
} from "../interface-detection";
import type { AnalyzableFunction } from "../types";

function functionsFromSource(source: string): AnalyzableFunction[] {
  const { ast, error } = parseSolidity(source, "fixture.sol");
  expect(error).toBeUndefined();
  const functions: AnalyzableFunction[] = [];
  visit(ast!, {
    FunctionDefinition(node: ASTNode) {
      const fn = node as { name?: string | null };
      if (fn.name) functions.push({ name: fn.name, node, source });
    },
  });
  return functions;
}

function fn(source: string, name: string): AnalyzableFunction {
  const found = functionsFromSource(source).find((f) => f.name === name);
  if (!found) throw new Error(`function "${name}" not found`);
  return found;
}

describe("findCallbackTriggerSites", () => {
  it("detects a direct named invocation of a standard receiver hook", () => {
    const source = `
      pragma solidity ^0.8.0;
      interface IERC721Receiver { function onERC721Received(address,address,uint256,bytes calldata) external returns (bytes4); }
      contract C {
        function mint(address to) external {
          IERC721Receiver(to).onERC721Received(msg.sender, address(0), 1, "");
        }
      }
    `;
    const triggers = findCallbackTriggerSites(fn(source, "mint"));
    expect(triggers).toHaveLength(1);
    expect(triggers[0].standard).toBe("ERC721");
    expect(triggers[0].kind).toBe("receiver-hook");
    expect(triggers[0].evidence.confidence).toBe("high");
  });

  it("detects a low-level .call() carrying a standard hook's selector", () => {
    const source = `
      pragma solidity ^0.8.0;
      interface IERC721Receiver { function onERC721Received(address,address,uint256,bytes calldata) external returns (bytes4); }
      contract C {
        function mint(address to) external {
          to.call(abi.encodeWithSelector(IERC721Receiver.onERC721Received.selector, msg.sender, address(0), 1, ""));
        }
      }
    `;
    const triggers = findCallbackTriggerSites(fn(source, "mint"));
    expect(triggers).toHaveLength(1);
    expect(triggers[0].evidence.kind).toBe("low-level-selector");
    expect(triggers[0].evidence.confidence).toBe("medium");
  });

  it("detects a custom callback registration resolved through a registry mapping", () => {
    const source = `
      pragma solidity ^0.8.0;
      interface IHook { function onDeposit(address, uint256) external; }
      contract C {
        mapping(address => address) public callbackHandlers;
        function deposit(address token, uint256 amount) external {
          IHook(callbackHandlers[token]).onDeposit(token, amount);
        }
      }
    `;
    const triggers = findCallbackTriggerSites(fn(source, "deposit"));
    expect(triggers).toHaveLength(1);
    expect(triggers[0].standard).toBe("CUSTOM");
    expect(triggers[0].kind).toBe("custom-hook");
  });

  it("falls back to the helper-name heuristic when no direct call site is found", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function _checkOnERC721Received(address a, address b, address to, uint256 id) internal {
          // indirection this analysis doesn't unwind further
          _dispatch(a, b, to, id);
        }
        function _dispatch(address, address, address, uint256) internal {}
      }
    `;
    const triggers = findCallbackTriggerSites(fn(source, "_checkOnERC721Received"));
    expect(triggers).toHaveLength(1);
    expect(triggers[0].evidence.kind).toBe("helper-name");
  });

  it("does not flag an unrelated function with no callback signature match", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function transfer(address to, uint256 amount) external returns (bool) {
          return true;
        }
      }
    `;
    expect(findCallbackTriggerSites(fn(source, "transfer"))).toHaveLength(0);
  });

  it("reports the enclosing loop for a batch-invoked callback", () => {
    const source = `
      pragma solidity ^0.8.0;
      interface IERC721Receiver { function onERC721Received(address,address,uint256,bytes calldata) external returns (bytes4); }
      contract C {
        function batch(address to, uint256[] calldata ids) external {
          for (uint256 i = 0; i < ids.length; i++) {
            IERC721Receiver(to).onERC721Received(msg.sender, address(0), ids[i], "");
          }
        }
      }
    `;
    const triggers = findCallbackTriggerSites(fn(source, "batch"));
    expect(triggers).toHaveLength(1);
    expect(triggers[0].loopNode).not.toBeNull();
  });
});

describe("findCallSiteLoopContext", () => {
  it("returns the loop node when the call is inside a for-loop body", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function batch(uint256[] calldata ids) external {
          for (uint256 i = 0; i < ids.length; i++) {
            _process(ids[i]);
          }
        }
        function _process(uint256) internal {}
      }
    `;
    expect(findCallSiteLoopContext(fn(source, "batch"), "_process")).not.toBeNull();
  });

  it("returns null when the call is not inside any loop", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function once() external { _process(1); }
        function _process(uint256) internal {}
      }
    `;
    expect(findCallSiteLoopContext(fn(source, "once"), "_process")).toBeNull();
  });
});

describe("detectImplementedReceiverHooks", () => {
  it("recognizes a function matching a known receiver-hook signature", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
          return this.onERC721Received.selector;
        }
      }
    `;
    const map = detectImplementedReceiverHooks(functionsFromSource(source));
    expect(map.has("onERC721Received")).toBe(true);
    expect(map.get("onERC721Received")?.[0].confidence).toBe("high");
  });

  it("does not match a same-named function with the wrong arity", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function onERC721Received(address to) external pure returns (address) { return to; }
      }
    `;
    const map = detectImplementedReceiverHooks(functionsFromSource(source));
    expect(map.get("onERC721Received")?.[0].confidence).toBe("medium");
  });
});

describe("detectERC165Support", () => {
  it("returns null when supportsInterface is not implemented", () => {
    const source = `pragma solidity ^0.8.0; contract C { function foo() external {} }`;
    expect(detectERC165Support(functionsFromSource(source))).toBeNull();
  });

  it("reports high confidence when a known interface ID is referenced", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
          return interfaceId == 0x150b7a02;
        }
      }
    `;
    const evidence = detectERC165Support(functionsFromSource(source));
    expect(evidence?.confidence).toBe("high");
  });
});
