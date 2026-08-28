import { parseSolidity, visit } from "../../../ast/parser";
import type { ASTNode } from "../../../types";
import { detectCallbackSpoofing } from "../spoofing";
import type { AnalyzableFunction } from "../types";

function functionsAndStateVars(source: string): { functions: AnalyzableFunction[]; stateVarNames: Set<string> } {
  const { ast, error } = parseSolidity(source, "fixture.sol");
  expect(error).toBeUndefined();
  const functions: AnalyzableFunction[] = [];
  const stateVarNames = new Set<string>();
  visit(ast!, {
    FunctionDefinition(node: ASTNode) {
      const fn = node as { name?: string | null };
      if (fn.name) functions.push({ name: fn.name, node, source });
    },
    StateVariableDeclaration(node: ASTNode) {
      const decl = node as { variables?: Array<{ name?: string }> };
      for (const v of decl.variables ?? []) if (v.name) stateVarNames.add(v.name);
    },
  });
  return { functions, stateVarNames };
}

describe("detectCallbackSpoofing", () => {
  it("flags a standard hook that mutates sensitive state without a sender check", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        mapping(address => uint256) public creditedBalance;
        function onERC1155Received(address, address from, uint256, uint256 value, bytes calldata) external returns (bytes4) {
          creditedBalance[from] += value;
          return this.onERC1155Received.selector;
        }
      }
    `;
    const { functions, stateVarNames } = functionsAndStateVars(source);
    const hits = detectCallbackSpoofing(functions, stateVarNames);
    expect(hits).toHaveLength(1);
    expect(hits[0].isStandardHook).toBe(true);
    expect(hits[0].sensitiveVars).toContain("creditedBalance");
  });

  it("does not flag the same hook when msg.sender is checked", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        address public token;
        mapping(address => uint256) public creditedBalance;
        function onERC1155Received(address, address from, uint256, uint256 value, bytes calldata) external returns (bytes4) {
          require(msg.sender == token, "untrusted");
          creditedBalance[from] += value;
          return this.onERC1155Received.selector;
        }
      }
    `;
    const { functions, stateVarNames } = functionsAndStateVars(source);
    expect(detectCallbackSpoofing(functions, stateVarNames)).toHaveLength(0);
  });

  it("does not flag the same hook when guarded by an auth-named modifier", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        mapping(address => uint256) public creditedBalance;
        modifier onlyToken() { _; }
        function onERC1155Received(address, address from, uint256, uint256 value, bytes calldata) external onlyToken returns (bytes4) {
          creditedBalance[from] += value;
          return this.onERC1155Received.selector;
        }
      }
    `;
    const { functions, stateVarNames } = functionsAndStateVars(source);
    expect(detectCallbackSpoofing(functions, stateVarNames)).toHaveLength(0);
  });

  it("flags a custom hook-named function matching the naming convention", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        mapping(address => uint256) public debt;
        function onLoanRepaidHook(address borrower, uint256 amount) external {
          debt[borrower] -= amount;
        }
      }
    `;
    const { functions, stateVarNames } = functionsAndStateVars(source);
    const hits = detectCallbackSpoofing(functions, stateVarNames);
    expect(hits).toHaveLength(1);
    expect(hits[0].isStandardHook).toBe(false);
  });

  it("does not flag an ordinary function with no hook-shaped name", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        mapping(address => uint256) public balances;
        function withdraw(uint256 amount) external {
          balances[msg.sender] -= amount;
        }
      }
    `;
    const { functions, stateVarNames } = functionsAndStateVars(source);
    expect(detectCallbackSpoofing(functions, stateVarNames)).toHaveLength(0);
  });

  it("does not flag a hook-shaped function that touches no sensitive state", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        uint256 public lastCallbackAt;
        function onSomeHook() external {
          lastCallbackAt = block.timestamp;
        }
      }
    `;
    const { functions, stateVarNames } = functionsAndStateVars(source);
    expect(detectCallbackSpoofing(functions, stateVarNames)).toHaveLength(0);
  });
});
