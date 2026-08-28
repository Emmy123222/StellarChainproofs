import { parseSolidity, visit } from "../../../ast/parser";
import type { ASTNode } from "../../../types";
import {
  atomicInvariantGuard,
  eoaOnlyGuard,
  manualMutexGuard,
  reentrancyGuardModifier,
  trustedReceiverGuard,
} from "../guards";
import type { AnalyzableFunction } from "../types";

function fn(source: string, name: string): AnalyzableFunction {
  const { ast, error } = parseSolidity(source, "fixture.sol");
  expect(error).toBeUndefined();
  let found: AnalyzableFunction | undefined;
  visit(ast!, {
    FunctionDefinition(node: ASTNode) {
      const f = node as { name?: string | null };
      if (f.name === name) found = { name, node, source };
    },
  });
  if (!found) throw new Error(`function "${name}" not found`);
  return found;
}

function lineOf(source: string, needle: string): number {
  const idx = source.indexOf(needle);
  return source.slice(0, idx).split("\n").length;
}

describe("reentrancyGuardModifier", () => {
  it("matches a nonReentrant-style modifier", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        modifier nonReentrant() { _; }
        function f() external nonReentrant {}
      }
    `;
    expect(reentrancyGuardModifier(fn(source, "f"))).not.toBeNull();
  });

  it("returns null when no modifier is applied", () => {
    const source = `pragma solidity ^0.8.0; contract C { function f() external {} }`;
    expect(reentrancyGuardModifier(fn(source, "f"))).toBeNull();
  });
});

describe("manualMutexGuard", () => {
  it("recognizes a hand-rolled require(!locked) / locked = true / locked = false mutex", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        bool private locked;
        function f() external {
          require(!locked, "reentrant");
          locked = true;
          _external();
          locked = false;
        }
        function _external() internal {}
      }
    `;
    const edgeLine = lineOf(source, "_external();");
    expect(manualMutexGuard(fn(source, "f"), edgeLine)).not.toBeNull();
  });

  it("returns null when the lock is never released", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        bool private locked;
        function f() external {
          require(!locked, "reentrant");
          locked = true;
          _external();
        }
        function _external() internal {}
      }
    `;
    const edgeLine = lineOf(source, "_external();");
    expect(manualMutexGuard(fn(source, "f"), edgeLine)).toBeNull();
  });

  it("returns null when there is no guard at all", () => {
    const source = `pragma solidity ^0.8.0; contract C { function f() external { _external(); } function _external() internal {} }`;
    expect(manualMutexGuard(fn(source, "f"), 1)).toBeNull();
  });
});

describe("trustedReceiverGuard", () => {
  it("recognizes a require() checking the target against a trust-named mapping", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        mapping(address => bool) public trustedReceivers;
        function f(address to) external {
          require(trustedReceivers[to], "not trusted");
          _external(to);
        }
        function _external(address) internal {}
      }
    `;
    const edgeLine = lineOf(source, "_external(to);");
    expect(trustedReceiverGuard(fn(source, "f"), edgeLine)).not.toBeNull();
  });

  it("returns null when there is no trust-check before the callback", () => {
    const source = `pragma solidity ^0.8.0; contract C { function f(address to) external { _external(to); } function _external(address) internal {} }`;
    expect(trustedReceiverGuard(fn(source, "f"), 1)).toBeNull();
  });
});

describe("eoaOnlyGuard", () => {
  it("recognizes an isContract() check before the callback", () => {
    const source = `
      pragma solidity ^0.8.0;
      library Address { function isContract(address) internal view returns (bool) {} }
      contract C {
        using Address for address;
        function f(address to) external {
          require(!to.isContract(), "no contracts");
          _external(to);
        }
        function _external(address) internal {}
      }
    `;
    const edgeLine = lineOf(source, "_external(to);");
    expect(eoaOnlyGuard(fn(source, "f"), edgeLine)).not.toBeNull();
  });

  it("recognizes a to.code.length == 0 check before the callback", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function f(address to) external {
          require(to.code.length == 0, "no contracts");
          _external(to);
        }
        function _external(address) internal {}
      }
    `;
    const edgeLine = lineOf(source, "_external(to);");
    expect(eoaOnlyGuard(fn(source, "f"), edgeLine)).not.toBeNull();
  });

  it("does not mistake an unrelated array-length loop bound for an EOA check", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function f(address to, uint256[] calldata ids) external {
          for (uint256 i = 0; i < ids.length; i++) {
            _external(to);
          }
        }
        function _external(address) internal {}
      }
    `;
    const edgeLine = lineOf(source, "_external(to);");
    expect(eoaOnlyGuard(fn(source, "f"), edgeLine)).toBeNull();
  });
});

describe("atomicInvariantGuard", () => {
  it("recognizes a post-callback balance/fee repayment invariant", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function flashLoan(address receiver, uint256 amount, uint256 fee) external {
          uint256 balanceBefore = 100;
          _external(receiver);
          uint256 balanceAfter = 100;
          require(balanceAfter >= balanceBefore + amount + fee, "not repaid");
        }
        function _external(address) internal {}
      }
    `;
    const edgeLine = lineOf(source, "_external(receiver);");
    expect(atomicInvariantGuard(fn(source, "flashLoan"), edgeLine)).not.toBeNull();
  });

  it("returns null when there is no post-callback check at all", () => {
    const source = `
      pragma solidity ^0.8.0;
      contract C {
        function flashLoan(address receiver) external {
          _external(receiver);
        }
        function _external(address) internal {}
      }
    `;
    const edgeLine = lineOf(source, "_external(receiver);");
    expect(atomicInvariantGuard(fn(source, "flashLoan"), edgeLine)).toBeNull();
  });
});
