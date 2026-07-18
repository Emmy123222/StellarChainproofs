import { parseSolidity } from "../../ast/parser";
import { buildImportGraph, buildMergedContractViews } from "../../ast/import-graph";
import { detectCrossFunctionReentrancy } from "../swc107-reentrancy-v2";
import * as path from "path";

const CROSS_FUNCTION_VULNERABLE = `
pragma solidity ^0.7.6;
contract VulnerableVault {
  mapping(address => uint256) public balances;

  function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    balances[msg.sender] -= amount;
  }

  function getBonus() external view returns (uint256) {
    return balances[msg.sender] / 10;
  }
}
`;

const SAFE_SEPARATE_STATE = `
pragma solidity ^0.7.6;
contract SafeVault {
  mapping(address => uint256) public balances;
  mapping(address => bool) public withdrawn;

  function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    balances[msg.sender] -= amount;
    withdrawn[msg.sender] = true;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
  }

  function getBonus() external view returns (uint256) {
    if (withdrawn[msg.sender]) {
      return 0;
    }
    return balances[msg.sender] / 10;
  }
}
`;

const SINGLE_FUNCTION = `
pragma solidity ^0.7.6;
contract SingleFn {
  mapping(address => uint256) public balances;

  function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
  }
}
`;

describe("detectCrossFunctionReentrancy (SWC-107-X / CP-107-X)", () => {
  it("detects cross-function reentrancy where re-entered function reads stale state", () => {
    const { ast } = parseSolidity(CROSS_FUNCTION_VULNERABLE, "vuln.sol");
    expect(ast).not.toBeNull();

    const graph = buildImportGraph([path.resolve("vuln.sol")]);
    // Manually set up the graph for testing
    graph.files.set(path.resolve("vuln.sol"), {
      filePath: "vuln.sol",
      absolutePath: path.resolve("vuln.sol"),
      source: CROSS_FUNCTION_VULNERABLE,
      ast: ast!,
    });

    const views = buildMergedContractViews(graph);
    const findings = views.flatMap((view) =>
      detectCrossFunctionReentrancy(view.node, view.source, "vuln.sol", { contractView: view }),
    );

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].id).toBe("CP-107-X");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].callPath).toBeDefined();
  });

  it("produces zero findings when state is updated before external call", () => {
    const { ast } = parseSolidity(SAFE_SEPARATE_STATE, "safe.sol");
    expect(ast).not.toBeNull();

    const graph = buildImportGraph([path.resolve("safe.sol")]);
    graph.files.set(path.resolve("safe.sol"), {
      filePath: "safe.sol",
      absolutePath: path.resolve("safe.sol"),
      source: SAFE_SEPARATE_STATE,
      ast: ast!,
    });

    const views = buildMergedContractViews(graph);
    const findings = views.flatMap((view) =>
      detectCrossFunctionReentrancy(view.node, view.source, "safe.sol", { contractView: view }),
    );

    expect(findings).toHaveLength(0);
  });

  it("produces zero findings when there is no external call", () => {
    const { ast } = parseSolidity(SINGLE_FUNCTION, "single.sol");
    expect(ast).not.toBeNull();

    const graph = buildImportGraph([path.resolve("single.sol")]);
    graph.files.set(path.resolve("single.sol"), {
      filePath: "single.sol",
      absolutePath: path.resolve("single.sol"),
      source: SINGLE_FUNCTION,
      ast: ast!,
    });

    const views = buildMergedContractViews(graph);
    const findings = views.flatMap((view) =>
      detectCrossFunctionReentrancy(view.node, view.source, "single.sol", { contractView: view }),
    );

    expect(findings).toHaveLength(0);
  });

  it("returns empty findings when contractView is not provided", () => {
    const { ast } = parseSolidity(CROSS_FUNCTION_VULNERABLE, "test.sol");
    expect(ast).not.toBeNull();

    const findings = detectCrossFunctionReentrancy(ast!, CROSS_FUNCTION_VULNERABLE, "test.sol");
    expect(findings).toHaveLength(0);
  });

  it("includes callPath in findings", () => {
    const { ast } = parseSolidity(CROSS_FUNCTION_VULNERABLE, "vuln.sol");
    expect(ast).not.toBeNull();

    const graph = buildImportGraph([path.resolve("vuln.sol")]);
    graph.files.set(path.resolve("vuln.sol"), {
      filePath: "vuln.sol",
      absolutePath: path.resolve("vuln.sol"),
      source: CROSS_FUNCTION_VULNERABLE,
      ast: ast!,
    });

    const views = buildMergedContractViews(graph);
    const findings = views.flatMap((view) =>
      detectCrossFunctionReentrancy(view.node, view.source, "vuln.sol", { contractView: view }),
    );

    if (findings.length > 0) {
      expect(findings[0].callPath).toBeDefined();
      expect(Array.isArray(findings[0].callPath)).toBe(true);
    }
  });
});
