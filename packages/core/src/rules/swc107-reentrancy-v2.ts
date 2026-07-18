import { getSnippet } from "../ast/parser";
import type { Finding, ASTNode } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";
import { buildFunctionCallGraph } from "./call-graph";
import { findReentrancyPaths } from "./taint-propagation";
import type { MergedContractView } from "../ast/import-graph";

/**
 * SWC-107-X: Cross-Function Reentrancy Detector
 *
 * Detects reentrancy vulnerabilities where:
 * 1. Function A makes an external call
 * 2. Function B is reachable during re-entry and reads stale state
 * 3. The state should have been updated before the external call but wasn't
 *
 * Example:
 *   function withdraw() {
 *     amount = balances[msg.sender];
 *     msg.sender.call{value: amount}("");  // external call
 *   }
 *   function bonus() {
 *     return balances[msg.sender] * 2;     // reads stale state during re-entry
 *   }
 */
export function detectCrossFunctionReentrancy(
  ast: ASTNode,
  source: string,
  filePath: string,
  ruleOptions?: RuleOptions,
): Finding[] {
  const findings: Finding[] = [];

  const contractView = ruleOptions?.contractView;
  if (!contractView) {
    return findings;
  }

  // Build call graph for the contract
  const callGraph = buildFunctionCallGraph(contractView);

  // Find all vulnerable paths
  const vulnerablePaths = findReentrancyPaths(contractView, callGraph);

  // Convert paths to findings
  for (const path of vulnerablePaths) {
    const externalCallMember = contractView.members.find(
      (m) => m.kind === "function" && m.name === path.externalCallFunction,
    );
    if (!externalCallMember) continue;

    findings.push(
      applyFindingContext(
        {
          id: "CP-107-X",
          swcId: "SWC-107",
          title: "Cross-function reentrancy vulnerability",
          description:
            `Function "${path.externalCallFunction}()" makes an external call ` +
            `and re-entry allows "${path.stateAccessFunction}()" to read stale state ` +
            `(${path.vulnerableStateName}). The state should have been updated before the ` +
            `external call. An attacker can exploit this to re-enter and access inconsistent contract state.`,
          recommendation:
            "Apply the Checks-Effects-Interactions pattern: update all state variables " +
            "before making any external calls. Ensure that re-entrant functions cannot access " +
            "stale state. Alternatively, use OpenZeppelin's ReentrancyGuard modifier or " +
            "implement a guard to prevent re-entry during state modifications.",
          severity: "critical",
          file: filePath,
          line: path.externalCallLine,
          snippet: getSnippet(externalCallMember.source, externalCallMember.node),
          callPath: path.callPath,
        },
        externalCallMember,
        contractView,
      ),
    );
  }

  return findings;
}
