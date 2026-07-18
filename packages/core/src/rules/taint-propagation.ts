import type { ASTNode } from "../types";
import type { MergedMember, MergedContractView } from "../ast/import-graph";
import { visit } from "../ast/parser";
import type { CallGraph } from "./call-graph";
import { findCallPath } from "./call-graph";

export interface ReentrancyPath {
  externalCallFunction: string;
  stateAccessFunction: string;
  vulnerableStateName: string;
  callPath: string[];
  externalCallLine: number;
  stateAccessLine: number;
}

/**
 * Analyze taint propagation for cross-function reentrancy.
 *
 * Returns a list of vulnerable paths where:
 * 1. A function makes an external call
 * 2. Any other function reads state that was modified before the external call
 *    (indicating stale state access during re-entry)
 */
export function findReentrancyPaths(contractView: MergedContractView, callGraph: CallGraph): ReentrancyPath[] {
  const paths: ReentrancyPath[] = [];
  const seen = new Set<string>();

  // For each function that makes an external call
  for (const externalCallFn of callGraph.externalCallFunctions) {
    const externalCallMember = contractView.members.find(
      (m) => m.kind === "function" && m.name === externalCallFn,
    );
    if (!externalCallMember) continue;

    // Find the line of the external call
    const externalCallLine = findExternalCallLine(externalCallMember.node);

    // Get all state variables accessed in this function and where they're accessed
    const allAccesses = analyzeStateAccess(externalCallMember.node, callGraph.stateVarNames);

    // Find state variables that are vulnerable to reentrancy:
    // - Variable is used (read) at any point
    // - Variable is not guaranteed to be properly updated before the external call
    const vulnerableVars = new Set<string>();

    for (const access of allAccesses) {
      const varName = access.varName;

      // Check if variable is read before external call
      const readBeforeCall = allAccesses.some(
        (a) => a.varName === varName && !a.isWrite && a.line < externalCallLine
      );

      // Check if variable is written before external call
      const writtenBeforeCall = allAccesses.some(
        (a) => a.varName === varName && a.isWrite && a.line < externalCallLine
      );

      // Vulnerable if: variable is read but not written before the external call
      // OR: variable is written but also read (complex state management)
      if (readBeforeCall && !writtenBeforeCall) {
        vulnerableVars.add(varName);
      }
    }

    // Now check every other function to see if it reads these vulnerable variables
    for (const member of contractView.members) {
      if (member.kind !== "function" || member.name === externalCallFn) continue;

      const otherFnAccesses = analyzeStateAccess(member.node, callGraph.stateVarNames);

      for (const varName of vulnerableVars) {
        const readsVar = otherFnAccesses.some((a) => a.varName === varName && !a.isWrite);

        if (readsVar) {
          const pathKey = `${externalCallFn}→${member.name}→${varName}`;
          if (!seen.has(pathKey)) {
            seen.add(pathKey);

            const stateAccessLine = otherFnAccesses.find((a) => a.varName === varName)?.line ?? 0;
            paths.push({
              externalCallFunction: externalCallFn,
              stateAccessFunction: member.name,
              vulnerableStateName: varName,
              callPath: [externalCallFn, member.name],
              externalCallLine,
              stateAccessLine,
            });
          }
        }
      }
    }
  }

  return paths;
}

/**
 * Find the line number of the external call in a function.
 */
function findExternalCallLine(fnNode: ASTNode): number {
  let line = 0;
  visit(fnNode, {
    FunctionCall(node: ASTNode) {
      const call = node as { expression?: ASTNode; loc?: { start?: { line?: number } } };
      const exprStr = JSON.stringify(call.expression);

      if (exprStr.includes('"call"') || exprStr.includes('"transfer"') || exprStr.includes('"send"')) {
        line = call.loc?.start?.line ?? 0;
      }
    },
  });
  return line;
}

/**
 * Analyze state variable accesses in a function.
 * Returns the variable names being read/written and their line numbers.
 */
function analyzeStateAccess(
  fnNode: ASTNode,
  stateVarNames: Set<string>,
): Array<{ varName: string; line: number; isWrite: boolean }> {
  const accesses: Array<{ varName: string; line: number; isWrite: boolean }> = [];
  const seen = new Set<string>();

  visit(fnNode, {
    Identifier(node: ASTNode) {
      const id = node as { name?: string; loc?: { start?: { line?: number } } };
      if (id.name && stateVarNames.has(id.name)) {
        const key = `${id.name}-${id.loc?.start?.line ?? 0}`;
        if (!seen.has(key)) {
          seen.add(key);
          accesses.push({
            varName: id.name,
            line: id.loc?.start?.line ?? 0,
            isWrite: false, // Heuristic: identifier is usually a read
          });
        }
      }
    },

    MemberAccess(node: ASTNode) {
      const member = node as { memberName?: string; loc?: { start?: { line?: number } } };
      if (member.memberName && stateVarNames.has(member.memberName)) {
        const key = `${member.memberName}-${member.loc?.start?.line ?? 0}`;
        if (!seen.has(key)) {
          seen.add(key);
          accesses.push({
            varName: member.memberName,
            line: member.loc?.start?.line ?? 0,
            isWrite: false,
          });
        }
      }
    },

    BinaryOperation(node: ASTNode) {
      const op = node as { operator?: string; left?: ASTNode };
      if ((op.operator === "=" || op.operator === "-=" || op.operator === "+=") && op.left) {
        const leftStr = JSON.stringify(op.left);
        for (const varName of stateVarNames) {
          if (leftStr.includes(`"name":"${varName}"`)) {
            const key = `${varName}-write-${(node as any).loc?.start?.line ?? 0}`;
            if (!seen.has(key)) {
              seen.add(key);
              accesses.push({
                varName,
                line: (node as any).loc?.start?.line ?? 0,
                isWrite: true,
              });
            }
          }
        }
      }
    },
  });

  return accesses;
}

/**
 * Check if a state variable is modified before an external call.
 * This helps distinguish between variables that should have been updated
 * before the call (valid state updates) vs after the call (reentrancy).
 */
function stateModifiedBeforeExternalCall(
  fnNode: { body?: { statements?: ASTNode[] } },
  varName: string,
  externalCallLine: number,
): boolean {
  const statements = fnNode.body?.statements ?? [];

  let foundModification = false;

  for (const stmt of statements) {
    const stmtStr = JSON.stringify(stmt);
    const line = (stmt as any).loc?.start?.line ?? 0;

    // If we've reached the external call, stop searching
    if (line >= externalCallLine) break;

    // Check if this statement modifies the state variable
    if (
      (stmtStr.includes(`"name":"${varName}"`) && stmtStr.includes('"operator":"="')) ||
      stmtStr.includes(`"name":"${varName}"`) &&
        (stmtStr.includes('"operator":"-="') || stmtStr.includes('"operator":"+="'))
    ) {
      foundModification = true;
    }
  }

  return foundModification;
}
