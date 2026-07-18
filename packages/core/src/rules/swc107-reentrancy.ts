import { visit, getSnippet } from "../ast/parser";
import type { MergedMember } from "../ast/import-graph";
import type { Finding, ASTNode } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";

/**
 * SWC-107: Reentrancy
 *
 * Flags functions that make external calls before updating state variables.
 * Operates on merged contract views to catch inherited vulnerable functions.
 */
export function detectReentrancy(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions,
): Finding[] {
  const findings: Finding[] = [];
  const members = options?.contractView?.members.filter((m) => m.kind === "function") ?? [];

  const functionsToCheck: Array<{ member?: MergedMember; node: ASTNode; source: string }> =
    members.length > 0
      ? members.map((m) => ({ member: m, node: m.node, source: m.source }))
      : collectLocalFunctions(ast, source);

  for (const { member, node, source: memberSource } of functionsToCheck) {
    const fn = node as {
      name?: string;
      body?: { statements?: ASTNode[] };
      loc?: { start?: { line?: number } };
    };
    if (!fn.body?.statements) continue;

    const statements = fn.body.statements;
    let externalCallIdx = -1;
    let stateWriteAfterCall = false;

    statements.forEach((stmt: ASTNode, i: number) => {
      const stmtStr = JSON.stringify(stmt);

      const isExternalCall =
        stmtStr.includes('"call"') ||
        stmtStr.includes('"transfer"') ||
        stmtStr.includes('"send"') ||
        stmtStr.includes('"value"');

      if (isExternalCall && externalCallIdx === -1) {
        externalCallIdx = i;
        return;
      }

      // Detect state variable write after an external call
      if (
        externalCallIdx !== -1 &&
        i > externalCallIdx &&
        (stmt as { type?: string }).type === "ExpressionStatement"
      ) {
        const exprStr = JSON.stringify(stmt);
        // Heuristic: assignment after call with no msg.sender guard
        if (
          exprStr.includes('"operator":"="') ||
          exprStr.includes('"operator":"-="')
        ) {
          stateWriteAfterCall = true;
        }
      }
    });

    if (stateWriteAfterCall) {
      const line = fn.loc?.start?.line ?? 0;
      findings.push(
        applyFindingContext(
          {
            id: "CP-107",
            swcId: "SWC-107",
            title: "Reentrancy vulnerability",
            description:
              `Function "${fn.name ?? "anonymous"}" makes an external call before updating ` +
              `state variables. An attacker can re-enter the function before the state is updated, ` +
              `potentially draining funds (e.g. the DAO hack).`,
            recommendation:
              "Apply the Checks-Effects-Interactions pattern: update all state variables " +
              "before making any external calls. Alternatively, use OpenZeppelin's " +
              "ReentrancyGuard modifier.",
            severity: "critical",
            file: filePath,
            line,
            snippet: getSnippet(memberSource, node),
          },
          member,
          options?.contractView
        )
      );
    }
  }

  return findings;
}

function collectLocalFunctions(
  ast: ASTNode,
  source: string
): Array<{ member?: undefined; node: ASTNode; source: string }> {
  const functions: Array<{ member?: undefined; node: ASTNode; source: string }> = [];
  visit(ast, {
    FunctionDefinition(node: ASTNode) {
      functions.push({ node, source });
    },
  });
  return functions;
}
