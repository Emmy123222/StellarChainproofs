import { visit, getSnippet } from "../ast/parser";
import type { MergedMember } from "../ast/import-graph";
import type { Finding, ASTNode } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";

/**
 * SWC-107: Reentrancy (Intra-function variant)
 *
 * Flags functions that make external calls before updating state variables
 * within the same function body. This catches the classic DAO-style reentrancy.
 */
export function detectReentrancy(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions,
): Finding[] {
  const findings: Finding[] = [];

  const contractView = ruleOptions?.contractView;
  const members = contractView?.members.filter((m) => m.kind === "function") ?? [];

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

    for (const issue of issues) {
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
            line: issue.line,
            snippet: issue.snippet,
          },
          member,
          contractView,
        ),
      );
    }
  }

  return findings;
}

function checkFunctionForReentrancy(
  statements: ASTNode[],
  fn: { name?: string; loc?: { start?: { line?: number } } },
  source: string,
  memberSource: string,
  node: ASTNode,
): Array<{ line: number; snippet: string }> {
  const issues: Array<{ line: number; snippet: string }> = [];

  let externalCallIdx = -1;

  for (let i = 0; i < statements.length; i++) {
    const stmt = statements[i];
    const stmtStr = JSON.stringify(stmt);

    // Detect external calls (call, transfer, send with value)
    const isExternalCall =
      stmtStr.includes('"call"') ||
      stmtStr.includes('"transfer"') ||
      stmtStr.includes('"send"') ||
      (stmtStr.includes('"value"') && stmtStr.includes('"MemberAccess"'));

    if (isExternalCall) {
      externalCallIdx = i;
    }

    // Detect state variable write after an external call
    if (
      externalCallIdx !== -1 &&
      i > externalCallIdx &&
      (stmt as { type?: string }).type === "ExpressionStatement"
    ) {
      const exprStr = JSON.stringify(stmt);
      // Heuristic: assignment after call
      if (exprStr.includes('"operator":"="') || exprStr.includes('"operator":"-="')) {
        const line = (stmt as { loc?: { start?: { line?: number } } }).loc?.start?.line ?? fn.loc?.start?.line ?? 0;
        issues.push({
          line,
          snippet: getSnippet(memberSource, stmt),
        });
      }
    }
  }

  return issues;
}

function collectLocalFunctions(
  ast: ASTNode,
  source: string,
): Array<{ member?: undefined; node: ASTNode; source: string }> {
  const functions: Array<{ member?: undefined; node: ASTNode; source: string }> = [];
  visit(ast, {
    FunctionDefinition(node: ASTNode) {
      functions.push({ node, source });
    },
  });
  return functions;
}
