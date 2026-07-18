import { visit, getSnippet } from "../ast/parser";
import type { MergedMember } from "../ast/import-graph";
import type { Finding, ASTNode } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";

/**
 * SWC-115: Authorization through tx.origin
 *
 * Using tx.origin for authorization is dangerous because a malicious
 * intermediate contract can trick the original EOA into calling it,
 * then relay that call — with the original tx.origin — to the target.
 *
 * Operates on merged contract views to catch inherited modifiers and functions.
 */
export function detectTxOrigin(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions,
): Finding[] {
  const findings: Finding[] = [];
  const members =
    options?.contractView?.members.filter(
      (m) => m.kind === "function" || m.kind === "modifier",
    ) ?? [];

  const functionsToCheck: Array<{ member?: MergedMember; node: ASTNode; source: string }> =
    members.length > 0
      ? members.map((m) => ({ member: m, node: m.node, source: m.source }))
      : [{ node: ast, source }];

  for (const { member, node, source: memberSource } of functionsToCheck) {
    visit(node, {
      MemberAccess(inner: ASTNode) {
        const finding = checkTxOriginNode(inner, memberSource, filePath, member, options);
        if (finding) findings.push(finding);
      },
    });
  }

  return findings;
}
