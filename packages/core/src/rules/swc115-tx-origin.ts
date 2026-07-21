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

  if (members.length > 0) {
    for (const member of members) {
      visit(member.node, {
        MemberAccess(node: ASTNode) {
          const finding = checkTxOriginNode(
            node,
            member.source,
            filePath,
            member,
            options
          );
          if (finding) findings.push(finding);
        },
      });
    }

    return findings;
  }

  visit(ast, {
    MemberAccess(node: ASTNode) {
      const finding = checkTxOriginNode(node, source, filePath);
      if (finding) findings.push(finding);
    },
  });

  return findings;
}

function checkTxOriginNode(
  node: ASTNode,
  source: string,
  filePath: string,
  member?: MergedMember,
  options?: RuleOptions,
): Finding | null {
  const access = node as {
    memberName?: string;
    expression?: { name?: string };
    loc?: { start?: { line?: number } };
  };

  if (access.memberName !== "origin" || access.expression?.name !== "tx") {
    return null;
  }

  const line = access.loc?.start?.line ?? 0;
  return applyFindingContext(
    {
      id: "CP-115",
      swcId: "SWC-115",
      title: "Use of tx.origin for authentication",
      description:
        "tx.origin refers to the original external account that initiated the transaction, " +
        "not the immediate caller. A phishing contract can exploit this to perform " +
        "unauthorized actions on behalf of the victim.",
      recommendation:
        "Replace tx.origin with msg.sender for authorization checks. " +
        "If you need to distinguish EOAs from contracts, use " +
        "msg.sender == tx.origin as a secondary check, not the primary guard.",
      severity: "high",
      file: filePath,
      line,
      snippet: getSnippet(source, node),
    },
    member,
    options?.contractView,
  );
}
