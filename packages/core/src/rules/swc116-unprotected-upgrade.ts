import { visit, getSnippet } from "../ast/parser";
import type { MergedMember } from "../ast/import-graph";
import type { Finding, ASTNode } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";

/**
 * CP-116: Unprotected upgrade authorization
 *
 * Detects _authorizeUpgrade functions without access control.
 * Critical for UUPS proxies where an empty override in a base contract
 * leaves the upgrade path open to anyone.
 */
export function detectUnprotectedUpgrade(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions
): Finding[] {
  const findings: Finding[] = [];
  const members = options?.contractView?.members.filter((m) => m.kind === "function") ?? [];

  const functionsToCheck: Array<{ member?: MergedMember; node: ASTNode; source: string }> =
    members.length > 0
      ? members.map((m) => ({ member: m, node: m.node, source: m.source }))
      : [];

  if (functionsToCheck.length === 0) {
    visit(ast, {
      FunctionDefinition(node: ASTNode) {
        functionsToCheck.push({ node, source });
      },
    });
  }

  for (const { member, node, source: memberSource } of functionsToCheck) {
    const fn = node as {
      name?: string;
      visibility?: string;
      modifiers?: ASTNode[];
      body?: { statements?: ASTNode[] };
      loc?: { start?: { line?: number } };
    };

    if (fn.name !== "_authorizeUpgrade") continue;
    if (fn.visibility !== "internal" && fn.visibility !== "private") continue;

    const hasAccessControl = hasUpgradeAccessControl(fn.modifiers ?? [], fn.body?.statements ?? []);
    if (hasAccessControl) continue;

    const line = fn.loc?.start?.line ?? 0;
    findings.push(
      applyFindingContext(
        {
          id: "CP-116",
          swcId: "SWC-116",
          title: "Unprotected upgrade authorization",
          description:
            `Function "_authorizeUpgrade" in "${options?.contractView?.name ?? "contract"}" ` +
            "has no access control. Anyone can authorize a contract upgrade, allowing complete " +
            "takeover of a UUPS proxy.",
          recommendation:
            "Restrict _authorizeUpgrade to authorized roles, e.g. " +
            "override with onlyOwner or onlyRole(UPGRADER_ROLE). " +
            "Ensure base contracts use `internal virtual` with proper guards in concrete implementations.",
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

  return findings;
}

function hasUpgradeAccessControl(modifiers: ASTNode[], statements: ASTNode[]): boolean {
  const protectedModifiers = new Set([
    "onlyOwner",
    "onlyRole",
    "onlyAdmin",
    "onlyProxyOwner",
    "auth",
  ]);

  for (const mod of modifiers) {
    const name = (mod as { name?: string }).name ?? "";
    if (protectedModifiers.has(name) || name.startsWith("only")) return true;
  }

  for (const stmt of statements) {
    const stmtStr = JSON.stringify(stmt);
    if (
      stmtStr.includes('"name":"require"') &&
      (stmtStr.includes('"name":"msg"') ||
        stmtStr.includes('"memberName":"sender"') ||
        stmtStr.includes('"name":"owner"') ||
        stmtStr.includes('"name":"_owner"'))
    ) {
      return true;
    }
  }

  return statements.length === 0 ? false : isRevertOnlyBody(statements);
}

function isRevertOnlyBody(statements: ASTNode[]): boolean {
  return statements.every((stmt) => {
    const s = JSON.stringify(stmt);
    return s.includes('"type":"RevertStatement"') || s.includes('"name":"revert"');
  });
}
