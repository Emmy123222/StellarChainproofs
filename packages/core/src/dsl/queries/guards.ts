import type { ASTNode } from "../../types";
import type { MergedContractView, MergedMember } from "../../ast/import-graph";
import { getSnippet } from "../../ast/parser";
import type { ExprNode } from "../expr-ast";
import { solidityExprToDslNode, negate } from "../solidity-expr-adapter";
import { expressionsEquivalent } from "../expr-normalize";

export interface Guard {
  /** The boolean condition that must hold for control flow to continue past this point. */
  expr: ExprNode;
  line: number;
  lineEnd: number;
  snippet: string;
  /** Function (or modifier) the guard was found in — for cross-function evidence. */
  source: string;
}

const REVERTING_CALL_NAMES = new Set(["revert", "assert"]);

function calleeName(expr: ASTNode): string | undefined {
  if (!expr) return undefined;
  if (expr.type === "Identifier") return expr.name;
  if (expr.type === "MemberAccess") return expr.memberName;
  return undefined;
}

function statementReverts(stmt: ASTNode | null | undefined): boolean {
  if (!stmt) return false;
  if (stmt.type === "RevertStatement" || stmt.type === "ThrowStatement") return true;
  if (stmt.type === "ExpressionStatement") {
    const expr = stmt.expression;
    if (expr?.type === "FunctionCall") {
      const name = calleeName(expr.expression);
      if (name === "revert") return true;
    }
    return false;
  }
  if (stmt.type === "Block") {
    return (stmt.statements ?? []).some((s: ASTNode) => statementReverts(s));
  }
  return false;
}

function locOf(node: ASTNode): { line: number; lineEnd: number } {
  const loc = (node as { loc?: { start?: { line?: number }; end?: { line?: number } } }).loc;
  return { line: loc?.start?.line ?? 0, lineEnd: loc?.end?.line ?? loc?.start?.line ?? 0 };
}

/**
 * Extract every boolean guard enforced by a statement list (`require(...)`,
 * `assert(...)`, `if (cond) revert(...)`/`if (!cond) revert(...)`), in
 * source order. Statements the DSL expression language can't represent
 * (see {@link solidityExprToDslNode}) are silently skipped — they simply
 * never match, which is the documented false-negative-biased behavior of
 * this evaluator.
 */
export function collectGuards(statements: ASTNode[], source: string, sourceLabel: string): Guard[] {
  const guards: Guard[] = [];

  for (const stmt of statements) {
    if (!stmt) continue;

    if (stmt.type === "ExpressionStatement" && stmt.expression?.type === "FunctionCall") {
      const call = stmt.expression;
      const name = calleeName(call.expression);
      if ((name === "require" || name === "assert") && call.arguments?.[0]) {
        const dslExpr = solidityExprToDslNode(call.arguments[0]);
        if (dslExpr) {
          const { line, lineEnd } = locOf(stmt);
          guards.push({ expr: dslExpr, line, lineEnd, snippet: getSnippet(source, stmt), source: sourceLabel });
        }
      }
      continue;
    }

    if (stmt.type === "IfStatement") {
      const condDsl = solidityExprToDslNode(stmt.condition);
      if (condDsl) {
        const { line, lineEnd } = locOf(stmt);
        const snippet = getSnippet(source, stmt);
        if (statementReverts(stmt.trueBody) && !stmt.falseBody) {
          guards.push({ expr: negate(condDsl), line, lineEnd, snippet, source: sourceLabel });
        } else if (!statementReverts(stmt.trueBody) && statementReverts(stmt.falseBody)) {
          guards.push({ expr: condDsl, line, lineEnd, snippet, source: sourceLabel });
        }
      }
      continue;
    }
  }

  return guards;
}

/**
 * Collect guards from a function body plus the bodies of every modifier it
 * applies (resolved against the contract's merged member view — this is
 * what lets an `onlyOwner` modifier satisfy an `access` invariant declared
 * on the function it guards, without requiring the guard to be inlined).
 */
export function collectGuardsForFunction(
  functionMember: MergedMember,
  contractView: MergedContractView,
): Guard[] {
  const fnNode = functionMember.node as { name?: string | null; body?: { statements?: ASTNode[] }; modifiers?: Array<{ name?: string }> };
  const guards: Guard[] = [];

  for (const stmt of fnNode.body?.statements ?? []) {
    guards.push(...collectGuards([stmt], functionMember.source, functionMember.name));
  }

  for (const invocation of fnNode.modifiers ?? []) {
    const modifierMember = contractView.members.find(
      (m) => m.kind === "modifier" && m.name === invocation.name,
    );
    if (!modifierMember) continue;
    const modNode = modifierMember.node as { body?: { statements?: ASTNode[] } };
    for (const stmt of modNode.body?.statements ?? []) {
      guards.push(...collectGuards([stmt], modifierMember.source, modifierMember.name));
    }
  }

  return guards;
}

/** True iff any guard in `guards` structurally enforces `condition`. */
export function findMatchingGuard(guards: Guard[], condition: ExprNode): Guard | undefined {
  return guards.find((g) => expressionsEquivalent(g.expr, condition));
}
