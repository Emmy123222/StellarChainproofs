import type { ASTNode } from "../../types";
import type { MergedContractView, MergedMember } from "../../ast/import-graph";
import { visit, getSnippet } from "../../ast/parser";
import { collectGuardsForFunction } from "./guards";
import { collectReferencedNames } from "../expr-normalize";

const ASSIGN_OPERATORS = new Set(["=", "+=", "-=", "*=", "/=", "%="]);

function baseIdentifierName(expr: ASTNode | null | undefined): string | undefined {
  if (!expr) return undefined;
  if (expr.type === "Identifier") return expr.name;
  if (expr.type === "IndexAccess") return baseIdentifierName(expr.base);
  if (expr.type === "MemberAccess") return baseIdentifierName(expr.expression);
  return undefined;
}

function paramNames(functionMember: MergedMember): Set<string> {
  const node = functionMember.node as { parameters?: Array<{ name?: string | null }> };
  const names = new Set<string>();
  for (const p of node.parameters ?? []) {
    if (p.name) names.add(p.name);
  }
  return names;
}

function referencesAny(expr: ASTNode, names: Set<string>): string | undefined {
  let found: string | undefined;
  visit(expr, {
    Identifier(node: ASTNode) {
      if (!found && names.has(node.name)) found = node.name;
    },
  });
  return found;
}

export interface StateWrite {
  stateVar: string;
  line: number;
  snippet: string;
  /** Function parameter flowing directly into this write, if any. */
  taintedByParam?: string;
}

/** Find every assignment to a state variable in `stateVarNames` within the function body. */
export function collectStateWrites(functionMember: MergedMember, stateVarNames: ReadonlySet<string>): StateWrite[] {
  const writes: StateWrite[] = [];
  const params = paramNames(functionMember);

  visit(functionMember.node as ASTNode, {
    BinaryOperation(node: ASTNode) {
      if (!ASSIGN_OPERATORS.has(node.operator)) return;
      const base = baseIdentifierName(node.left);
      if (!base || !stateVarNames.has(base)) return;
      const loc = (node as { loc?: { start?: { line?: number } } }).loc;
      const taintedByParam = referencesAny(node.right, params);
      writes.push({
        stateVar: base,
        line: loc?.start?.line ?? 0,
        snippet: getSnippet(functionMember.source, node),
        taintedByParam,
      });
    },
  });

  return writes;
}

export interface UnguardedTaintFinding {
  write: StateWrite;
  paramName: string;
}

/**
 * Bounded, first-order taint check: for every write to a state variable in
 * `stateVarNames` whose right-hand side references a function parameter
 * directly, verify that the same parameter is referenced by a guard
 * (`require`/`assert`/`if (...) revert`) at or before that write's line.
 *
 * This is a syntactic, single-hop check — it does not track taint through
 * intermediate local variables or across function calls. That scope is
 * intentional (see the DSL limitations doc): it catches the common
 * "unvalidated parameter written straight to storage" pattern
 * deterministically, without the unbounded search space of full taint
 * propagation.
 */
export function findUnguardedParamWrites(
  functionMember: MergedMember,
  contractView: MergedContractView,
  stateVarNames: ReadonlySet<string>,
): UnguardedTaintFinding[] {
  const writes = collectStateWrites(functionMember, stateVarNames);
  const guards = collectGuardsForFunction(functionMember, contractView);
  const findings: UnguardedTaintFinding[] = [];

  for (const write of writes) {
    if (!write.taintedByParam) continue;
    const guardedBefore = guards.some(
      (g) => g.line <= write.line && collectReferencedNames(g.expr).has(write.taintedByParam!),
    );
    if (!guardedBefore) {
      findings.push({ write, paramName: write.taintedByParam });
    }
  }

  return findings;
}
