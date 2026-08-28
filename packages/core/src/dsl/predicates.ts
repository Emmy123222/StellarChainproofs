import type { ExprNode } from "./expr-ast";
import type { EvaluationBudget, PredicateDef } from "./types";

export class PredicateExpansionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PredicateExpansionError";
  }
}

/**
 * Inline every reusable-predicate call (`isOwner()`) in `expr` with its
 * defining expression, so the evaluator only ever has to structurally
 * match against plain identifiers/operators — never predicate names, which
 * (by construction) never appear literally in the Solidity source being
 * checked.
 *
 * Cyclic predicate definitions are already rejected at parse time
 * ({@link import("./spec-parser").parseInvariantSpecFile}), so this only
 * needs a depth cap as defense in depth against unexpectedly deep — but
 * acyclic — predicate chains, keeping expansion bounded as required by the
 * evaluator's determinism/termination guarantees.
 */
export function inlinePredicates(
  expr: ExprNode,
  predicates: ReadonlyMap<string, PredicateDef>,
  budget: EvaluationBudget,
): ExprNode {
  return expand(expr, predicates, 0, budget.maxPredicateDepth);
}

function expand(
  node: ExprNode,
  predicates: ReadonlyMap<string, PredicateDef>,
  depth: number,
  maxDepth: number,
): ExprNode {
  if (depth > maxDepth) {
    throw new PredicateExpansionError(
      `Predicate expansion exceeded the maximum depth (${maxDepth}) — likely an unexpectedly deep (though acyclic) predicate chain`,
    );
  }

  switch (node.type) {
    case "Call": {
      if (node.callee.type === "Identifier" && predicates.has(node.callee.name)) {
        const def = predicates.get(node.callee.name)!;
        return expand(def.expr, predicates, depth + 1, maxDepth);
      }
      return {
        ...node,
        callee: expand(node.callee, predicates, depth, maxDepth),
        args: node.args.map((a) => expand(a, predicates, depth, maxDepth)),
      };
    }
    case "MemberAccess":
      return { ...node, object: expand(node.object, predicates, depth, maxDepth) };
    case "IndexAccess":
      return {
        ...node,
        object: expand(node.object, predicates, depth, maxDepth),
        index: expand(node.index, predicates, depth, maxDepth),
      };
    case "Unary":
      return { ...node, argument: expand(node.argument, predicates, depth, maxDepth) };
    case "Binary":
      return {
        ...node,
        left: expand(node.left, predicates, depth, maxDepth),
        right: expand(node.right, predicates, depth, maxDepth),
      };
    default:
      return node;
  }
}

const UNSUPPORTED_BUILTIN_CALLS = new Set(["old", "changed"]);

/**
 * Find calls to built-ins that are accepted by the parser/typechecker for
 * forward compatibility but not yet given evaluation semantics (temporal
 * operators `old()`/`changed()` — bounded structural matching has no notion
 * of "value at function entry" without full symbolic state tracking).
 * Returns the first such call name found, if any.
 */
export function findUnsupportedConstruct(expr: ExprNode): string | undefined {
  if (expr.type === "Call" && expr.callee.type === "Identifier") {
    if (UNSUPPORTED_BUILTIN_CALLS.has(expr.callee.name)) return expr.callee.name;
    for (const a of expr.args) {
      const found = findUnsupportedConstruct(a);
      if (found) return found;
    }
    return undefined;
  }
  if (expr.type === "MemberAccess") return findUnsupportedConstruct(expr.object);
  if (expr.type === "IndexAccess") {
    return findUnsupportedConstruct(expr.object) ?? findUnsupportedConstruct(expr.index);
  }
  if (expr.type === "Unary") return findUnsupportedConstruct(expr.argument);
  if (expr.type === "Binary") {
    return findUnsupportedConstruct(expr.left) ?? findUnsupportedConstruct(expr.right);
  }
  return undefined;
}
