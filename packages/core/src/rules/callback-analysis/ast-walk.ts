import type { ASTNode } from "../../types";

/**
 * Loop-aware AST walk context. `loopNode` is the innermost enclosing
 * for/while/do-while statement, or `null` when not inside a loop.
 */
export interface WalkContext {
  loopNode: ASTNode | null;
}

const LOOP_TYPES = new Set(["ForStatement", "WhileStatement", "DoWhileStatement"]);

/**
 * Default budget on visited nodes for a single {@link walkWithLoopContext} call.
 * Guards against pathological/adversarial ASTs (e.g. deeply duplicated or
 * generated contracts) causing unbounded traversal time.
 */
export const DEFAULT_WALK_NODE_BUDGET = 200_000;

/**
 * Generic, loop-context-aware AST traversal.
 *
 * Unlike {@link import("../../ast/parser").visit}, which dispatches only on
 * node type, this walks every enumerable property of every node so callers
 * can observe ancestor context (specifically: "am I inside a loop body, and
 * if so which loop"). This is needed to distinguish a single receiver-hook
 * callback from a batch callback invoked once per loop iteration.
 *
 * Traversal is bounded by `nodeBudget` and cycle-safe (a `WeakSet` guards
 * against revisiting the same object), so a single call can never hang
 * regardless of input shape.
 *
 * @returns `true` if traversal completed; `false` if the node budget was
 * exhausted first (callers may treat this as "results may be incomplete").
 */
export function walkWithLoopContext(
  root: ASTNode,
  visitor: (node: ASTNode, ctx: WalkContext) => void,
  nodeBudget: number = DEFAULT_WALK_NODE_BUDGET,
): boolean {
  const seen = new WeakSet<object>();
  let budget = nodeBudget;

  function go(node: unknown, ctx: WalkContext): boolean {
    if (budget <= 0) return false;
    if (!node || typeof node !== "object") return true;
    const obj = node as Record<string, unknown>;

    if (Array.isArray(obj)) {
      for (const item of obj as unknown[]) {
        if (!go(item, ctx)) return false;
      }
      return true;
    }

    if (seen.has(obj)) return true;
    seen.add(obj);
    budget -= 1;
    if (budget <= 0) return false;

    const nodeType = (obj as { type?: unknown }).type;
    visitor(obj as ASTNode, ctx);

    const nextCtx: WalkContext =
      typeof nodeType === "string" && LOOP_TYPES.has(nodeType)
        ? { loopNode: obj as ASTNode }
        : ctx;

    for (const key of Object.keys(obj)) {
      if (key === "loc" || key === "range") continue;
      if (!go(obj[key], nextCtx)) return false;
    }
    return true;
  }

  return go(root, { loopNode: null });
}

/**
 * Collects every state-variable-write target name reachable from `node`
 * (assignment / compound-assignment left-hand sides), independent of loop
 * context. Used to resolve which identifier a loop bound or guard condition
 * refers to.
 */
export function collectIdentifierNames(node: ASTNode | null | undefined): Set<string> {
  const names = new Set<string>();
  if (!node) return names;
  walkWithLoopContext(node, (n) => {
    const rec = n as { type?: string; name?: string; memberName?: string };
    if (rec.type === "Identifier" && rec.name) names.add(rec.name);
    if (rec.type === "MemberAccess" && rec.memberName) names.add(rec.memberName);
  });
  return names;
}

export function nodeLine(node: ASTNode | null | undefined): number {
  const loc = (node as { loc?: { start?: { line?: number } } } | null | undefined)?.loc;
  return loc?.start?.line ?? 0;
}
