import type { MergedContractView, MergedMember } from "../ast/import-graph";
import type { ExprNode } from "./expr-ast";
import { DiagnosticBag } from "./diagnostics";

/** Global Solidity identifiers usable inside a condition without further binding. */
const GLOBAL_ROOTS = new Set(["msg", "block", "tx", "now", "this", "address"]);
const GLOBAL_MEMBERS: Record<string, Set<string>> = {
  msg: new Set(["sender", "value", "data", "sig"]),
  block: new Set(["timestamp", "number", "difficulty", "coinbase", "gaslimit", "chainid", "basefee"]),
  tx: new Set(["origin", "gasprice"]),
};
const BUILTIN_CALL_NAMES = new Set(["old", "changed", "keccak256", "sha256", "ecrecover"]);

function paramNames(functionMember?: MergedMember): Set<string> {
  if (!functionMember) return new Set();
  const node = functionMember.node as { parameters?: Array<{ name?: string | null }> };
  const names = new Set<string>();
  for (const p of node.parameters ?? []) if (p.name) names.add(p.name);
  return names;
}

function memberOf(node: ExprNode): { rootName: string; path: string[] } | null {
  const path: string[] = [];
  let current: ExprNode = node;
  while (current.type === "MemberAccess") {
    path.unshift(current.member);
    current = current.object;
  }
  if (current.type !== "Identifier") return null;
  return { rootName: current.name, path };
}

/**
 * Verify every plain identifier / member-access chain referenced by a
 * (predicate-expanded) condition resolves to something the target contract
 * actually declares: a state variable, a function parameter, a callable
 * public function/getter, or a known global (`msg.sender`, `block.timestamp`,
 * ...). Emits `DSL005` warnings (not hard errors — a name that doesn't
 * resolve simply can never structurally match a guard, so the invariant
 * will report `fail`/`error` on its own merits) so spec authors get an
 * immediate "did you mean" signal instead of a silent, permanent failure.
 */
export function checkIdentifiersBound(
  condition: ExprNode,
  contractView: MergedContractView,
  functionMember: MergedMember | undefined,
  diagnostics: DiagnosticBag,
  invariantId: string,
): void {
  const stateVars = new Set(contractView.members.filter((m) => m.kind === "stateVariable").map((m) => m.name));
  const functions = new Set(contractView.members.filter((m) => m.kind === "function").map((m) => m.name));
  const params = paramNames(functionMember);
  const checked = new Set<string>();

  const visit = (node: ExprNode): void => {
    if (node.type === "MemberAccess" || node.type === "Identifier") {
      const resolved = memberOf(node);
      if (resolved) {
        const key = [resolved.rootName, ...resolved.path].join(".");
        if (checked.has(key)) return;
        checked.add(key);

        if (GLOBAL_ROOTS.has(resolved.rootName)) {
          const allowed = GLOBAL_MEMBERS[resolved.rootName];
          if (allowed && resolved.path.length > 0 && !allowed.has(resolved.path[0])) {
            diagnostics.warn(
              "DSL005",
              `${invariantId}: '${resolved.rootName}.${resolved.path[0]}' is not a recognized global member`,
              undefined,
              invariantId,
            );
          }
          return;
        }
        if (stateVars.has(resolved.rootName) || params.has(resolved.rootName) || functions.has(resolved.rootName)) {
          return;
        }
        diagnostics.warn(
          "DSL005",
          `${invariantId}: unknown identifier '${resolved.rootName}' — not a state variable, parameter, or function on '${contractView.name}'`,
          undefined,
          invariantId,
        );
      }
      if (node.type === "MemberAccess") visit(node.object);
      return;
    }
    if (node.type === "IndexAccess") {
      visit(node.object);
      visit(node.index);
      return;
    }
    if (node.type === "Call") {
      if (node.callee.type === "Identifier" && !BUILTIN_CALL_NAMES.has(node.callee.name) && !functions.has(node.callee.name)) {
        diagnostics.warn(
          "DSL006",
          `${invariantId}: unknown function or predicate '${node.callee.name}'`,
          undefined,
          invariantId,
        );
      } else {
        visit(node.callee);
      }
      for (const a of node.args) visit(a);
      return;
    }
    if (node.type === "Unary") {
      visit(node.argument);
      return;
    }
    if (node.type === "Binary") {
      visit(node.left);
      visit(node.right);
    }
  };

  visit(condition);
}
