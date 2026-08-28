import type { ASTNode } from "../../types";
import type { MergedMember } from "../../ast/import-graph";
import { visit, getSnippet } from "../../ast/parser";

export interface CallSite {
  name: string;
  line: number;
  snippet: string;
}

/** Sentinel `order.before`/`order.after` value matching any low-level external call (`.call`/`.send`/`.transfer`). */
export const EXTERNAL_CALL_MARKER = "<external-call>";

/** Unwrap `foo.bar{value: x}(...)`'s `NameValueExpression` wrapper down to the underlying callee expression. */
function unwrapNameValue(expr: ASTNode): ASTNode {
  return expr?.type === "NameValueExpression" ? unwrapNameValue(expr.expression) : expr;
}

function isExternalCallExpression(expr: ASTNode): boolean {
  const inner = unwrapNameValue(expr);
  if (!inner || inner.type !== "MemberAccess") return false;
  return inner.memberName === "call" || inner.memberName === "send" || inner.memberName === "transfer";
}

function calleeDisplayName(expr: ASTNode): string | undefined {
  const inner = unwrapNameValue(expr);
  if (!inner) return undefined;
  if (inner.type === "Identifier") return inner.name;
  if (inner.type === "MemberAccess") return inner.memberName;
  return undefined;
}

/**
 * Find every call site within `functionMember` whose callee name matches
 * `name` (or, for {@link EXTERNAL_CALL_MARKER}, every low-level external
 * call), returning them ordered by line number ascending — the ordering
 * `call-order` invariants are checked against.
 */
export function findCallSites(functionMember: MergedMember, name: string): CallSite[] {
  const sites: CallSite[] = [];
  const fnNode = functionMember.node as ASTNode;

  visit(fnNode, {
    FunctionCall(node: ASTNode) {
      const expr = node.expression as ASTNode;
      const loc = (node as { loc?: { start?: { line?: number } } }).loc;
      const line = loc?.start?.line ?? 0;

      if (name === EXTERNAL_CALL_MARKER) {
        if (isExternalCallExpression(expr)) {
          sites.push({ name, line, snippet: getSnippet(functionMember.source, node) });
        }
        return;
      }

      const calleeName = calleeDisplayName(expr);
      if (calleeName === name) {
        sites.push({ name, line, snippet: getSnippet(functionMember.source, node) });
      }
    },
  });

  return sites.sort((a, b) => a.line - b.line);
}

/** First (lowest-line) call site matching `name`, if any. */
export function firstCallSite(functionMember: MergedMember, name: string): CallSite | undefined {
  return findCallSites(functionMember, name)[0];
}
