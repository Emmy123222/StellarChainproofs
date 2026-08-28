import type { ASTNode } from "../../types";
import type { MergedMember } from "../../ast/import-graph";
import { visit, getSnippet } from "../../ast/parser";

export interface EmitSite {
  eventName: string;
  line: number;
  snippet: string;
}

/** Collect every `emit X(...)` statement reachable within a function body. */
export function collectEmitSites(functionMember: MergedMember): EmitSite[] {
  const sites: EmitSite[] = [];
  const fnNode = functionMember.node as ASTNode;

  visit(fnNode, {
    EmitStatement(node: ASTNode) {
      const call = node.eventCall as { expression?: ASTNode } | undefined;
      const nameNode = call?.expression as { name?: string; memberName?: string } | undefined;
      const eventName = nameNode?.name ?? nameNode?.memberName;
      if (!eventName) return;
      const loc = (node as { loc?: { start?: { line?: number } } }).loc;
      sites.push({
        eventName,
        line: loc?.start?.line ?? 0,
        snippet: getSnippet(functionMember.source, node),
      });
    },
  });

  return sites;
}

/** True iff the function emits the named event anywhere in its body. */
export function emitsEvent(functionMember: MergedMember, eventName: string): EmitSite | undefined {
  return collectEmitSites(functionMember).find((s) => s.eventName === eventName);
}
