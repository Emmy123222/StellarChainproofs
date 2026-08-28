import type { ASTNode } from "../../types";
import type { MergedContractView, MergedMember } from "../../ast/import-graph";
import type { CallGraph } from "../call-graph";
import { nodeLine, walkWithLoopContext } from "./ast-walk";
import {
  detectImplementedReceiverHooks,
  findCallSiteLoopContext,
  findCallbackTriggerSites,
  type DirectTrigger,
} from "./interface-detection";
import type { AnalyzableFunction, CallbackEdge, CallbackGraph, InterfaceEvidence } from "./types";

/** Maximum call-chain depth followed when resolving an indirect (helper-mediated) callback. */
const MAX_HOP_DEPTH = 3;
/** Maximum number of (function, depth) states explored per entry function, bounding BFS cost on adversarial/huge call graphs. */
const MAX_EXPLORED_STATES = 500;

export function analyzableFunctionsFromView(view: MergedContractView): AnalyzableFunction[] {
  return view.members
    .filter((m): m is MergedMember & { kind: "function" } => m.kind === "function")
    .map((m) => ({ name: m.name, node: m.node, source: m.source, definedIn: m.definedIn, member: m }));
}

function functionVisibility(node: ASTNode): string {
  return (node as { visibility?: string }).visibility ?? "default";
}

function isEntryCandidate(fn: AnalyzableFunction): boolean {
  const visibility = functionVisibility(fn.node);
  return visibility === "public" || visibility === "external" || visibility === "default";
}

function isArrayLengthBound(condition: ASTNode | undefined): { arrayBase?: string } | null {
  if (!condition) return null;
  const op = condition as { type?: string; operator?: string; right?: ASTNode };
  if (op.type !== "BinaryOperation" || !op.operator) return null;
  if (!["<", "<="].includes(op.operator)) return null;

  const right = op.right as { type?: string; memberName?: string; expression?: ASTNode } | undefined;
  if (right?.type === "MemberAccess" && right.memberName === "length") {
    const base = right.expression as { name?: string; memberName?: string } | undefined;
    return { arrayBase: base?.name ?? base?.memberName };
  }
  return null;
}

/**
 * A batch loop counts as bounded when the function contains an explicit
 * guard (`require`/`if (...) revert`) comparing the same array's `.length`
 * against a literal or a named constant before the loop is reached — the
 * common `require(ids.length <= MAX_BATCH_SIZE)` pattern.
 */
function hasExplicitLengthCap(entryFn: AnalyzableFunction, arrayBase: string | undefined, loopLine: number): boolean {
  if (!arrayBase) return false;

  let capped = false;
  walkWithLoopContext(entryFn.node, (node: ASTNode) => {
    if (capped) return;
    const line = nodeLine(node);
    if (line >= loopLine || line === 0) return;

    const rec = node as { type?: string; left?: ASTNode; operator?: string };
    if (rec.type !== "BinaryOperation" || !rec.operator) return;
    if (!["<=", "<", "=="].includes(rec.operator)) return;

    const left = rec.left as { type?: string; memberName?: string; expression?: ASTNode } | undefined;
    if (left?.type === "MemberAccess" && left.memberName === "length") {
      const base = left.expression as { name?: string; memberName?: string } | undefined;
      if ((base?.name ?? base?.memberName) === arrayBase) capped = true;
    }
  });

  return capped;
}

function loopConditionNode(loop: ASTNode): ASTNode | undefined {
  const rec = loop as { type?: string; conditionExpression?: ASTNode; condition?: ASTNode };
  return rec.type === "ForStatement" ? rec.conditionExpression : rec.condition;
}

interface BfsState {
  fn: AnalyzableFunction;
  path: string[];
  firstHopName: string | null;
}

/**
 * Build the standards-aware callback graph for a single contract: every
 * point where control implicitly leaves to an address the contract does
 * not control, as mandated by a token/vault/flash-loan standard (as
 * opposed to a raw, standard-agnostic external call, which SWC-107 /
 * CP-107-X already cover).
 */
export function buildCallbackGraph(view: MergedContractView, callGraph: CallGraph): CallbackGraph {
  const functions = analyzableFunctionsFromView(view);
  const byName = new Map(functions.map((f) => [f.name, f]));

  const directTriggersByFn = new Map<string, DirectTrigger[]>();
  for (const fn of functions) {
    directTriggersByFn.set(fn.name, findCallbackTriggerSites(fn));
  }

  const implementedHooks = detectImplementedReceiverHooks(functions);
  const edges: CallbackEdge[] = [];
  let truncated = false;

  for (const entryFn of functions) {
    if (!isEntryCandidate(entryFn)) continue;

    const ownTriggers = directTriggersByFn.get(entryFn.name) ?? [];
    for (const trigger of ownTriggers) {
      edges.push(makeEdge(entryFn, entryFn, [entryFn.name], trigger, trigger.line));
    }

    if (ownTriggers.length > 0) continue; // already covers this entry's own body

    // BFS through internal callees to find every function (directly, or via
    // a further helper-name match) whose body triggers a callback —
    // reachable in a single call chain from entryFn. A contract commonly
    // fires more than one distinct callback from the same entry function
    // (e.g. an ERC-777 sender hook followed by an ERC-721 receiver hook in
    // the same deposit-and-mint flow), so this does not stop at the first
    // match; it only avoids descending further *past* a function that
    // already produced an edge, since that function's own body is where
    // that particular callback's control handoff happens.
    const visited = new Set<string>([entryFn.name]);
    const queue: BfsState[] = [{ fn: entryFn, path: [entryFn.name], firstHopName: null }];
    let explored = 0;

    while (queue.length > 0) {
      const { fn, path, firstHopName } = queue.shift()!;
      if (path.length > MAX_HOP_DEPTH) continue;

      const node = callGraph.nodes.get(fn.name);
      for (const calleeName of node?.callees ?? []) {
        explored += 1;
        if (explored > MAX_EXPLORED_STATES) {
          truncated = true;
          queue.length = 0;
          break;
        }
        if (visited.has(calleeName)) continue;
        visited.add(calleeName);

        const calleeFn = byName.get(calleeName);
        if (!calleeFn) continue;

        const hop = firstHopName ?? calleeName;
        const calleeTriggers = directTriggersByFn.get(calleeName) ?? [];
        if (calleeTriggers.length > 0) {
          const loopNode = findCallSiteLoopContext(entryFn, hop);
          for (const trigger of calleeTriggers) {
            edges.push(
              makeEdge(entryFn, calleeFn, [...path, calleeName], trigger, trigger.line, loopNode),
            );
          }
          continue; // don't descend past a resolved trigger function
        }

        queue.push({ fn: calleeFn, path: [...path, calleeName], firstHopName: hop });
      }
    }
  }

  const byEntryFunction = new Map<string, CallbackEdge[]>();
  for (const edge of edges) {
    const list = byEntryFunction.get(edge.entryFunction) ?? [];
    list.push(edge);
    byEntryFunction.set(edge.entryFunction, list);
  }

  return { edges, byEntryFunction, implementedHooks, truncated };

  function makeEdge(
    entryFn: AnalyzableFunction,
    triggerFn: AnalyzableFunction,
    viaPath: string[],
    trigger: DirectTrigger,
    triggerLine: number,
    loopNodeOverride?: ASTNode | null,
  ): CallbackEdge {
    const loopNode = loopNodeOverride !== undefined ? loopNodeOverride : trigger.loopNode;
    const isBatch = loopNode !== null;

    let isUnboundedBatch = false;
    if (isBatch && loopNode) {
      const bound = isArrayLengthBound(loopConditionNode(loopNode));
      if (bound) {
        isUnboundedBatch = !hasExplicitLengthCap(entryFn, bound.arrayBase, nodeLine(loopNode));
      }
    }

    const entryCallSiteLine =
      entryFn.name === triggerFn.name ? triggerLine : findEntryCallSiteLine(entryFn, viaPath[1] ?? triggerFn.name);

    const evidence: InterfaceEvidence[] = [trigger.evidence];

    return {
      entryFunction: entryFn.name,
      triggerFunction: triggerFn.name,
      viaPath,
      standard: trigger.standard,
      kind: trigger.kind,
      line: triggerLine,
      isBatch,
      isUnboundedBatch,
      evidence,
      entryCallSiteLine,
    };
  }

  function findEntryCallSiteLine(entryFn: AnalyzableFunction, calleeName: string): number {
    let line = 0;
    walkWithLoopContext(entryFn.node, (node: ASTNode) => {
      if (line) return;
      const rec = node as { type?: string; expression?: ASTNode };
      if (rec.type !== "FunctionCall" || !rec.expression) return;
      const expr = rec.expression as { type?: string; name?: string };
      if (expr.type === "Identifier" && expr.name === calleeName) {
        line = nodeLine(node);
      }
    });
    return line || nodeLine(entryFn.node);
  }
}
