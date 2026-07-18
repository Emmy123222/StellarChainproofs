import { visit } from "../ast/parser";
import type { ASTNode } from "../types";
import type { MergedContractView } from "../ast/import-graph";

export interface CallGraphNode {
  name: string;
  isConstructor: boolean;
  hasExternalCall: boolean;
  callees: string[];
  callers: string[];
  stateVariablesRead: Set<string>;
  stateVariablesWritten: Set<string>;
}

export interface CallGraphEdge {
  from: string;
  to: string;
  isExternal: boolean;
  line: number;
}

export interface CallGraph {
  nodes: Map<string, CallGraphNode>;
  edges: CallGraphEdge[];
  externalCallFunctions: Set<string>;
  stateVarNames: Set<string>;
}

/**
 * Build a function call graph for the contract.
 * Extracts inter-function calls and external calls.
 */
export function buildFunctionCallGraph(contractView: MergedContractView): CallGraph {
  const nodes = new Map<string, CallGraphNode>();
  const edges: CallGraphEdge[] = [];
  const externalCallFunctions = new Set<string>();
  const stateVarNames = new Set<string>();

  // Extract all state variable names
  for (const member of contractView.members) {
    if (member.kind === "stateVariable") {
      stateVarNames.add(member.name);
    }
  }

  // Initialize nodes for all functions
  for (const member of contractView.members) {
    if (member.kind === "function") {
      nodes.set(member.name, {
        name: member.name,
        isConstructor: false,
        hasExternalCall: false,
        callees: [],
        callers: [],
        stateVariablesRead: new Set(),
        stateVariablesWritten: new Set(),
      });
    }
  }

  // Analyze each function
  for (const member of contractView.members) {
    if (member.kind !== "function") continue;

    const fnNode = member.node as { body?: { statements?: ASTNode[] } };
    if (!fnNode.body?.statements) continue;

    analyzeFunction(member.name, fnNode, nodes, edges, stateVarNames, externalCallFunctions);
  }

  // Build callers from edges
  for (const edge of edges) {
    const callerNode = nodes.get(edge.from);
    const calleeNode = nodes.get(edge.to);
    if (callerNode && !edge.isExternal) {
      callerNode.callees.push(edge.to);
    }
    if (calleeNode && !edge.isExternal) {
      calleeNode.callers.push(edge.from);
    }
  }

  return {
    nodes,
    edges,
    externalCallFunctions,
    stateVarNames,
  };
}

function analyzeFunction(
  fnName: string,
  fnNode: { body?: { statements?: ASTNode[] } },
  nodes: Map<string, CallGraphNode>,
  edges: CallGraphEdge[],
  stateVarNames: Set<string>,
  externalCallFunctions: Set<string>,
): void {
  const fnData = nodes.get(fnName)!;
  const statements = fnNode.body?.statements ?? [];

  visit(fnNode, {
    FunctionCall(node: ASTNode) {
      const call = node as {
        names?: string[];
        expression?: ASTNode;
        loc?: { start?: { line?: number } };
      };

      const line = call.loc?.start?.line ?? 0;
      const exprStr = JSON.stringify(call.expression);

      // Detect external call: msg.sender.call or address.call
      if (exprStr.includes('"call"') || exprStr.includes('"transfer"') || exprStr.includes('"send"')) {
        fnData.hasExternalCall = true;
        externalCallFunctions.add(fnName);
        return;
      }

      // Detect internal function call
      const expr = call.expression as { name?: string; type?: string };
      if (expr.type === "Identifier" && expr.name && nodes.has(expr.name)) {
        edges.push({
          from: fnName,
          to: expr.name,
          isExternal: false,
          line,
        });
      }
    },

    StateVariableDeclaration(node: ASTNode) {
      // Track state variable writes
      const decl = node as { variables?: Array<{ name?: string }> };
      for (const v of decl.variables ?? []) {
        if (v.name) {
          fnData.stateVariablesWritten.add(v.name);
        }
      }
    },

    MemberAccess(node: ASTNode) {
      // Track state variable reads (simple heuristic)
      const member = node as { memberName?: string };
      if (member.memberName && stateVarNames.has(member.memberName)) {
        fnData.stateVariablesRead.add(member.memberName);
      }
    },

    Identifier(node: ASTNode) {
      // Track state variable reads
      const id = node as { name?: string };
      if (id.name && stateVarNames.has(id.name)) {
        fnData.stateVariablesRead.add(id.name);
      }
    },
  });
}

/**
 * Find all functions reachable from a given function via internal calls.
 * Includes the starting function itself.
 */
export function findReachableFunctions(
  from: string,
  callGraph: CallGraph,
): Set<string> {
  const reachable = new Set<string>();
  const queue = [from];

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (reachable.has(current)) continue;
    reachable.add(current);

    const node = callGraph.nodes.get(current);
    if (node) {
      for (const callee of node.callees) {
        if (!reachable.has(callee)) {
          queue.push(callee);
        }
      }
    }
  }

  return reachable;
}

/**
 * Check if there is a call path from function A to function B.
 * Returns the path as an array of function names, or null if no path exists.
 */
export function findCallPath(
  from: string,
  to: string,
  callGraph: CallGraph,
): string[] | null {
  if (from === to) return [from];

  const visited = new Set<string>();
  const queue: Array<{ fn: string; path: string[] }> = [{ fn: from, path: [from] }];

  while (queue.length > 0) {
    const { fn, path } = queue.shift()!;
    if (visited.has(fn)) continue;
    visited.add(fn);

    const node = callGraph.nodes.get(fn);
    if (!node) continue;

    for (const callee of node.callees) {
      if (callee === to) {
        return [...path, to];
      }
      if (!visited.has(callee)) {
        queue.push({ fn: callee, path: [...path, callee] });
      }
    }
  }

  return null;
}
