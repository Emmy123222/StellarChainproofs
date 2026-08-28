import type { ASTNode } from "../../types";
import { nodeLine, walkWithLoopContext } from "./ast-walk";
import {
  CALLBACK_TRIGGER_HELPERS,
  CUSTOM_HOOK_NAME_PATTERN,
  KNOWN_ERC165_SELECTORS,
  RECEIVER_HOOK_NAMES,
  RECEIVER_HOOK_SIGNATURES,
  getReceiverHookSignature,
} from "./standards";
import type { AnalyzableFunction, CallbackKind, CallbackStandard, InterfaceEvidence } from "./types";

export interface DirectTrigger {
  standard: CallbackStandard;
  kind: CallbackKind;
  line: number;
  loopNode: ASTNode | null;
  evidence: InterfaceEvidence;
}

const CALLBACK_REGISTRY_NAME_PATTERN = /callback|hook|handler|listener|registry/i;

/**
 * Scan a single function body for statements that directly invoke a
 * standard receiver/sender/flash-callback hook, or a project-defined
 * callback registered through a hook registry mapping.
 *
 * Does not follow calls into other functions — see
 * {@link callback-graph.ts buildCallbackGraph} for cross-function
 * (helper-indirected) trigger resolution.
 */
export function findDirectCallbackTriggers(fn: AnalyzableFunction): DirectTrigger[] {
  const triggers: DirectTrigger[] = [];

  walkWithLoopContext(fn.node, (node, ctx) => {
    const rec = node as { type?: string; expression?: ASTNode; arguments?: ASTNode[] };
    if (rec.type !== "FunctionCall" || !rec.expression) return;

    const callee = rec.expression as { type?: string; memberName?: string; expression?: ASTNode };
    if (callee.type !== "MemberAccess" || !callee.memberName) return;

    const line = nodeLine(node);

    // Direct named invocation of a standard hook, e.g.
    // IERC721Receiver(to).onERC721Received(...) or receiver.tokensReceived(...)
    if (RECEIVER_HOOK_NAMES.has(callee.memberName)) {
      const sig = getReceiverHookSignature(callee.memberName)!;
      triggers.push({
        standard: sig.standard,
        kind: sig.kind,
        line,
        loopNode: ctx.loopNode,
        evidence: {
          kind: "function-signature",
          detail: `Direct call to ${callee.memberName}(...) matching the ${sig.standard} hook signature`,
          confidence: "high",
          line,
        },
      });
      return;
    }

    // Low-level call carrying a standard hook's selector, e.g.
    // to.call(abi.encodeWithSelector(IERC721Receiver.onERC721Received.selector, ...))
    if (callee.memberName === "call" && rec.arguments && rec.arguments.length > 0) {
      const hookName = findReceiverHookNameInSubtree(rec.arguments);
      if (hookName) {
        const sig = getReceiverHookSignature(hookName)!;
        triggers.push({
          standard: sig.standard,
          kind: sig.kind,
          line,
          loopNode: ctx.loopNode,
          evidence: {
            kind: "low-level-selector",
            detail: `Low-level .call() carrying the ${hookName} selector`,
            confidence: "medium",
            line,
          },
        });
        return;
      }
    }

    // Custom callback registration: invoking a hook-shaped function name on
    // an address pulled from a registry/handler mapping, e.g.
    // IHook(callbackHandlers[token]).onDeposit(...)
    if (
      CUSTOM_HOOK_NAME_PATTERN.test(callee.memberName) &&
      resolvesThroughRegistryMapping(callee.expression)
    ) {
      triggers.push({
        standard: "CUSTOM",
        kind: "custom-hook",
        line,
        loopNode: ctx.loopNode,
        evidence: {
          kind: "naming-heuristic",
          detail: `Call to registered handler's ${callee.memberName}(...) resolved through a callback/hook registry mapping`,
          confidence: "medium",
          line,
        },
      });
    }
  });

  return triggers;
}

function findReceiverHookNameInSubtree(nodes: ASTNode[]): string | undefined {
  let found: string | undefined;
  for (const n of nodes) {
    walkWithLoopContext(n, (node) => {
      if (found) return;
      const rec = node as { type?: string; memberName?: string; name?: string };
      if (rec.type === "MemberAccess" && rec.memberName && RECEIVER_HOOK_NAMES.has(rec.memberName)) {
        found = rec.memberName;
      }
    });
    if (found) break;
  }
  return found;
}

function resolvesThroughRegistryMapping(expr: ASTNode | undefined): boolean {
  if (!expr) return false;
  let matched = false;
  walkWithLoopContext(expr, (node) => {
    if (matched) return;
    const rec = node as { type?: string; base?: ASTNode; name?: string; memberName?: string };
    if (rec.type === "IndexAccess") {
      const base = (node as unknown as { base?: ASTNode }).base as
        | { name?: string; memberName?: string }
        | undefined;
      const baseName = base?.name ?? base?.memberName;
      if (baseName && CALLBACK_REGISTRY_NAME_PATTERN.test(baseName)) matched = true;
    }
  });
  return matched;
}

/**
 * If `fn`'s own name matches one of the well-known OpenZeppelin-style
 * dispatch-helper names, its entire body is treated as performing that
 * standard's callback — even if the concrete low-level call is nested
 * behind further indirection this analysis doesn't unwind. The synthetic
 * trigger is anchored at the function's first statement (or definition
 * line as fallback) and carries no loop context of its own, since
 * batch-ness is a property of how *callers* invoke this helper.
 */
export function triggerFromHelperName(fn: AnalyzableFunction): DirectTrigger | null {
  const helper = CALLBACK_TRIGGER_HELPERS.find((h) => h.functionNamePattern.test(fn.name));
  if (!helper) return null;

  const body = (fn.node as { body?: { statements?: ASTNode[] } }).body;
  const firstStmt = body?.statements?.[0];
  const line = nodeLine(firstStmt) || nodeLine(fn.node);

  return {
    standard: helper.standard,
    kind: helper.kind,
    line,
    loopNode: null,
    evidence: {
      kind: "helper-name",
      detail: `Function name "${fn.name}" matches the ${helper.detail}`,
      confidence: "high",
      line,
    },
  };
}

/**
 * Triggers within `fn`'s own body: direct detection when available, falling
 * back to the helper-name heuristic only when no concrete call site was
 * found. A function can match a helper name (e.g. `_checkOnERC721Received`)
 * *and* contain the literal hook invocation the direct scan already finds;
 * returning both would double-count the same callback as two edges.
 */
export function findCallbackTriggerSites(fn: AnalyzableFunction): DirectTrigger[] {
  const direct = findDirectCallbackTriggers(fn);
  if (direct.length > 0) return direct;

  const helperTrigger = triggerFromHelperName(fn);
  return helperTrigger ? [helperTrigger] : [];
}

/**
 * Find the innermost loop (if any) enclosing a call to `calleeName` within
 * `fn`'s body. Used to determine whether an indirect callback (reached
 * through one or more internal helper calls) is invoked once per loop
 * iteration.
 */
export function findCallSiteLoopContext(fn: AnalyzableFunction, calleeName: string): ASTNode | null {
  let loopNode: ASTNode | null = null;
  walkWithLoopContext(fn.node, (node, ctx) => {
    if (loopNode) return;
    const rec = node as { type?: string; expression?: ASTNode };
    if (rec.type !== "FunctionCall" || !rec.expression) return;
    const expr = rec.expression as { type?: string; name?: string };
    if (expr.type === "Identifier" && expr.name === calleeName) {
      loopNode = ctx.loopNode;
    }
  });
  return loopNode;
}

/**
 * Functions this contract itself implements that structurally match a
 * known receiver/callback hook signature (name + parameter count) — i.e.
 * this contract is a callback *target* for some other token/vault/flash
 * lender. Used both for ERC-165 cross-checking and for callback-spoofing
 * analysis (an unauthenticated implementation of one of these is directly
 * callable by anyone, not just the real token contract).
 */
export function detectImplementedReceiverHooks(
  functions: AnalyzableFunction[],
): Map<string, InterfaceEvidence[]> {
  const result = new Map<string, InterfaceEvidence[]>();

  for (const fn of functions) {
    const sig = RECEIVER_HOOK_SIGNATURES.find((h) => h.name === fn.name);
    if (!sig) continue;

    const params = (fn.node as { parameters?: unknown[] }).parameters ?? [];
    const confidence = params.length === sig.paramCount ? "high" : "medium";

    const evidence: InterfaceEvidence = {
      kind: "function-signature",
      detail: `Implements ${sig.name}(...) with ${params.length} parameter(s) (spec expects ${sig.paramCount})`,
      confidence,
      line: nodeLine(fn.node),
    };
    result.set(fn.name, [...(result.get(fn.name) ?? []), evidence]);
  }

  return result;
}

/**
 * True when the contract implements `supportsInterface(bytes4)` and its
 * body references at least one known receiver-hook ERC-165 interface ID —
 * i.e. it declares ERC-165 support for a standard it also implements
 * hooks for, rather than just having an empty/stub implementation.
 */
export function detectERC165Support(functions: AnalyzableFunction[]): InterfaceEvidence | null {
  const fn = functions.find((f) => f.name === "supportsInterface");
  if (!fn) return null;

  let matchesKnownSelector = false;
  walkWithLoopContext(fn.node, (node) => {
    // solidity-parser represents a `0x...` literal as a NumberLiteral whose
    // `number` field carries the full hex text (not a dedicated hex-literal
    // node type — that's reserved for the `hex"..."` string-literal form).
    const rec = node as { type?: string; number?: string };
    if (rec.type === "NumberLiteral" && rec.number?.toLowerCase().startsWith("0x")) {
      const normalized = rec.number.toLowerCase();
      if ([...KNOWN_ERC165_SELECTORS].some((sel) => normalized === sel.toLowerCase())) {
        matchesKnownSelector = true;
      }
    }
  });

  return {
    kind: "erc165-selector",
    detail: matchesKnownSelector
      ? "supportsInterface(bytes4) references a known receiver-hook interface ID"
      : "supportsInterface(bytes4) is implemented",
    confidence: matchesKnownSelector ? "high" : "low",
    line: nodeLine(fn.node),
  };
}
