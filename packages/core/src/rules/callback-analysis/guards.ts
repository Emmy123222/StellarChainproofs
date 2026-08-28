import type { ASTNode } from "../../types";
import { nodeLine, walkWithLoopContext } from "./ast-walk";
import { REENTRANCY_GUARD_MODIFIER_PATTERN, TRUSTED_RECEIVER_NAME_PATTERN } from "./standards";
import type { AnalyzableFunction, CallbackEdge, CallbackKind, GuardEvidence } from "./types";

function fnModifiers(fn: AnalyzableFunction): Array<{ name?: string }> {
  return (fn.node as { modifiers?: Array<{ name?: string }> }).modifiers ?? [];
}

/** `nonReentrant` (or equivalent) OpenZeppelin-style modifier applied to the function. */
export function reentrancyGuardModifier(fn: AnalyzableFunction): GuardEvidence | null {
  const match = fnModifiers(fn).find((m) => m.name && REENTRANCY_GUARD_MODIFIER_PATTERN.test(m.name));
  if (!match?.name) return null;
  return {
    kind: "reentrancy-guard-modifier",
    detail: `Function is guarded by modifier "${match.name}"`,
    line: nodeLine(fn.node),
  };
}

/**
 * Hand-rolled mutex: a boolean state variable checked with
 * `require(!locked)` (or `if (locked) revert(...)`) before the callback,
 * set true before it, and set false after it, all within the same
 * function. Functionally equivalent to a reentrancy-guard modifier.
 */
export function manualMutexGuard(fn: AnalyzableFunction, edgeLine: number): GuardEvidence | null {
  const body = (fn.node as { body?: { statements?: ASTNode[] } }).body;
  const statements = body?.statements ?? [];
  if (statements.length === 0) return null;

  let lockVar: string | undefined;

  // require(!locked, ...) / require(locked == false, ...) as an early check.
  for (const stmt of statements.slice(0, 3)) {
    walkWithLoopContext(stmt, (node) => {
      if (lockVar) return;
      const rec = node as { type?: string; expression?: ASTNode };
      if (rec.type !== "FunctionCall") return;
      const callee = (rec as { expression?: { name?: string } }).expression;
      if (callee?.name !== "require") return;

      const args = (rec as unknown as { arguments?: ASTNode[] }).arguments ?? [];
      const cond = args[0] as { type?: string; operator?: string; subExpression?: ASTNode; left?: ASTNode } | undefined;
      if (!cond) return;

      if (cond.type === "UnaryOperation" && cond.operator === "!") {
        const target = cond.subExpression as { type?: string; name?: string } | undefined;
        if (target?.type === "Identifier" && target.name) lockVar = target.name;
      } else if (cond.type === "BinaryOperation" && cond.operator === "==") {
        const left = cond.left as { type?: string; name?: string } | undefined;
        if (left?.type === "Identifier" && left.name) lockVar = left.name;
      }
    });
    if (lockVar) break;
  }

  if (!lockVar) return null;

  let setTrueBefore = false;
  let setFalseAfter = false;
  walkWithLoopContext(fn.node, (node) => {
    const rec = node as { type?: string; operator?: string; left?: ASTNode; right?: ASTNode };
    if (rec.type !== "BinaryOperation" || rec.operator !== "=") return;
    const left = rec.left as { type?: string; name?: string } | undefined;
    if (left?.type !== "Identifier" || left.name !== lockVar) return;

    const right = rec.right as { type?: string; value?: boolean } | undefined;
    const line = nodeLine(node);
    if (right?.type === "BooleanLiteral" && right.value === true && line < edgeLine) setTrueBefore = true;
    if (right?.type === "BooleanLiteral" && right.value === false && line >= edgeLine) setFalseAfter = true;
  });

  if (!setTrueBefore || !setFalseAfter) return null;

  return {
    kind: "manual-mutex",
    detail: `Function is protected by a hand-rolled mutex on state variable "${lockVar}"`,
    line: nodeLine(fn.node),
  };
}

/**
 * A `require`/`if (...) revert` before `edgeLine` that checks the callback
 * target against a state variable or function whose name suggests a
 * trust/allowlist mapping — e.g. `require(trustedReceivers[to])`.
 */
export function trustedReceiverGuard(fn: AnalyzableFunction, edgeLine: number): GuardEvidence | null {
  let found: GuardEvidence | null = null;

  walkWithLoopContext(fn.node, (node) => {
    if (found) return;
    const line = nodeLine(node);
    if (line === 0 || line >= edgeLine) return;

    const rec = node as { type?: string; expression?: ASTNode };
    if (rec.type !== "FunctionCall") return;
    const callee = (rec as { expression?: { name?: string } }).expression;
    if (callee?.name !== "require" && callee?.name !== "assert") return;

    const args = (rec as unknown as { arguments?: ASTNode[] }).arguments ?? [];
    const cond = args[0];
    if (!cond) return;

    walkWithLoopContext(cond, (inner) => {
      if (found) return;
      const innerRec = inner as { type?: string; name?: string; memberName?: string };
      const name = innerRec.type === "Identifier" ? innerRec.name : innerRec.memberName;
      if (name && TRUSTED_RECEIVER_NAME_PATTERN.test(name)) {
        found = {
          kind: "trusted-receiver-allowlist",
          detail: `Callback target is checked against "${name}" before the callback (line ${line})`,
          line,
        };
      }
    });
  });

  return found;
}

/**
 * `require(target.code.length == 0)` / `!target.isContract()`-style guard
 * before the callback: if the recipient can only ever be an EOA, no
 * receiver-hook callback can actually fire.
 */
export function eoaOnlyGuard(fn: AnalyzableFunction, edgeLine: number): GuardEvidence | null {
  let found: GuardEvidence | null = null;

  walkWithLoopContext(fn.node, (node) => {
    if (found) return;
    const line = nodeLine(node);
    if (line === 0 || line >= edgeLine) return;

    const rec = node as { type?: string; memberName?: string; expression?: ASTNode };
    if (rec.type !== "MemberAccess") return;

    if (rec.memberName === "isContract") {
      found = {
        kind: "eoa-only-check",
        detail: `Recipient contract-code check ("isContract") appears before the callback (line ${line})`,
        line,
      };
      return;
    }

    // `<addr>.code.length` — the modern (>=0.8.1) EOA-check idiom. Matched
    // narrowly (base must itself be a `.code` MemberAccess) so an
    // unrelated array/bytes `.length` access earlier in the function
    // (e.g. a batch loop bound) isn't mistaken for a recipient check.
    if (rec.memberName === "length") {
      const base = rec.expression as { type?: string; memberName?: string } | undefined;
      if (base?.type === "MemberAccess" && base.memberName === "code") {
        found = {
          kind: "eoa-only-check",
          detail: `Recipient contract-code check ("code.length") appears before the callback (line ${line})`,
          line,
        };
      }
    }
  });

  return found;
}

/**
 * Flash-loan/mint specific: a post-callback `require`/`if (...) revert`
 * comparing a balance-after value against a balance-before value plus a
 * fee — the standard atomicity invariant that makes an intentional
 * mid-function external call to a borrower-controlled contract safe.
 */
export function atomicInvariantGuard(fn: AnalyzableFunction, edgeLine: number): GuardEvidence | null {
  let found: GuardEvidence | null = null;

  walkWithLoopContext(fn.node, (node) => {
    if (found) return;
    const line = nodeLine(node);
    if (line === 0 || line <= edgeLine) return;

    const rec = node as { type?: string; expression?: ASTNode };
    if (rec.type !== "FunctionCall") return;
    const callee = (rec as { expression?: { name?: string } }).expression;
    if (callee?.name !== "require" && callee?.name !== "assert") return;

    const args = (rec as unknown as { arguments?: ASTNode[] }).arguments ?? [];
    const cond = args[0] as { type?: string; operator?: string } | undefined;
    if (cond?.type === "BinaryOperation" && [">=", ">", "=="].includes(cond.operator ?? "")) {
      const containsAddition = containsOperator(cond as unknown as ASTNode, "+");
      const referencesBalance = /balance|amount|repay|owed/i.test(JSON.stringify(cond));
      if (containsAddition && referencesBalance) {
        found = {
          kind: "atomic-invariant-check",
          detail: `Post-callback repayment/invariant check found at line ${line}`,
          line,
        };
      }
    }
  });

  return found;
}

function containsOperator(node: ASTNode, operator: string): boolean {
  let found = false;
  walkWithLoopContext(node, (n) => {
    const rec = n as { type?: string; operator?: string };
    if (rec.type === "BinaryOperation" && rec.operator === operator) found = true;
  });
  return found;
}

/**
 * Evaluate every recognized guard against a specific callback edge, in the
 * context of the function whose CEI ordering is under evaluation
 * (`entryFn`). Returns the full list of guards that apply — callers decide
 * which combination is sufficient to suppress a given finding category.
 */
export function evaluateGuards(entryFn: AnalyzableFunction, edge: CallbackEdge): GuardEvidence[] {
  const guards: GuardEvidence[] = [];

  const modifierGuard = reentrancyGuardModifier(entryFn);
  if (modifierGuard) guards.push(modifierGuard);

  const mutex = manualMutexGuard(entryFn, edge.entryCallSiteLine);
  if (mutex) guards.push(mutex);

  const trusted = trustedReceiverGuard(entryFn, edge.entryCallSiteLine);
  if (trusted) guards.push(trusted);

  const eoaOnly = eoaOnlyGuard(entryFn, edge.entryCallSiteLine);
  if (eoaOnly) guards.push(eoaOnly);

  if (edge.kind === "flash-callback") {
    const invariant = atomicInvariantGuard(entryFn, edge.entryCallSiteLine);
    if (invariant) guards.push(invariant);
  }

  return guards;
}

/** Guard kinds that fully suppress CEI / cross-function / read-only findings for non-flash callbacks. */
const SUPPRESSING_GUARD_KINDS = new Set([
  "reentrancy-guard-modifier",
  "manual-mutex",
  "trusted-receiver-allowlist",
  "eoa-only-check",
]);

export function isSuppressedByGuards(guards: GuardEvidence[], kind: CallbackKind): boolean {
  if (kind === "flash-callback") {
    return guards.some((g) => g.kind === "atomic-invariant-check");
  }
  return guards.some((g) => SUPPRESSING_GUARD_KINDS.has(g.kind));
}
