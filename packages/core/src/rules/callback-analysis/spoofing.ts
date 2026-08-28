import type { ASTNode } from "../../types";
import { nodeLine, walkWithLoopContext } from "./ast-walk";
import { CUSTOM_HOOK_NAME_PATTERN, RECEIVER_HOOK_SIGNATURES, SENSITIVE_STATE_NAME_PATTERN } from "./standards";
import type { AnalyzableFunction } from "./types";

export interface SpoofingFinding {
  fn: AnalyzableFunction;
  hookName: string;
  isStandardHook: boolean;
  sensitiveVars: string[];
  line: number;
}

function fnVisibility(node: ASTNode): string {
  return (node as { visibility?: string }).visibility ?? "default";
}

/**
 * `require(msg.sender == X)` / `if (msg.sender != X) revert(...)`-shaped
 * comparison anywhere in the function body. Deliberately lenient (any
 * comparison touching `msg.sender`, not just ones inside `require`) to
 * avoid false-positiving on equivalent access-control idioms (custom
 * errors, modifier-encoded checks the parser inlines differently, etc.) —
 * a spoofing finding should only fire when there is no sender-authentication
 * signal at all.
 */
function hasSenderAuthCheck(fn: AnalyzableFunction): boolean {
  let found = false;
  walkWithLoopContext(fn.node, (node) => {
    if (found) return;
    const rec = node as { type?: string; operator?: string; left?: ASTNode; right?: ASTNode };
    if (rec.type !== "BinaryOperation" || !["==", "!="].includes(rec.operator ?? "")) return;

    const sides = [rec.left, rec.right];
    const referencesSender = sides.some((side) => {
      let hit = false;
      walkWithLoopContext(side as ASTNode, (n) => {
        const r = n as { type?: string; memberName?: string };
        if (r.type === "MemberAccess" && r.memberName === "sender") hit = true;
      });
      return hit;
    });
    if (referencesSender) found = true;
  });
  return found;
}

const AUTH_MODIFIER_PATTERN = /^only|auth|restricted/i;

/** A custom modifier (e.g. `onlyToken`, `onlyVault`) is presumed to encode its own sender check. */
function hasAuthModifier(fn: AnalyzableFunction): boolean {
  const modifiers = (fn.node as { modifiers?: Array<{ name?: string }> }).modifiers ?? [];
  return modifiers.some((m) => m.name && AUTH_MODIFIER_PATTERN.test(m.name));
}

function collectSensitiveStateWrites(fn: AnalyzableFunction, stateVarNames: Set<string>): string[] {
  const hits = new Set<string>();
  walkWithLoopContext(fn.node, (node) => {
    const rec = node as { type?: string; operator?: string; left?: ASTNode };
    if (rec.type !== "BinaryOperation" || !rec.operator || !["=", "+=", "-="].includes(rec.operator)) return;

    walkWithLoopContext(rec.left as ASTNode, (n) => {
      const r = n as { type?: string; name?: string; memberName?: string };
      const name = r.type === "Identifier" ? r.name : r.type === "MemberAccess" ? r.memberName : undefined;
      if (name && stateVarNames.has(name) && SENSITIVE_STATE_NAME_PATTERN.test(name)) {
        hits.add(name);
      }
    });
  });
  return [...hits];
}

/**
 * Detects "callback spoofing": a contract exposes a public/external
 * function shaped like a standard (or clearly hook-named custom) callback
 * — `onERC721Received`, `tokensReceived`, a project-defined `onXHook`,
 * etc. — that mutates sensitive accounting state without first verifying
 * `msg.sender` is the token/vault/operator contract it expects to be
 * called back by. Anyone can call such a function directly and convince
 * the contract a transfer happened that never did.
 */
export function detectCallbackSpoofing(
  functions: AnalyzableFunction[],
  stateVarNames: Set<string>,
): SpoofingFinding[] {
  const findings: SpoofingFinding[] = [];
  const standardHookNames = new Set(RECEIVER_HOOK_SIGNATURES.map((h) => h.name));

  for (const fn of functions) {
    const visibility = fnVisibility(fn.node);
    if (visibility !== "public" && visibility !== "external" && visibility !== "default") continue;

    const isStandardHook = standardHookNames.has(fn.name);
    const isCustomHook = !isStandardHook && CUSTOM_HOOK_NAME_PATTERN.test(fn.name);
    if (!isStandardHook && !isCustomHook) continue;

    const sensitiveVars = collectSensitiveStateWrites(fn, stateVarNames);
    if (sensitiveVars.length === 0) continue;

    if (hasSenderAuthCheck(fn) || hasAuthModifier(fn)) continue;

    findings.push({
      fn,
      hookName: fn.name,
      isStandardHook,
      sensitiveVars,
      line: nodeLine(fn.node),
    });
  }

  return findings;
}
