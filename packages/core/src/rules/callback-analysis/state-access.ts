import type { ASTNode } from "../../types";
import { nodeLine, walkWithLoopContext } from "./ast-walk";
import type { StateAccessRecord } from "./types";

const WRITE_OPERATORS = new Set(["=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>="]);

/**
 * Resolve the base identifier/member name a (possibly nested)
 * assignment target refers to, e.g. `balances[msg.sender]` -> `balances`,
 * `vault.totalShares` -> `totalShares`.
 */
function resolveTargetNames(node: ASTNode | null | undefined, stateVarNames: Set<string>): string[] {
  const names: string[] = [];
  if (!node) return names;

  const rec = node as {
    type?: string;
    name?: string;
    memberName?: string;
    base?: ASTNode;
    expression?: ASTNode;
    components?: ASTNode[];
  };

  if (rec.type === "Identifier" && rec.name && stateVarNames.has(rec.name)) {
    names.push(rec.name);
  } else if (rec.type === "MemberAccess") {
    if (rec.memberName && stateVarNames.has(rec.memberName)) {
      names.push(rec.memberName);
    }
    names.push(...resolveTargetNames(rec.expression, stateVarNames));
  } else if (rec.type === "IndexAccess") {
    names.push(...resolveTargetNames((rec as unknown as { base?: ASTNode }).base, stateVarNames));
  } else if (rec.type === "TupleExpression" && Array.isArray(rec.components)) {
    for (const c of rec.components) names.push(...resolveTargetNames(c, stateVarNames));
  }

  return names;
}

/**
 * Collect every read/write of a known state variable within `fnNode`,
 * in document order, with 1-indexed source lines.
 *
 * A write is recorded whenever a state variable name is the resolved target
 * of an assignment/compound-assignment. All other appearances of a state
 * variable name (bare identifier or member access) are recorded as reads —
 * this over-approximates (an assignment target technically isn't "read" in
 * the value sense) which is the conservative, safe direction for a security
 * detector: it can only make the CEI-violation check stricter, never miss a
 * genuine read.
 */
export function collectStateAccesses(fnNode: ASTNode, stateVarNames: Set<string>): StateAccessRecord[] {
  if (stateVarNames.size === 0) return [];
  const accesses: StateAccessRecord[] = [];
  const seenKeys = new Set<string>();
  const writeTargets = new WeakSet<object>();

  walkWithLoopContext(fnNode, (node) => {
    const rec = node as { type?: string; operator?: string; left?: ASTNode };
    if (rec.type === "BinaryOperation" && rec.operator && WRITE_OPERATORS.has(rec.operator) && rec.left) {
      const targets = resolveTargetNames(rec.left, stateVarNames);
      const line = nodeLine(node);
      for (const varName of targets) {
        const key = `w:${varName}:${line}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          accesses.push({ varName, line, isWrite: true });
        }
      }
      markSubtreeAsWriteTarget(rec.left, writeTargets);
    }
  });

  walkWithLoopContext(fnNode, (node) => {
    const rec = node as { type?: string; name?: string; memberName?: string };
    if (writeTargets.has(node as object)) return;

    let varName: string | undefined;
    if (rec.type === "Identifier" && rec.name && stateVarNames.has(rec.name)) {
      varName = rec.name;
    } else if (rec.type === "MemberAccess" && rec.memberName && stateVarNames.has(rec.memberName)) {
      varName = rec.memberName;
    }
    if (!varName) return;

    const line = nodeLine(node);
    const key = `r:${varName}:${line}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      accesses.push({ varName, line, isWrite: false });
    }
  });

  return accesses.sort((a, b) => a.line - b.line);
}

function markSubtreeAsWriteTarget(node: ASTNode | null | undefined, set: WeakSet<object>): void {
  if (!node) return;
  walkWithLoopContext(node, (n) => {
    if (n && typeof n === "object") set.add(n as object);
  });
}

/**
 * Among state vars accessed in `accesses`, return the subset that are read
 * strictly before `line` but never written strictly before `line`. These
 * are candidates for "stale value used across a callback": whatever
 * consumed them before the callback saw a value that a Checks-Effects-
 * Interactions ordering would have already finalized.
 */
export function varsReadBeforeLineWithoutPriorWrite(
  accesses: StateAccessRecord[],
  line: number,
): Set<string> {
  const result = new Set<string>();
  const names = new Set(accesses.map((a) => a.varName));

  for (const name of names) {
    const readBefore = accesses.some((a) => a.varName === name && !a.isWrite && a.line < line);
    const writtenBefore = accesses.some((a) => a.varName === name && a.isWrite && a.line < line);
    if (readBefore && !writtenBefore) result.add(name);
  }

  return result;
}

/**
 * State vars written at-or-after `line` — i.e. finalized only after the
 * callback has already handed control to an external address. A non-empty
 * result for a var that's also touched earlier in the function is the
 * hallmark of a Checks-Effects-Interactions violation.
 */
export function varsWrittenAtOrAfterLine(accesses: StateAccessRecord[], line: number): Set<string> {
  const result = new Set<string>();
  for (const a of accesses) {
    if (a.isWrite && a.line >= line) result.add(a.varName);
  }
  return result;
}

export function firstReadLine(accesses: StateAccessRecord[], varName: string): number {
  return accesses.find((a) => a.varName === varName)?.line ?? 0;
}
