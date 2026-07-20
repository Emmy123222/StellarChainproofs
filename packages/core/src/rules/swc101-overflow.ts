import { visit, getSnippet } from "../ast/parser";
import type { Finding, ASTNode } from "../types";
import { runSymbolicExec } from "./symbolic-exec";

/**
 * SWC-101: Integer Overflow and Underflow
 *
 * Replaces the original pragma-only heuristic with a lightweight symbolic
 * execution pass that:
 *
 *  1. Propagates range constraints from require/assert guards to eliminate
 *     false positives caused by manual bounds checks (e.g. require(a+b >= a)).
 *  2. Always analyzes `unchecked {}` blocks in Solidity >=0.8, fixing the
 *     false negative where explicit unchecked arithmetic was silently missed.
 *  3. Falls back to the original pragma-level flag for pre-0.8 code that
 *     has no constraints at all (preserves existing detection rate).
 */
export function detectIntegerOverflow(
  ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  const findings: Finding[] = [];
  let pragmaVersion = "";

  // ── Step 1: Extract pragma version ───────────────────────────────────────
  visit(ast, {
    PragmaDirective(node: ASTNode) {
      const pragma = node as { value?: string };
      if (pragma.value) pragmaVersion = pragma.value;
    },
  });

  if (!pragmaVersion) {
    const pragmaMatch = source.match(/pragma\s+solidity\s+([^;]+);/);
    if (pragmaMatch) {
      pragmaVersion = pragmaMatch[1];
    }
  }

  const is08Plus =
    pragmaVersion.includes("^0.8") ||
    pragmaVersion.includes(">=0.8") ||
    pragmaVersion.includes("0.8.") ||
    pragmaVersion.includes("0.9.");

  // ── Step 2: Symbolic execution pass ──────────────────────────────────────
  // For >=0.8: surfaces only unchecked-block overflows (new capability).
  // For <0.8 : surfaces all arithmetic that cannot be proven safe by guards.
  const symbolicCandidates = runSymbolicExec(ast, { is08Plus });

  // Build a lookup by line so we can attach snippets
  const candidateLines = new Set(symbolicCandidates.map((c) => c.line));

  // ── Step 3: Walk AST once more to attach snippets and emit findings ───────
  const emitted = new Set<number>(); // deduplicate by line

  visit(ast, {
    BinaryOperation(node: ASTNode) {
      const op = node as {
        operator?: string;
        loc?: { start?: { line?: number } };
      };

      if (!["+", "-", "*", "**", "+=", "-=", "*="].includes(op.operator ?? "")) return;

      const line = op.loc?.start?.line ?? 0;
      if (!candidateLines.has(line) || emitted.has(line)) return;
      emitted.add(line);

      const snippet = getSnippet(source, node);

      // Check if SafeMath is used on this line (pre-0.8 safety heuristic)
      if (
        !is08Plus &&
        (snippet.includes(".add(") ||
          snippet.includes(".sub(") ||
          snippet.includes(".mul("))
      ) {
        return;
      }

      const candidate = symbolicCandidates.find((c) => c.line === line);
      const inUnchecked = candidate?.inUncheckedBlock ?? false;

      if (inUnchecked) {
        findings.push({
          id: "CP-101",
          swcId: "SWC-101",
          title: "Integer overflow / underflow in unchecked block",
          description:
            `Arithmetic operation "${op.operator}" is inside an explicit \`unchecked\` block. ` +
            "Solidity >=0.8 disables overflow protection here; if operand values can exceed " +
            "type bounds the result silently wraps (same behaviour as pre-0.8).",
          recommendation:
            "Remove the `unchecked` wrapper unless you have verified (via require/assert " +
            "guards or type constraints) that overflow is impossible on this specific operation. " +
            "Prefer explicit bounds checks over unchecked arithmetic.",
          severity: "high",
          file: filePath,
          line,
          snippet,
        });
      } else {
        findings.push({
          id: "CP-101",
          swcId: "SWC-101",
          title: "Integer overflow / underflow",
          description:
            `Arithmetic operation "${op.operator}" on Solidity <0.8.0 without ` +
            "SafeMath or provable bounds constraints. If the value exceeds uint/int " +
            "bounds it silently wraps around.",
          recommendation:
            "Upgrade to Solidity ^0.8.0 where overflow reverts by default, or wrap " +
            "arithmetic with OpenZeppelin's SafeMath library.",
          severity: "high",
          file: filePath,
          line,
          snippet,
        });
      }
    },
  });

  return findings;
}

/**
 * SWC-104: Unchecked Call Return Value
 *
 * .call() and .send() return a boolean that must be checked.
 * Ignoring it silently swallows failures.
 */
export function detectUncheckedReturn(
  ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  const findings: Finding[] = [];

  visit(ast, {
    ExpressionStatement(node: ASTNode) {
      const exprNode = node as {
        expression?: ASTNode;
        loc?: { start?: { line?: number } };
      };
      const expr = exprNode.expression as
        | {
            type?: string;
            memberName?: string;
            loc?: { start?: { line?: number } };
          }
        | undefined;

      // A bare .call() / .send() not assigned to anything
      if (
        (expr?.type === "FunctionCall" &&
          JSON.stringify(expr).includes('"memberName":"call"')) ||
        (expr?.type === "FunctionCall" &&
          JSON.stringify(expr).includes('"memberName":"send"'))
      ) {
        const line = exprNode.loc?.start?.line ?? 0;
        findings.push({
          id: "CP-104",
          swcId: "SWC-104",
          title: "Unchecked call return value",
          description:
            ".call() and .send() return a boolean indicating success. " +
            "Ignoring this return value means failures are silently swallowed, " +
            "potentially leaving the contract in an inconsistent state.",
          recommendation:
            'Always check the return value: `(bool success, ) = addr.call{value: amount}(""); ' +
            'require(success, "Transfer failed");`. Prefer .transfer() for simple ETH sends ' +
            "if reentrancy is not a concern.",
          severity: "medium",
          file: filePath,
          line,
          snippet: getSnippet(source, node),
        });
      }
    },
  });

  return findings;
}
