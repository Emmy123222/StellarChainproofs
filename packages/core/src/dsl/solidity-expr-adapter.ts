import type { ASTNode } from "../types";
import type { BinaryOperator, ExprNode, UnaryOperator } from "./expr-ast";
import { BINARY_OPERATORS, UNARY_OPERATORS } from "./expr-ast";

const SUPPORTED_BINARY = new Set<string>(BINARY_OPERATORS);
const SUPPORTED_UNARY = new Set<string>(UNARY_OPERATORS);

/**
 * Best-effort translation of a `@solidity-parser/parser` expression subtree
 * (as found inside `require(...)`, `assert(...)`, modifier bodies, and
 * `if (...) revert(...)` guards) into the same {@link ExprNode} shape used
 * by DSL conditions, so both sides can be compared with
 * {@link expressionsEquivalent}.
 *
 * Returns `null` for constructs the DSL expression language cannot
 * represent (assignments, ternaries, `new`, inline assembly, bitwise/shift
 * operators, etc.) rather than guessing — an unrepresentable guard simply
 * never matches, which is the conservative, false-negative-biased behavior
 * documented in expr-normalize.ts.
 */
export function solidityExprToDslNode(node: ASTNode): ExprNode | null {
  if (!node || typeof node !== "object") return null;
  const zeroRange = { start: 0, end: 0 };

  switch (node.type) {
    case "Identifier":
      return { type: "Identifier", name: node.name, range: zeroRange };

    case "MemberAccess": {
      const object = solidityExprToDslNode(node.expression);
      if (!object) return null;
      return { type: "MemberAccess", object, member: node.memberName, range: zeroRange };
    }

    case "NumberLiteral": {
      // Solidity allows `_` digit separators (`1_000_000`) that `Number()` doesn't parse.
      const value = Number(String(node.number).replace(/_/g, ""));
      if (Number.isNaN(value)) return null;
      return { type: "NumberLiteral", value, raw: String(node.number), range: zeroRange };
    }

    case "BooleanLiteral":
      return { type: "BooleanLiteral", value: !!node.value, range: zeroRange };

    case "StringLiteral":
      return { type: "StringLiteral", value: node.value ?? "", range: zeroRange };

    case "UnaryOperation": {
      if (!SUPPORTED_UNARY.has(node.operator)) return null;
      const argument = solidityExprToDslNode(node.subExpression);
      if (!argument) return null;
      return {
        type: "Unary",
        operator: node.operator as UnaryOperator,
        argument,
        range: zeroRange,
      };
    }

    case "BinaryOperation": {
      if (!SUPPORTED_BINARY.has(node.operator)) return null;
      const left = solidityExprToDslNode(node.left);
      const right = solidityExprToDslNode(node.right);
      if (!left || !right) return null;
      return {
        type: "Binary",
        operator: node.operator as BinaryOperator,
        left,
        right,
        range: zeroRange,
      };
    }

    case "FunctionCall": {
      const callee = solidityExprToDslNode(node.expression);
      if (!callee) return null;
      const args: ExprNode[] = [];
      for (const rawArg of node.arguments ?? []) {
        const arg = solidityExprToDslNode(rawArg);
        if (!arg) return null;
        args.push(arg);
      }
      return { type: "Call", callee, args, range: zeroRange };
    }

    case "IndexAccess": {
      const object = solidityExprToDslNode(node.base);
      const index = node.index !== undefined && node.index !== null ? solidityExprToDslNode(node.index) : null;
      if (!object || !index) return null;
      return { type: "IndexAccess", object, index, range: zeroRange };
    }

    case "TupleExpression": {
      // A parenthesized single expression, e.g. `(a == b)`.
      const components = node.components ?? [];
      if (components.length === 1) return solidityExprToDslNode(components[0]);
      return null;
    }

    default:
      return null;
  }
}

/**
 * Negate a boolean guard expression at the DSL-AST level, used to translate
 * `if (!cond) revert(...)` into the positive invariant `cond` the same way
 * `require(cond)` would express it, and vice versa.
 */
export function negate(node: ExprNode): ExprNode {
  if (node.type === "Unary" && node.operator === "!") {
    return node.argument;
  }
  return { type: "Unary", operator: "!", argument: node, range: node.range };
}
