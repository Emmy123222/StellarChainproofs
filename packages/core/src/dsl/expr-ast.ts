/**
 * AST for the invariant condition expression language.
 *
 * This is the small, deterministic expression grammar used inside a spec's
 * `condition` (and reusable `predicates`) fields:
 *
 * ```
 * expr        := or
 * or          := and ("||" and)*
 * and         := equality ("&&" equality)*
 * equality    := comparison (("==" | "!=") comparison)*
 * comparison  := additive (("<" | "<=" | ">" | ">=") additive)*
 * additive    := multiplicative (("+" | "-") multiplicative)*
 * multiplicative := unary (("*" | "/" | "%") unary)*
 * unary       := ("!" | "-") unary | postfix
 * postfix     := primary ("." identifier | "(" args ")")*
 * primary     := number | string | boolean | identifier | "(" expr ")"
 * ```
 *
 * `old(x)` and user predicates like `isOwner()` are ordinary call
 * expressions resolved later by the binder — the grammar has no special
 * case for them.
 */
import type { SourceRange } from "./source";

export type ExprNodeType =
  | "NumberLiteral"
  | "StringLiteral"
  | "BooleanLiteral"
  | "Identifier"
  | "MemberAccess"
  | "IndexAccess"
  | "Call"
  | "Unary"
  | "Binary";

export interface ExprNodeBase {
  type: ExprNodeType;
  /** Offset range within the raw condition string (not the enclosing spec file). */
  range: { start: number; end: number };
}

export interface NumberLiteralNode extends ExprNodeBase {
  type: "NumberLiteral";
  value: number;
  raw: string;
}

export interface StringLiteralNode extends ExprNodeBase {
  type: "StringLiteral";
  value: string;
}

export interface BooleanLiteralNode extends ExprNodeBase {
  type: "BooleanLiteral";
  value: boolean;
}

export interface IdentifierNode extends ExprNodeBase {
  type: "Identifier";
  name: string;
}

export interface MemberAccessNode extends ExprNodeBase {
  type: "MemberAccess";
  object: ExprNode;
  member: string;
}

export interface IndexAccessNode extends ExprNodeBase {
  type: "IndexAccess";
  object: ExprNode;
  index: ExprNode;
}

export interface CallNode extends ExprNodeBase {
  type: "Call";
  callee: ExprNode;
  args: ExprNode[];
}

export const UNARY_OPERATORS = ["!", "-"] as const;
export type UnaryOperator = (typeof UNARY_OPERATORS)[number];

export interface UnaryNode extends ExprNodeBase {
  type: "Unary";
  operator: UnaryOperator;
  argument: ExprNode;
}

export const BINARY_OPERATORS = [
  "||",
  "&&",
  "==",
  "!=",
  "<",
  "<=",
  ">",
  ">=",
  "+",
  "-",
  "*",
  "/",
  "%",
] as const;
export type BinaryOperator = (typeof BINARY_OPERATORS)[number];

export interface BinaryNode extends ExprNodeBase {
  type: "Binary";
  operator: BinaryOperator;
  left: ExprNode;
  right: ExprNode;
}

export type ExprNode =
  | NumberLiteralNode
  | StringLiteralNode
  | BooleanLiteralNode
  | IdentifierNode
  | MemberAccessNode
  | IndexAccessNode
  | CallNode
  | UnaryNode
  | BinaryNode;

/** Convert an offset-based expression range into a full {@link SourceRange}. */
export function exprNodeSourceRange(
  node: ExprNode,
  file: string,
  fullText: string,
  baseOffset: number,
  offsetToPosition: (text: string, offset: number) => SourceRange["start"],
): SourceRange {
  return {
    file,
    start: offsetToPosition(fullText, baseOffset + node.range.start),
    end: offsetToPosition(fullText, baseOffset + node.range.end),
  };
}

/** Depth-first walk over an expression tree. */
export function walkExpr(node: ExprNode, visit: (node: ExprNode) => void): void {
  visit(node);
  switch (node.type) {
    case "MemberAccess":
      walkExpr(node.object, visit);
      break;
    case "IndexAccess":
      walkExpr(node.object, visit);
      walkExpr(node.index, visit);
      break;
    case "Call":
      walkExpr(node.callee, visit);
      for (const a of node.args) walkExpr(a, visit);
      break;
    case "Unary":
      walkExpr(node.argument, visit);
      break;
    case "Binary":
      walkExpr(node.left, visit);
      walkExpr(node.right, visit);
      break;
    default:
      break;
  }
}
