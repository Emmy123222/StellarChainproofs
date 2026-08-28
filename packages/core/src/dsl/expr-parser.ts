import { tokenize, type Token } from "./expr-lexer";
import type {
  BinaryOperator,
  ExprNode,
  UnaryOperator,
} from "./expr-ast";

export class ExprParseError extends Error {
  constructor(message: string, readonly offset: number) {
    super(message);
    this.name = "ExprParseError";
  }
}

const BOOLEAN_LITERALS = new Set(["true", "false"]);

/** Recursive-descent parser over the condition expression grammar (see expr-ast.ts). */
class Parser {
  private pos = 0;
  constructor(private readonly tokens: Token[]) {}

  private peek(): Token {
    return this.tokens[this.pos];
  }

  private advance(): Token {
    const t = this.tokens[this.pos];
    if (t.type !== "eof") this.pos++;
    return t;
  }

  private expectPunct(value: string): Token {
    const t = this.peek();
    if (t.type !== "punct" || t.value !== value) {
      throw new ExprParseError(`Expected '${value}' but found '${t.value || "<eof>"}'`, t.start);
    }
    return this.advance();
  }

  private isPunct(value: string): boolean {
    const t = this.peek();
    return t.type === "punct" && t.value === value;
  }

  parse(): ExprNode {
    const node = this.parseOr();
    if (this.peek().type !== "eof") {
      throw new ExprParseError(
        `Unexpected trailing token '${this.peek().value}'`,
        this.peek().start,
      );
    }
    return node;
  }

  private parseOr(): ExprNode {
    let left = this.parseAnd();
    while (this.isPunct("||")) {
      const op = this.advance();
      const right = this.parseAnd();
      left = this.binary("||", left, right, op.start);
    }
    return left;
  }

  private parseAnd(): ExprNode {
    let left = this.parseEquality();
    while (this.isPunct("&&")) {
      const op = this.advance();
      const right = this.parseEquality();
      left = this.binary("&&", left, right, op.start);
    }
    return left;
  }

  private parseEquality(): ExprNode {
    let left = this.parseComparison();
    while (this.isPunct("==") || this.isPunct("!=")) {
      const op = this.advance();
      const right = this.parseComparison();
      left = this.binary(op.value as BinaryOperator, left, right, op.start);
    }
    return left;
  }

  private parseComparison(): ExprNode {
    let left = this.parseAdditive();
    while (
      this.isPunct("<") ||
      this.isPunct("<=") ||
      this.isPunct(">") ||
      this.isPunct(">=")
    ) {
      const op = this.advance();
      const right = this.parseAdditive();
      left = this.binary(op.value as BinaryOperator, left, right, op.start);
    }
    return left;
  }

  private parseAdditive(): ExprNode {
    let left = this.parseMultiplicative();
    while (this.isPunct("+") || this.isPunct("-")) {
      const op = this.advance();
      const right = this.parseMultiplicative();
      left = this.binary(op.value as BinaryOperator, left, right, op.start);
    }
    return left;
  }

  private parseMultiplicative(): ExprNode {
    let left = this.parseUnary();
    while (this.isPunct("*") || this.isPunct("/") || this.isPunct("%")) {
      const op = this.advance();
      const right = this.parseUnary();
      left = this.binary(op.value as BinaryOperator, left, right, op.start);
    }
    return left;
  }

  private parseUnary(): ExprNode {
    if (this.isPunct("!") || this.isPunct("-")) {
      const op = this.advance();
      const argument = this.parseUnary();
      return {
        type: "Unary",
        operator: op.value as UnaryOperator,
        argument,
        range: { start: op.start, end: argument.range.end },
      };
    }
    return this.parsePostfix();
  }

  private parsePostfix(): ExprNode {
    let node = this.parsePrimary();
    for (;;) {
      if (this.isPunct(".")) {
        this.advance();
        const name = this.peek();
        if (name.type !== "identifier") {
          throw new ExprParseError("Expected member name after '.'", name.start);
        }
        this.advance();
        node = {
          type: "MemberAccess",
          object: node,
          member: name.value,
          range: { start: node.range.start, end: name.end },
        };
        continue;
      }
      if (this.isPunct("(")) {
        this.advance();
        const args: ExprNode[] = [];
        if (!this.isPunct(")")) {
          args.push(this.parseOr());
          while (this.isPunct(",")) {
            this.advance();
            args.push(this.parseOr());
          }
        }
        const closing = this.expectPunct(")");
        node = {
          type: "Call",
          callee: node,
          args,
          range: { start: node.range.start, end: closing.end },
        };
        continue;
      }
      if (this.isPunct("[")) {
        this.advance();
        const index = this.parseOr();
        const closing = this.expectPunct("]");
        node = {
          type: "IndexAccess",
          object: node,
          index,
          range: { start: node.range.start, end: closing.end },
        };
        continue;
      }
      break;
    }
    return node;
  }

  private parsePrimary(): ExprNode {
    const t = this.peek();

    if (t.type === "number") {
      this.advance();
      return {
        type: "NumberLiteral",
        value: Number(t.value),
        raw: t.value,
        range: { start: t.start, end: t.end },
      };
    }

    if (t.type === "string") {
      this.advance();
      return { type: "StringLiteral", value: t.value, range: { start: t.start, end: t.end } };
    }

    if (t.type === "identifier") {
      if (BOOLEAN_LITERALS.has(t.value)) {
        this.advance();
        return {
          type: "BooleanLiteral",
          value: t.value === "true",
          range: { start: t.start, end: t.end },
        };
      }
      this.advance();
      return { type: "Identifier", name: t.value, range: { start: t.start, end: t.end } };
    }

    if (t.type === "punct" && t.value === "(") {
      this.advance();
      const inner = this.parseOr();
      const closing = this.expectPunct(")");
      return { ...inner, range: { start: t.start, end: closing.end } };
    }

    throw new ExprParseError(
      `Unexpected token '${t.value || "<eof>"}'`,
      t.start,
    );
  }

  private binary(
    operator: BinaryOperator,
    left: ExprNode,
    right: ExprNode,
    opStart: number,
  ): ExprNode {
    void opStart;
    return {
      type: "Binary",
      operator,
      left,
      right,
      range: { start: left.range.start, end: right.range.end },
    };
  }
}

/** Parse a condition/predicate expression string into an {@link ExprNode} tree. */
export function parseExpression(source: string): ExprNode {
  const tokens = tokenize(source);
  return new Parser(tokens).parse();
}
