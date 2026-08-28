import { parseExpression, ExprParseError } from "../expr-parser";
import { tokenize, LexError } from "../expr-lexer";
import { canonicalize, expressionsEquivalent, collectReferencedNames } from "../expr-normalize";

describe("expression lexer", () => {
  it("tokenizes operators, literals, and identifiers", () => {
    const tokens = tokenize(`msg.sender == owner && amount >= 10`);
    expect(tokens.map((t) => t.value)).toEqual([
      "msg", ".", "sender", "==", "owner", "&&", "amount", ">=", "10", "",
    ]);
  });

  it("throws LexError with an offset for an unexpected character", () => {
    expect(() => tokenize("a @ b")).toThrow(LexError);
    try {
      tokenize("a @ b");
    } catch (err) {
      expect((err as LexError).offset).toBe(2);
    }
  });

  it("supports single and double quoted strings with escapes", () => {
    const tokens = tokenize(`'it\\'s' == "a\\"b"`);
    expect(tokens[0].value).toBe("it's");
    expect(tokens[2].value).toBe('a"b');
  });
});

describe("expression parser", () => {
  it("parses precedence correctly: && binds tighter than ||", () => {
    const node = parseExpression("a || b && c");
    expect(node.type).toBe("Binary");
    if (node.type === "Binary") {
      expect(node.operator).toBe("||");
      expect(node.right.type).toBe("Binary");
    }
  });

  it("parses comparison, arithmetic, member access, and calls", () => {
    const node = parseExpression("balances[owner] >= totalSupply - reserve && isOwner()");
    expect(node.type).toBe("Binary");
  });

  it("parses member access chains", () => {
    const node = parseExpression("msg.sender");
    expect(node).toMatchObject({ type: "MemberAccess", member: "sender" });
  });

  it("parses unary operators", () => {
    const node = parseExpression("!paused && -1 == x");
    expect(node.type).toBe("Binary");
  });

  it("respects parentheses", () => {
    const a = canonicalize(parseExpression("(a + b) * c"));
    const b = canonicalize(parseExpression("a + b * c"));
    expect(a).not.toBe(b);
  });

  it("throws ExprParseError with an offset on malformed input", () => {
    expect(() => parseExpression("a ==")).toThrow(ExprParseError);
    expect(() => parseExpression("(a + b")).toThrow(ExprParseError);
    expect(() => parseExpression("a b")).toThrow(ExprParseError);
  });
});

describe("expression normalization", () => {
  it("treats commutative operators as order-independent", () => {
    expect(expressionsEquivalent(parseExpression("a == b"), parseExpression("b == a"))).toBe(true);
    expect(expressionsEquivalent(parseExpression("a && b"), parseExpression("b && a"))).toBe(true);
  });

  it("treats flipped comparisons as equivalent", () => {
    expect(expressionsEquivalent(parseExpression("a >= b"), parseExpression("b <= a"))).toBe(true);
    expect(expressionsEquivalent(parseExpression("a > b"), parseExpression("b < a"))).toBe(true);
  });

  it("does not treat non-commutative operators as order-independent", () => {
    expect(expressionsEquivalent(parseExpression("a - b"), parseExpression("b - a"))).toBe(false);
    expect(expressionsEquivalent(parseExpression("a / b"), parseExpression("b / a"))).toBe(false);
  });

  it("is conservative: does not infer algebraic equivalence", () => {
    // a + b >= c  is mathematically related to  a >= c - b  but not syntactically —
    // the evaluator is documented to be false-negative biased here.
    expect(expressionsEquivalent(parseExpression("a + b >= c"), parseExpression("a >= c - b"))).toBe(false);
  });

  it("collects referenced identifier/member names", () => {
    const names = collectReferencedNames(parseExpression("msg.sender == owner && balances[owner] > 0"));
    expect(names.has("msg.sender")).toBe(true);
    expect(names.has("owner")).toBe(true);
    expect(names.has("balances")).toBe(true);
  });
});
