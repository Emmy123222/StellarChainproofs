import type { BinaryOperator, ExprNode } from "./expr-ast";

/**
 * Structural equivalence for expression trees.
 *
 * The evaluator needs to answer "does this `require(...)` guard already
 * enforce this invariant condition?" without a general theorem prover.
 * It does so by comparing *canonical forms*: two expressions canonicalize
 * to the same string iff they are equivalent up to
 *
 *  - commutativity of `==`, `!=`, `&&`, `||`, `+`, `*`
 *  - operand order for flipped comparisons (`a >= b` ≡ `b <= a`)
 *  - redundant parentheses / whitespace (the AST already discards these)
 *
 * This is intentionally conservative: two conditions that are
 * mathematically equivalent but not syntactically related after these
 * rules (e.g. `a + b >= c` vs `a >= c - b`) are reported as *not* matching.
 * That is a deliberate false-negative bias — see the DSL limitations
 * section in the docs — because silently accepting semantically-inferred
 * but unverified equivalences would defeat the "deterministic, bounded"
 * design goal.
 */

const COMMUTATIVE: ReadonlySet<BinaryOperator> = new Set(["==", "!=", "&&", "||", "+", "*"]);

const FLIP_MAP: Partial<Record<BinaryOperator, BinaryOperator>> = {
  ">": "<",
  ">=": "<=",
};

function canonicalNumber(value: number): string {
  // Avoid "1" vs "1.0" mismatches from differing literal spellings.
  return Number.isFinite(value) ? String(value) : "NaN";
}

/** Render an expression tree as a canonical string for equivalence comparison. */
export function canonicalize(node: ExprNode): string {
  switch (node.type) {
    case "NumberLiteral":
      return `#${canonicalNumber(node.value)}`;
    case "StringLiteral":
      return `s${JSON.stringify(node.value)}`;
    case "BooleanLiteral":
      return `b${node.value}`;
    case "Identifier":
      return `id:${node.name}`;
    case "MemberAccess":
      return `${canonicalize(node.object)}.${node.member}`;
    case "IndexAccess":
      return `${canonicalize(node.object)}[${canonicalize(node.index)}]`;
    case "Call": {
      const args = node.args.map(canonicalize).join(",");
      return `${canonicalize(node.callee)}(${args})`;
    }
    case "Unary":
      return `${node.operator}${canonicalize(node.argument)}`;
    case "Binary": {
      let operator = node.operator;
      let left = node.left;
      let right = node.right;
      const flipped = FLIP_MAP[operator];
      if (flipped) {
        operator = flipped;
        [left, right] = [right, left];
      }
      const leftStr = canonicalize(left);
      const rightStr = canonicalize(right);
      if (COMMUTATIVE.has(operator)) {
        const [a, b] = leftStr <= rightStr ? [leftStr, rightStr] : [rightStr, leftStr];
        return `(${a}${operator}${b})`;
      }
      return `(${leftStr}${operator}${rightStr})`;
    }
    default:
      return "?";
  }
}

/** True iff two expression trees are structurally equivalent (see module doc). */
export function expressionsEquivalent(a: ExprNode, b: ExprNode): boolean {
  return canonicalize(a) === canonicalize(b);
}

/**
 * Render an expression tree back into Solidity-like source text, for
 * human-facing output (`chainproof invariants explain`, error messages).
 * Unlike {@link canonicalize}, this preserves operand order and original
 * operators — it's for reading, not for equivalence comparison.
 */
export function prettyPrint(node: ExprNode): string {
  switch (node.type) {
    case "NumberLiteral":
      return node.raw;
    case "StringLiteral":
      return JSON.stringify(node.value);
    case "BooleanLiteral":
      return String(node.value);
    case "Identifier":
      return node.name;
    case "MemberAccess":
      return `${prettyPrint(node.object)}.${node.member}`;
    case "IndexAccess":
      return `${prettyPrint(node.object)}[${prettyPrint(node.index)}]`;
    case "Call":
      return `${prettyPrint(node.callee)}(${node.args.map(prettyPrint).join(", ")})`;
    case "Unary":
      return `${node.operator}${prettyPrint(node.argument)}`;
    case "Binary":
      return `${prettyPrint(node.left)} ${node.operator} ${prettyPrint(node.right)}`;
    default:
      return "?";
  }
}

/**
 * Collect the set of leaf identifier/member-access names referenced by an
 * expression, in canonical dotted form (`msg.sender`, `owner`, ...).
 * Used to find which state variables an invariant's condition depends on.
 */
export function collectReferencedNames(node: ExprNode): Set<string> {
  const names = new Set<string>();
  const visit = (n: ExprNode): void => {
    if (n.type === "Identifier") {
      names.add(n.name);
    } else if (n.type === "MemberAccess") {
      const chain = memberChain(n);
      if (chain) names.add(chain);
      visit(n.object);
    } else if (n.type === "IndexAccess") {
      const chain = memberChain(n);
      if (chain) names.add(chain);
      visit(n.object);
      visit(n.index);
    } else if (n.type === "Call") {
      visit(n.callee);
      for (const a of n.args) visit(a);
    } else if (n.type === "Unary") {
      visit(n.argument);
    } else if (n.type === "Binary") {
      visit(n.left);
      visit(n.right);
    }
  };
  visit(node);
  return names;
}

function memberChain(node: ExprNode): string | null {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberAccess") {
    const base = memberChain(node.object);
    return base ? `${base}.${node.member}` : null;
  }
  if (node.type === "IndexAccess") {
    // `balances[owner]` references the mapping `balances` itself.
    return memberChain(node.object);
  }
  return null;
}
