export type TokenType =
  | "number"
  | "string"
  | "identifier"
  | "punct"
  | "eof";

export interface Token {
  type: TokenType;
  value: string;
  start: number;
  end: number;
}

const PUNCTUATORS = [
  "&&",
  "||",
  "==",
  "!=",
  "<=",
  ">=",
  "(",
  ")",
  "[",
  "]",
  ".",
  ",",
  "!",
  "<",
  ">",
  "+",
  "-",
  "*",
  "/",
  "%",
] as const;

export class LexError extends Error {
  constructor(message: string, readonly offset: number) {
    super(message);
    this.name = "LexError";
  }
}

/**
 * Tokenize an invariant condition expression.
 * Deterministic, single-pass, linear-time — no backtracking.
 */
export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = source.length;

  const isDigit = (c: string) => c >= "0" && c <= "9";
  const isIdentStart = (c: string) => /[A-Za-z_$]/.test(c);
  const isIdentPart = (c: string) => /[A-Za-z0-9_$]/.test(c);

  while (i < n) {
    const c = source[i];

    if (c === " " || c === "\t" || c === "\n" || c === "\r") {
      i++;
      continue;
    }

    if (isDigit(c)) {
      const start = i;
      while (i < n && isDigit(source[i])) i++;
      if (source[i] === "." && isDigit(source[i + 1])) {
        i++;
        while (i < n && isDigit(source[i])) i++;
      }
      tokens.push({ type: "number", value: source.slice(start, i), start, end: i });
      continue;
    }

    if (isIdentStart(c)) {
      const start = i;
      while (i < n && isIdentPart(source[i])) i++;
      tokens.push({ type: "identifier", value: source.slice(start, i), start, end: i });
      continue;
    }

    if (c === '"' || c === "'") {
      const quote = c;
      const start = i;
      i++;
      let value = "";
      while (i < n && source[i] !== quote) {
        if (source[i] === "\\" && i + 1 < n) {
          value += source[i + 1];
          i += 2;
        } else {
          value += source[i];
          i++;
        }
      }
      if (i >= n) {
        throw new LexError("Unterminated string literal", start);
      }
      i++; // closing quote
      tokens.push({ type: "string", value, start, end: i });
      continue;
    }

    const two = source.slice(i, i + 2);
    if ((PUNCTUATORS as readonly string[]).includes(two)) {
      tokens.push({ type: "punct", value: two, start: i, end: i + 2 });
      i += 2;
      continue;
    }

    if ((PUNCTUATORS as readonly string[]).includes(c)) {
      tokens.push({ type: "punct", value: c, start: i, end: i + 1 });
      i++;
      continue;
    }

    throw new LexError(`Unexpected character '${c}'`, i);
  }

  tokens.push({ type: "eof", value: "", start: n, end: n });
  return tokens;
}
