/**
 * A minimal, position-tracking JSON parser.
 *
 * `JSON.parse` discards where each value came from, but the DSL needs to
 * point diagnostics at the exact byte range of the offending `invariants[i]`
 * entry (or its `condition` string) inside the spec file. This module parses
 * strict JSON into a lightweight AST that keeps a `{start, end}` offset pair
 * on every node, alongside `toJsValue`/`getAtPath` helpers to bridge back to
 * plain JS values where positions aren't needed.
 *
 * Deliberately not a general-purpose JSON5/JSONC parser — comments and
 * trailing commas are rejected, matching `JSON.parse` semantics exactly, so
 * spec files remain unambiguous and diffable.
 */

export class JsonAstParseError extends Error {
  constructor(message: string, readonly offset: number) {
    super(message);
    this.name = "JsonAstParseError";
  }
}

export interface JsonAstObjectEntry {
  key: string;
  keyStart: number;
  keyEnd: number;
  value: JsonAstNode;
}

export type JsonAstNode =
  | { type: "object"; start: number; end: number; entries: JsonAstObjectEntry[] }
  | { type: "array"; start: number; end: number; items: JsonAstNode[] }
  | { type: "string"; start: number; end: number; value: string }
  | { type: "number"; start: number; end: number; value: number }
  | { type: "boolean"; start: number; end: number; value: boolean }
  | { type: "null"; start: number; end: number };

class JsonParser {
  private pos = 0;
  constructor(private readonly text: string) {}

  parse(): JsonAstNode {
    this.skipWs();
    const node = this.parseValue();
    this.skipWs();
    if (this.pos !== this.text.length) {
      throw new JsonAstParseError(`Unexpected trailing content`, this.pos);
    }
    return node;
  }

  private skipWs(): void {
    while (this.pos < this.text.length && /\s/.test(this.text[this.pos])) this.pos++;
  }

  private parseValue(): JsonAstNode {
    this.skipWs();
    const c = this.text[this.pos];
    if (c === "{") return this.parseObject();
    if (c === "[") return this.parseArray();
    if (c === '"') return this.parseString();
    if (c === "t" || c === "f") return this.parseBoolean();
    if (c === "n") return this.parseNull();
    if (c === "-" || (c >= "0" && c <= "9")) return this.parseNumber();
    throw new JsonAstParseError(`Unexpected character '${c ?? "<eof>"}'`, this.pos);
  }

  private parseObject(): JsonAstNode {
    const start = this.pos;
    this.pos++; // {
    const entries: JsonAstObjectEntry[] = [];
    this.skipWs();
    if (this.text[this.pos] === "}") {
      this.pos++;
      return { type: "object", start, end: this.pos, entries };
    }
    for (;;) {
      this.skipWs();
      if (this.text[this.pos] !== '"') {
        throw new JsonAstParseError("Expected string key", this.pos);
      }
      const keyNode = this.parseString();
      this.skipWs();
      if (this.text[this.pos] !== ":") {
        throw new JsonAstParseError("Expected ':' after object key", this.pos);
      }
      this.pos++;
      const value = this.parseValue();
      entries.push({ key: keyNode.value, keyStart: keyNode.start, keyEnd: keyNode.end, value });
      this.skipWs();
      if (this.text[this.pos] === ",") {
        this.pos++;
        continue;
      }
      if (this.text[this.pos] === "}") {
        this.pos++;
        break;
      }
      throw new JsonAstParseError("Expected ',' or '}' in object", this.pos);
    }
    return { type: "object", start, end: this.pos, entries };
  }

  private parseArray(): JsonAstNode {
    const start = this.pos;
    this.pos++; // [
    const items: JsonAstNode[] = [];
    this.skipWs();
    if (this.text[this.pos] === "]") {
      this.pos++;
      return { type: "array", start, end: this.pos, items };
    }
    for (;;) {
      items.push(this.parseValue());
      this.skipWs();
      if (this.text[this.pos] === ",") {
        this.pos++;
        continue;
      }
      if (this.text[this.pos] === "]") {
        this.pos++;
        break;
      }
      throw new JsonAstParseError("Expected ',' or ']' in array", this.pos);
    }
    return { type: "array", start, end: this.pos, items };
  }

  private parseString(): { type: "string"; start: number; end: number; value: string } {
    const start = this.pos;
    this.pos++; // opening quote
    let value = "";
    while (this.pos < this.text.length && this.text[this.pos] !== '"') {
      const c = this.text[this.pos];
      if (c === "\\") {
        const next = this.text[this.pos + 1];
        const map: Record<string, string> = {
          '"': '"',
          "\\": "\\",
          "/": "/",
          b: "\b",
          f: "\f",
          n: "\n",
          r: "\r",
          t: "\t",
        };
        if (next === "u") {
          const hex = this.text.slice(this.pos + 2, this.pos + 6);
          value += String.fromCharCode(parseInt(hex, 16));
          this.pos += 6;
        } else if (next in map) {
          value += map[next];
          this.pos += 2;
        } else {
          throw new JsonAstParseError(`Invalid escape '\\${next}'`, this.pos);
        }
      } else {
        value += c;
        this.pos++;
      }
    }
    if (this.text[this.pos] !== '"') {
      throw new JsonAstParseError("Unterminated string", start);
    }
    this.pos++; // closing quote
    return { type: "string", start, end: this.pos, value };
  }

  private parseBoolean(): { type: "boolean"; start: number; end: number; value: boolean } {
    const start = this.pos;
    if (this.text.startsWith("true", this.pos)) {
      this.pos += 4;
      return { type: "boolean", start, end: this.pos, value: true };
    }
    if (this.text.startsWith("false", this.pos)) {
      this.pos += 5;
      return { type: "boolean", start, end: this.pos, value: false };
    }
    throw new JsonAstParseError("Invalid literal", start);
  }

  private parseNull(): { type: "null"; start: number; end: number } {
    const start = this.pos;
    if (this.text.startsWith("null", this.pos)) {
      this.pos += 4;
      return { type: "null", start, end: this.pos };
    }
    throw new JsonAstParseError("Invalid literal", start);
  }

  private parseNumber(): { type: "number"; start: number; end: number; value: number } {
    const start = this.pos;
    const re = /-?\d+(\.\d+)?([eE][+-]?\d+)?/y;
    re.lastIndex = this.pos;
    const match = re.exec(this.text);
    if (!match || match.index !== this.pos) {
      throw new JsonAstParseError("Invalid number", start);
    }
    this.pos += match[0].length;
    return { type: "number", start, end: this.pos, value: Number(match[0]) };
  }
}

/** Parse `text` as strict JSON, returning a position-tracking AST. Throws {@link JsonAstParseError}. */
export function parseJsonAst(text: string): JsonAstNode {
  return new JsonParser(text).parse();
}

/** Convert a {@link JsonAstNode} tree back into a plain JS value (discarding positions). */
export function toJsValue(node: JsonAstNode): unknown {
  switch (node.type) {
    case "object": {
      const obj: Record<string, unknown> = {};
      for (const entry of node.entries) obj[entry.key] = toJsValue(entry.value);
      return obj;
    }
    case "array":
      return node.items.map(toJsValue);
    case "string":
      return node.value;
    case "number":
      return node.value;
    case "boolean":
      return node.value;
    case "null":
      return null;
  }
}

/** Navigate a dotted/indexed path (e.g. `["invariants", 2, "condition"]`) within a parsed JSON AST. */
export function getAtPath(
  node: JsonAstNode | undefined,
  path: Array<string | number>,
): JsonAstNode | undefined {
  let current = node;
  for (const segment of path) {
    if (!current) return undefined;
    if (typeof segment === "number") {
      if (current.type !== "array") return undefined;
      current = current.items[segment];
    } else {
      if (current.type !== "object") return undefined;
      current = current.entries.find((e) => e.key === segment)?.value;
    }
  }
  return current;
}
