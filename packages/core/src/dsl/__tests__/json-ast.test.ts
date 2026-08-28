import { parseJsonAst, toJsValue, getAtPath, JsonAstParseError } from "../json-ast";

describe("parseJsonAst", () => {
  it("parses nested objects/arrays with correct offsets", () => {
    const text = `{"a": [1, 2, {"b": "c"}]}`;
    const ast = parseJsonAst(text);
    expect(toJsValue(ast)).toEqual({ a: [1, 2, { b: "c" }] });

    const bNode = getAtPath(ast, ["a", 2, "b"]);
    expect(bNode?.type).toBe("string");
    expect(text.slice(bNode!.start, bNode!.end)).toBe('"c"');
  });

  it("handles escape sequences and unicode escapes in strings", () => {
    const ast = parseJsonAst(String.raw`{"s": "line1\nline2\tA"}`);
    expect(toJsValue(ast)).toEqual({ s: "line1\nline2\tA" });
  });

  it("parses booleans, null, and negative/decimal/exponent numbers", () => {
    const ast = parseJsonAst(`{"a": true, "b": false, "c": null, "d": -1.5e3}`);
    expect(toJsValue(ast)).toEqual({ a: true, b: false, c: null, d: -1500 });
  });

  it("throws JsonAstParseError with an offset for malformed JSON", () => {
    expect(() => parseJsonAst("{ a: 1 }")).toThrow(JsonAstParseError);
    expect(() => parseJsonAst("[1, 2,]")).toThrow(JsonAstParseError);
    expect(() => parseJsonAst('{"a": 1')).toThrow(JsonAstParseError);
    try {
      parseJsonAst("{ a: 1 }");
    } catch (err) {
      expect((err as JsonAstParseError).offset).toBeGreaterThanOrEqual(0);
    }
  });

  it("getAtPath returns undefined for a path that doesn't exist", () => {
    const ast = parseJsonAst(`{"a": 1}`);
    expect(getAtPath(ast, ["b"])).toBeUndefined();
    expect(getAtPath(ast, ["a", "nested"])).toBeUndefined();
  });
});
