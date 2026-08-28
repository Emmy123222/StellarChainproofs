import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { parseInvariantSpecFile } from "../spec-parser";
import { SpecParseError } from "../errors";

function writeTempSpec(name: string, content: string, dir?: string): { file: string; dir: string } {
  const tmpDir = dir ?? fs.mkdtempSync(path.join(os.tmpdir(), "cpinv-"));
  const file = path.join(tmpDir, name);
  fs.writeFileSync(file, content, "utf-8");
  return { file, dir: tmpDir };
}

const VALID_SPEC = JSON.stringify({
  schemaVersion: "1.0.0",
  name: "test-spec",
  invariants: [
    {
      id: "INV-1",
      kind: "access",
      title: "Only owner",
      severity: "high",
      scope: { contract: "Foo", function: "bar" },
      condition: "msg.sender == owner",
    },
  ],
});

describe("parseInvariantSpecFile", () => {
  it("parses a well-formed spec into a fully-bound InvariantSpec", () => {
    const { file } = writeTempSpec("valid.cpinv.json", VALID_SPEC);
    const { spec, diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics).toEqual([]);
    expect(spec).toBeDefined();
    expect(spec!.invariants).toHaveLength(1);
    expect(spec!.invariants[0].condition?.type).toBe("Binary");
  });

  it("throws SpecParseError for a missing file", () => {
    expect(() => parseInvariantSpecFile("/nonexistent/path/spec.cpinv.json")).toThrow(SpecParseError);
  });

  it("reports DSL001 for malformed JSON without throwing", () => {
    const { file } = writeTempSpec("broken.cpinv.json", "{ not valid json ");
    const { spec, diagnostics } = parseInvariantSpecFile(file);
    expect(spec).toBeUndefined();
    expect(diagnostics.some((d) => d.code === "DSL001")).toBe(true);
  });

  it("reports DSL003 for a missing schemaVersion", () => {
    const { file } = writeTempSpec(
      "no-version.cpinv.json",
      JSON.stringify({ name: "x", invariants: [] }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics.some((d) => d.code === "DSL003")).toBe(true);
  });

  it("reports DSL003 for an unsupported schemaVersion", () => {
    const { file } = writeTempSpec(
      "bad-version.cpinv.json",
      JSON.stringify({ schemaVersion: "99.0.0", name: "x", invariants: [] }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics.some((d) => d.code === "DSL003")).toBe(true);
  });

  it("reports DSL020 when a required scope field is missing", () => {
    const { file } = writeTempSpec(
      "missing-scope.cpinv.json",
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "x",
        invariants: [
          {
            id: "INV-1",
            kind: "access",
            title: "t",
            severity: "high",
            scope: { contract: "Foo" }, // missing function, required for 'access'
            condition: "true",
          },
        ],
      }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics.some((d) => d.code === "DSL020")).toBe(true);
  });

  it("reports DSL011 for duplicate invariant ids", () => {
    const { file } = writeTempSpec(
      "dup.cpinv.json",
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "x",
        invariants: [
          { id: "INV-1", kind: "access", title: "a", severity: "high", scope: { contract: "F", function: "g" }, condition: "true" },
          { id: "INV-1", kind: "access", title: "b", severity: "high", scope: { contract: "F", function: "h" }, condition: "true" },
        ],
      }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics.some((d) => d.code === "DSL011")).toBe(true);
  });

  it("reports DSL004 with a source range for a malformed condition expression", () => {
    const { file } = writeTempSpec(
      "bad-expr.cpinv.json",
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "x",
        invariants: [
          { id: "INV-1", kind: "access", title: "a", severity: "high", scope: { contract: "F", function: "g" }, condition: "a ==" },
        ],
      }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    const diag = diagnostics.find((d) => d.code === "DSL004");
    expect(diag).toBeDefined();
    expect(diag!.range?.file).toBe(file);
    expect(diag!.range!.start.line).toBeGreaterThan(0);
  });

  it("reports DSL006/DSL007 for unknown or misused predicate calls", () => {
    const { file } = writeTempSpec(
      "unknown-pred.cpinv.json",
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "x",
        predicates: { isOwner: "msg.sender == owner" },
        invariants: [
          { id: "INV-1", kind: "access", title: "a", severity: "high", scope: { contract: "F", function: "g" }, condition: "notDefined()" },
          { id: "INV-2", kind: "access", title: "b", severity: "high", scope: { contract: "F", function: "h" }, condition: "isOwner(1)" },
        ],
      }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics.some((d) => d.code === "DSL006")).toBe(true);
    expect(diagnostics.some((d) => d.code === "DSL007")).toBe(true);
  });

  it("detects a direct recursive predicate definition (DSL008)", () => {
    const { file } = writeTempSpec(
      "recursive.cpinv.json",
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "x",
        predicates: { a: "b()", b: "a()" },
        invariants: [
          { id: "INV-1", kind: "access", title: "t", severity: "high", scope: { contract: "F", function: "g" }, condition: "a()" },
        ],
      }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics.some((d) => d.code === "DSL008")).toBe(true);
  });

  it("detects a self-recursive predicate definition (DSL008)", () => {
    const { file } = writeTempSpec(
      "self-recursive.cpinv.json",
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "x",
        predicates: { a: "a()" },
        invariants: [
          { id: "INV-1", kind: "access", title: "t", severity: "high", scope: { contract: "F", function: "g" }, condition: "a()" },
        ],
      }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics.some((d) => d.code === "DSL008")).toBe(true);
  });

  it("resolves imports and merges predicates from them", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpinv-import-"));
    writeTempSpec(
      "common.cpinv.json",
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "common",
        predicates: { isOwner: "msg.sender == owner" },
        invariants: [],
      }),
      dir,
    );
    const { file } = writeTempSpec(
      "root.cpinv.json",
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "root",
        imports: ["./common.cpinv.json"],
        invariants: [
          { id: "INV-1", kind: "access", title: "t", severity: "high", scope: { contract: "F", function: "g" }, condition: "isOwner()" },
        ],
      }),
      dir,
    );
    const { spec, diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics).toEqual([]);
    expect(spec!.predicates.has("isOwner")).toBe(true);
  });

  it("detects an import cycle (DSL009)", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpinv-cycle-"));
    writeTempSpec(
      "a.cpinv.json",
      JSON.stringify({ schemaVersion: "1.0.0", name: "a", imports: ["./b.cpinv.json"], invariants: [] }),
      dir,
    );
    const { file: bFile } = writeTempSpec(
      "b.cpinv.json",
      JSON.stringify({ schemaVersion: "1.0.0", name: "b", imports: ["./a.cpinv.json"], invariants: [] }),
      dir,
    );
    const { diagnostics } = parseInvariantSpecFile(bFile);
    expect(diagnostics.some((d) => d.code === "DSL009")).toBe(true);
  });

  it("reports DSL010 for an import that cannot be read", () => {
    const { file } = writeTempSpec(
      "missing-import.cpinv.json",
      JSON.stringify({ schemaVersion: "1.0.0", name: "x", imports: ["./does-not-exist.cpinv.json"], invariants: [] }),
    );
    const { diagnostics } = parseInvariantSpecFile(file);
    expect(diagnostics.some((d) => d.code === "DSL010")).toBe(true);
  });
});
