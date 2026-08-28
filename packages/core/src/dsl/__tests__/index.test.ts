import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  scaffoldInvariantSpec,
  explainInvariant,
  checkInvariantsFromFile,
  validateInvariantSpecFile,
  serializeReport,
} from "../index";
import { parseInvariantSpecFile } from "../spec-parser";
import { SpecValidationError } from "../errors";
import { validateSpecSchema } from "../schema";
import { parseJsonAst, toJsValue } from "../json-ast";
import { DiagnosticBag } from "../diagnostics";

function writeTemp(content: string, name: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpinv-index-"));
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf-8");
  return file;
}

describe("scaffoldInvariantSpec", () => {
  it("produces a spec that passes schema validation as-is", () => {
    const raw = scaffoldInvariantSpec("my-project", "MyContract");
    const text = JSON.stringify(raw);
    const ast = parseJsonAst(text);
    const diagnostics = new DiagnosticBag();
    validateSpecSchema(toJsValue(ast), ast, text, "scaffold.cpinv.json", diagnostics);
    expect(diagnostics.hasErrors).toBe(false);
  });
});

describe("explainInvariant", () => {
  it("describes a resolved invariant including its expanded predicate", () => {
    const file = writeTemp(
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "explain-test",
        predicates: { isOwner: "msg.sender == owner" },
        invariants: [
          {
            id: "INV-1",
            kind: "access",
            title: "Only owner",
            severity: "high",
            scope: { contract: "Foo", function: "bar" },
            condition: "isOwner()",
            assumptions: ["owner is never zero"],
          },
        ],
      }),
      "explain.cpinv.json",
    );
    const { spec } = parseInvariantSpecFile(file);
    const text = explainInvariant(spec!, "INV-1");
    expect(text).toContain("INV-1");
    expect(text).toContain("Only owner");
    expect(text).toContain("owner is never zero");
    expect(text).toContain("isOwner()");
  });

  it("returns a helpful message for an unknown invariant id", () => {
    const file = writeTemp(
      JSON.stringify({ schemaVersion: "1.0.0", name: "x", invariants: [] }),
      "empty.cpinv.json",
    );
    const { spec } = parseInvariantSpecFile(file);
    const text = explainInvariant(spec!, "NOPE");
    expect(text).toContain("not found");
  });
});

describe("validateInvariantSpecFile", () => {
  it("reports valid:false for a spec with schema errors", () => {
    const file = writeTemp(JSON.stringify({ name: "x" }), "invalid.cpinv.json");
    const { valid, diagnostics } = validateInvariantSpecFile(file);
    expect(valid).toBe(false);
    expect(diagnostics.length).toBeGreaterThan(0);
  });

  it("reports valid:true for a well-formed spec", () => {
    const file = writeTemp(
      JSON.stringify({
        schemaVersion: "1.0.0",
        name: "x",
        invariants: [
          { id: "I1", kind: "event", title: "t", severity: "low", scope: { contract: "F", function: "g" }, event: "E" },
        ],
      }),
      "valid.cpinv.json",
    );
    const { valid } = validateInvariantSpecFile(file);
    expect(valid).toBe(true);
  });
});

describe("checkInvariantsFromFile", () => {
  it("throws SpecValidationError for a spec that fails to parse", async () => {
    const file = writeTemp(JSON.stringify({ name: "x" }), "invalid2.cpinv.json");
    await expect(checkInvariantsFromFile(file, { targets: ["."] })).rejects.toThrow(SpecValidationError);
  });
});

describe("serializeReport", () => {
  it("produces deterministic, key-sorted JSON", () => {
    const report = {
      resultSchemaVersion: "1.0.0",
      specName: "x",
      specSchemaVersion: "1.0.0",
      generatedAt: "2024-01-01T00:00:00.000Z",
      targets: ["a.sol"],
      results: [],
      diagnostics: [],
      summary: { pass: 0, fail: 0, error: 0, timeout: 0, skipped: 0, total: 0 },
      bounded: { timeExceeded: false, stepsExceededIds: [] },
    };
    const a = serializeReport(report);
    const b = serializeReport({ ...report, targets: ["a.sol"] });
    expect(a).toBe(b);
    expect(a.indexOf('"bounded"')).toBeLessThan(a.indexOf('"diagnostics"'));
  });
});
