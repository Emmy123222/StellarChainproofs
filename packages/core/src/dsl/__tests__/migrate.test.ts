import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { migrateInvariantSpecFile } from "../migrate";
import { CorruptArtifactError, MigrationError } from "../errors";
import { validateSpecSchema } from "../schema";
import { parseJsonAst, toJsValue } from "../json-ast";
import { DiagnosticBag } from "../diagnostics";
import { CURRENT_SPEC_SCHEMA_VERSION } from "../types";

function writeTemp(content: string, name = "spec.json"): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpinv-migrate-"));
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf-8");
  return file;
}

describe("migrateInvariantSpecFile", () => {
  it("is a no-op for a spec already on the current schema version", () => {
    const file = writeTemp(
      JSON.stringify({ schemaVersion: CURRENT_SPEC_SCHEMA_VERSION, name: "x", invariants: [] }),
    );
    const result = migrateInvariantSpecFile(file);
    expect(result.fromVersion).toBe(CURRENT_SPEC_SCHEMA_VERSION);
    expect(result.changes).toEqual([]);
  });

  it("migrates a legacy 0.9-shaped spec to the current schema and the result validates cleanly", () => {
    const file = writeTemp(
      JSON.stringify({
        version: "0.9",
        name: "legacy-spec",
        rules: [
          {
            id: "R1",
            kind: "access",
            title: "Only owner",
            severity: "high",
            contract: "Foo",
            function: "bar",
            expr: "msg.sender == owner",
          },
        ],
      }),
    );
    const result = migrateInvariantSpecFile(file);
    expect(result.fromVersion).toBe("0.9");
    expect(result.toVersion).toBe(CURRENT_SPEC_SCHEMA_VERSION);
    expect(result.spec.invariants[0].scope).toEqual({ contract: "Foo", function: "bar" });
    expect(result.spec.invariants[0].condition).toBe("msg.sender == owner");
    expect(result.changes.length).toBeGreaterThan(0);

    // The migrated output must itself be a valid spec.
    const text = JSON.stringify(result.spec);
    const ast = parseJsonAst(text);
    const diagnostics = new DiagnosticBag();
    validateSpecSchema(toJsValue(ast), ast, text, file, diagnostics);
    expect(diagnostics.hasErrors).toBe(false);
  });

  it("throws CorruptArtifactError for a file that isn't valid JSON", () => {
    const file = writeTemp("{ this is not json", "corrupt.json");
    expect(() => migrateInvariantSpecFile(file)).toThrow(CorruptArtifactError);
  });

  it("throws CorruptArtifactError for a missing file", () => {
    expect(() => migrateInvariantSpecFile("/nonexistent/spec.cpinv.json")).toThrow(CorruptArtifactError);
  });

  it("throws MigrationError for an unrecognized schemaVersion with no migration path", () => {
    const file = writeTemp(JSON.stringify({ schemaVersion: "2.5.0", name: "x", invariants: [] }));
    expect(() => migrateInvariantSpecFile(file)).toThrow(MigrationError);
  });

  it("throws MigrationError for a file with neither schemaVersion nor a legacy shape", () => {
    const file = writeTemp(JSON.stringify({ foo: "bar" }));
    expect(() => migrateInvariantSpecFile(file)).toThrow(MigrationError);
  });
});
