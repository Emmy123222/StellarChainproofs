import * as fs from "fs";
import * as path from "path";
import { parseJsonAst, toJsValue, JsonAstParseError } from "./json-ast";
import { CURRENT_SPEC_SCHEMA_VERSION } from "./types";
import type { InvariantSpecFileRaw } from "./types";
import { CorruptArtifactError, MigrationError } from "./errors";

export interface MigrationResult {
  fromVersion: string;
  toVersion: string;
  spec: InvariantSpecFileRaw;
  /** Human-readable list of transformations applied, for the CLI/PR description. */
  changes: string[];
}

interface LegacyInvariant {
  id: string;
  kind?: string;
  title?: string;
  description?: string;
  severity?: string;
  contract?: string;
  function?: string;
  expr?: string;
  assumptions?: string[];
  references?: string[];
}

interface LegacySpec {
  version?: string;
  name?: string;
  description?: string;
  rules?: LegacyInvariant[];
}

/**
 * Migrate a `"0.9"` pre-release spec (flat `contract`/`function` fields,
 * `rules[].expr` instead of `invariants[].condition`, top-level `version`
 * instead of `schemaVersion`) to the current `"1.0.0"` schema.
 *
 * `"0.9"` was never published as a stable format — this migration exists so
 * specs authored against early drafts of this feature (and any fixtures
 * generated from them) upgrade cleanly instead of becoming permanently
 * unreadable, which is the corruption-handling guarantee required for any
 * versioned spec/config format in this codebase.
 */
function migrateFrom09(legacy: LegacySpec): MigrationResult {
  const changes: string[] = [
    "renamed top-level 'version' -> 'schemaVersion'",
    "renamed 'rules' -> 'invariants'",
    "nested 'contract'/'function' fields under 'scope'",
    "renamed 'expr' -> 'condition'",
  ];

  const invariants = (legacy.rules ?? []).map((rule) => ({
    id: rule.id,
    kind: (rule.kind ?? "access") as InvariantSpecFileRaw["invariants"][number]["kind"],
    title: rule.title ?? rule.id,
    description: rule.description,
    severity: (rule.severity ?? "medium") as InvariantSpecFileRaw["invariants"][number]["severity"],
    scope: { contract: rule.contract ?? "", function: rule.function },
    condition: rule.expr,
    assumptions: rule.assumptions ?? [],
    references: rule.references ?? [],
  }));

  return {
    fromVersion: legacy.version ?? "0.9",
    toVersion: CURRENT_SPEC_SCHEMA_VERSION,
    spec: {
      schemaVersion: CURRENT_SPEC_SCHEMA_VERSION,
      name: legacy.name ?? "migrated-spec",
      description: legacy.description,
      invariants,
    },
    changes,
  };
}

/**
 * Read, parse, and migrate an on-disk spec file to
 * {@link CURRENT_SPEC_SCHEMA_VERSION}. Throws {@link CorruptArtifactError}
 * for unreadable/malformed JSON and {@link MigrationError} for a version
 * this build doesn't know how to migrate from.
 */
export function migrateInvariantSpecFile(filePath: string): MigrationResult {
  const absolutePath = path.resolve(filePath);
  let text: string;
  try {
    text = fs.readFileSync(absolutePath, "utf-8");
  } catch (err) {
    throw new CorruptArtifactError(
      `Could not read spec file for migration: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  let value: unknown;
  try {
    value = toJsValue(parseJsonAst(text));
  } catch (err) {
    const offset = err instanceof JsonAstParseError ? err.offset : undefined;
    throw new CorruptArtifactError(
      `Spec file is not valid JSON${offset !== undefined ? ` (offset ${offset})` : ""}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (typeof value !== "object" || value === null) {
    throw new CorruptArtifactError("Spec file root must be a JSON object");
  }

  const obj = value as Record<string, unknown>;

  if (obj.schemaVersion === CURRENT_SPEC_SCHEMA_VERSION) {
    return {
      fromVersion: CURRENT_SPEC_SCHEMA_VERSION,
      toVersion: CURRENT_SPEC_SCHEMA_VERSION,
      spec: obj as unknown as InvariantSpecFileRaw,
      changes: [],
    };
  }

  if (typeof obj.schemaVersion === "string") {
    throw new MigrationError(
      `No migration path from schemaVersion '${obj.schemaVersion}' to '${CURRENT_SPEC_SCHEMA_VERSION}'`,
    );
  }

  if (typeof obj.version === "string" || Array.isArray(obj.rules)) {
    return migrateFrom09(obj as LegacySpec);
  }

  throw new MigrationError(
    "Spec file has neither a recognized 'schemaVersion' nor a legacy 'version'/'rules' shape — nothing to migrate from",
  );
}
