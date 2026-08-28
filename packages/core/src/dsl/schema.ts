import type { JsonAstNode } from "./json-ast";
import { getAtPath } from "./json-ast";
import { DiagnosticBag } from "./diagnostics";
import { rangeFromOffsets } from "./source";
import type { SourceRange } from "./source";
import { INVARIANT_KINDS, SUPPORTED_SPEC_SCHEMA_VERSIONS, type InvariantKind } from "./types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

/** Fields required on `invariants[i]` for each {@link InvariantKind}. */
const REQUIRED_FIELDS_BY_KIND: Record<InvariantKind, string[]> = {
  state: ["condition"],
  access: ["condition"],
  arithmetic: ["condition"],
  "cross-function": ["condition"],
  "value-flow": ["condition"],
  event: ["event"],
  "call-order": ["order"],
};

/** Kinds that require `scope.function` (as opposed to contract-wide). */
const REQUIRES_SCOPE_FUNCTION: ReadonlySet<InvariantKind> = new Set([
  "access",
  "arithmetic",
  "call-order",
  "event",
  "value-flow",
]);

function rangeFor(text: string, file: string, node: JsonAstNode | undefined): SourceRange | undefined {
  if (!node) return undefined;
  return rangeFromOffsets(file, text, node.start, node.end);
}

/**
 * Structural validation of a parsed spec against the invariant-DSL schema.
 * Runs before binding/typechecking (which need semantic contract info) so
 * malformed specs fail fast with precise, field-level diagnostics.
 */
export function validateSpecSchema(
  value: unknown,
  ast: JsonAstNode,
  text: string,
  file: string,
  diagnostics: DiagnosticBag,
): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    diagnostics.error("DSL002", "Spec root must be a JSON object", rangeFor(text, file, ast));
    return;
  }
  const root = value as Record<string, unknown>;

  if (typeof root.schemaVersion !== "string") {
    diagnostics.error(
      "DSL003",
      "Missing required string field 'schemaVersion'",
      rangeFor(text, file, ast),
    );
  } else if (!SUPPORTED_SPEC_SCHEMA_VERSIONS.includes(root.schemaVersion)) {
    diagnostics.error(
      "DSL003",
      `Unsupported schemaVersion '${root.schemaVersion}'. Supported: ${SUPPORTED_SPEC_SCHEMA_VERSIONS.join(", ")}. Run 'chainproof invariants migrate' to upgrade.`,
      rangeFor(text, file, getAtPath(ast, ["schemaVersion"])),
    );
  }

  if (typeof root.name !== "string" || root.name.trim() === "") {
    diagnostics.error("DSL002", "Missing required non-empty string field 'name'", rangeFor(text, file, ast));
  }

  if (root.imports !== undefined) {
    if (!Array.isArray(root.imports) || root.imports.some((i) => typeof i !== "string")) {
      diagnostics.error(
        "DSL002",
        "'imports' must be an array of strings",
        rangeFor(text, file, getAtPath(ast, ["imports"])),
      );
    }
  }

  if (root.predicates !== undefined) {
    if (typeof root.predicates !== "object" || root.predicates === null || Array.isArray(root.predicates)) {
      diagnostics.error(
        "DSL002",
        "'predicates' must be an object mapping name -> expression string",
        rangeFor(text, file, getAtPath(ast, ["predicates"])),
      );
    } else {
      for (const [name, expr] of Object.entries(root.predicates as Record<string, unknown>)) {
        if (typeof expr !== "string") {
          diagnostics.error(
            "DSL002",
            `Predicate '${name}' must be a string expression`,
            rangeFor(text, file, getAtPath(ast, ["predicates", name])),
          );
        }
      }
    }
  }

  if (!Array.isArray(root.invariants)) {
    diagnostics.error("DSL002", "Missing required array field 'invariants'", rangeFor(text, file, ast));
    return;
  }

  const seenIds = new Map<string, number>();
  root.invariants.forEach((raw, index) => {
    validateInvariantEntry(raw, index, ast, text, file, diagnostics, seenIds);
  });
}

function validateInvariantEntry(
  raw: unknown,
  index: number,
  ast: JsonAstNode,
  text: string,
  file: string,
  diagnostics: DiagnosticBag,
  seenIds: Map<string, number>,
): void {
  const entryNode = getAtPath(ast, ["invariants", index]);
  const entryRange = rangeFor(text, file, entryNode);

  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    diagnostics.error("DSL002", `invariants[${index}] must be an object`, entryRange);
    return;
  }
  const entry = raw as Record<string, unknown>;
  const id = typeof entry.id === "string" ? entry.id : undefined;

  if (!id) {
    diagnostics.error("DSL002", `invariants[${index}] is missing required string field 'id'`, entryRange);
  } else {
    const prior = seenIds.get(id);
    if (prior !== undefined) {
      diagnostics.error(
        "DSL011",
        `Duplicate invariant id '${id}' (also used at invariants[${prior}])`,
        entryRange,
        id,
      );
    } else {
      seenIds.set(id, index);
    }
  }

  const label = id ?? `invariants[${index}]`;

  if (typeof entry.title !== "string" || entry.title.trim() === "") {
    diagnostics.error("DSL002", `${label}: missing required string field 'title'`, entryRange, id);
  }

  if (typeof entry.severity !== "string" || !(SEVERITIES as readonly string[]).includes(entry.severity)) {
    diagnostics.error(
      "DSL002",
      `${label}: 'severity' must be one of ${SEVERITIES.join(", ")}`,
      rangeFor(text, file, getAtPath(ast, ["invariants", index, "severity"])) ?? entryRange,
      id,
    );
  }

  const kind = typeof entry.kind === "string" ? (entry.kind as InvariantKind) : undefined;
  if (!kind || !INVARIANT_KINDS.includes(kind)) {
    diagnostics.error(
      "DSL016",
      `${label}: 'kind' must be one of ${INVARIANT_KINDS.join(", ")}`,
      rangeFor(text, file, getAtPath(ast, ["invariants", index, "kind"])) ?? entryRange,
      id,
    );
  }

  const scope = entry.scope as Record<string, unknown> | undefined;
  if (typeof scope !== "object" || scope === null || typeof scope.contract !== "string") {
    diagnostics.error(
      "DSL020",
      `${label}: 'scope.contract' is required`,
      rangeFor(text, file, getAtPath(ast, ["invariants", index, "scope"])) ?? entryRange,
      id,
    );
  } else if (kind && REQUIRES_SCOPE_FUNCTION.has(kind) && typeof scope.function !== "string") {
    diagnostics.error(
      "DSL020",
      `${label}: 'scope.function' is required for kind '${kind}'`,
      rangeFor(text, file, getAtPath(ast, ["invariants", index, "scope"])) ?? entryRange,
      id,
    );
  }

  if (kind && REQUIRED_FIELDS_BY_KIND[kind]) {
    for (const field of REQUIRED_FIELDS_BY_KIND[kind]) {
      if (entry[field] === undefined) {
        diagnostics.error(
          "DSL020",
          `${label}: '${field}' is required for kind '${kind}'`,
          entryRange,
          id,
        );
      }
    }
  }

  if (entry.condition !== undefined && typeof entry.condition !== "string") {
    diagnostics.error(
      "DSL002",
      `${label}: 'condition' must be a string`,
      rangeFor(text, file, getAtPath(ast, ["invariants", index, "condition"])) ?? entryRange,
      id,
    );
  }

  if (entry.event !== undefined && typeof entry.event !== "string") {
    diagnostics.error(
      "DSL002",
      `${label}: 'event' must be a string`,
      rangeFor(text, file, getAtPath(ast, ["invariants", index, "event"])) ?? entryRange,
      id,
    );
  }

  if (entry.order !== undefined) {
    const order = entry.order as Record<string, unknown>;
    if (
      typeof order !== "object" ||
      order === null ||
      typeof order.before !== "string" ||
      typeof order.after !== "string"
    ) {
      diagnostics.error(
        "DSL002",
        `${label}: 'order' must be an object with string 'before' and 'after' fields`,
        rangeFor(text, file, getAtPath(ast, ["invariants", index, "order"])) ?? entryRange,
        id,
      );
    }
  }

  if (entry.assumptions !== undefined) {
    if (!Array.isArray(entry.assumptions) || entry.assumptions.some((a) => typeof a !== "string")) {
      diagnostics.error(
        "DSL002",
        `${label}: 'assumptions' must be an array of strings`,
        entryRange,
        id,
      );
    }
  }

  if (entry.references !== undefined) {
    if (!Array.isArray(entry.references) || entry.references.some((r) => typeof r !== "string")) {
      diagnostics.error(
        "DSL002",
        `${label}: 'references' must be an array of strings`,
        entryRange,
        id,
      );
    }
  }
}
