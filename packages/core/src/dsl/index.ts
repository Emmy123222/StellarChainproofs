/**
 * @packageDocumentation
 * Deterministic Security Invariant Specification and Checking DSL.
 *
 * A versioned, declarative JSON spec format (`*.cpinv.json`) plus a bounded,
 * deterministic evaluator that checks protocol-specific invariants
 * (access control, state, arithmetic, call ordering, events, value-flow,
 * and cross-function properties) against Solidity source — as static
 * AST/call-graph queries, never a live network or symbolic executor.
 *
 * See `docs/invariant-dsl.md` for the spec format, the expression
 * language, and documented limitations.
 *
 * @example
 * ```typescript
 * import { parseInvariantSpecFile, checkInvariants } from '@chainproof/core';
 *
 * const { spec, diagnostics } = parseInvariantSpecFile('vault.cpinv.json');
 * if (spec) {
 *   const report = await checkInvariants(spec, { targets: ['contracts/Vault.sol'] });
 *   console.log(report.summary);
 * }
 * ```
 */
import * as path from "path";
import { parseInvariantSpecFile } from "./spec-parser";
import { checkInvariants } from "./evaluator";
import { SpecValidationError } from "./errors";
import type {
  CheckInvariantsOptions,
  InvariantCheckReport,
  InvariantDecl,
  InvariantSpec,
  InvariantSpecFileRaw,
} from "./types";
import { CURRENT_SPEC_SCHEMA_VERSION } from "./types";
import { canonicalize, prettyPrint } from "./expr-normalize";
import { inlinePredicates } from "./predicates";
import type { Diagnostic } from "./diagnostics";
import { formatRange } from "./source";

// ─── Parsing & validation ───────────────────────────────────────────────────

export { parseInvariantSpecFile } from "./spec-parser";
export type { ParseSpecResult } from "./spec-parser";

/** Parse and validate a spec file without checking it against any contract. `valid` is false iff any error-severity diagnostic was produced. */
export function validateInvariantSpecFile(filePath: string): { valid: boolean; diagnostics: Diagnostic[] } {
  const { diagnostics } = parseInvariantSpecFile(filePath);
  return { valid: !diagnostics.some((d) => d.severity === "error"), diagnostics };
}

// ─── Checking ────────────────────────────────────────────────────────────────

export { checkInvariants } from "./evaluator";

/**
 * Parse `specFile` and check it against `options.targets` in one call.
 * Throws {@link SpecValidationError} if the spec itself fails to parse —
 * callers that need to distinguish "bad spec" from "spec check failures"
 * should use {@link parseInvariantSpecFile} + {@link checkInvariants} directly.
 */
export async function checkInvariantsFromFile(
  specFile: string,
  options: CheckInvariantsOptions,
): Promise<InvariantCheckReport> {
  const { spec, diagnostics } = parseInvariantSpecFile(specFile);
  if (!spec) {
    throw new SpecValidationError(
      `Spec '${path.basename(specFile)}' failed to parse — see diagnostics`,
      diagnostics,
    );
  }
  return checkInvariants(spec, options);
}

// ─── Explanation ─────────────────────────────────────────────────────────────

/**
 * Render a human-readable explanation of one invariant: its declared
 * intent, resolved scope, fully predicate-expanded condition, and
 * assumptions — used by `chainproof invariants explain` and useful for
 * spec-review in a PR description.
 */
export function explainInvariant(spec: InvariantSpec, invariantId: string): string {
  const decl = spec.invariants.find((i) => i.id === invariantId);
  if (!decl) {
    const available = spec.invariants.map((i) => i.id).join(", ") || "(none)";
    return `Invariant '${invariantId}' not found in spec '${spec.name}'. Available: ${available}`;
  }

  const lines: string[] = [];
  lines.push(`${decl.id}: ${decl.title}`);
  lines.push(`  kind:     ${decl.kind}`);
  lines.push(`  severity: ${decl.severity}`);
  lines.push(`  scope:    ${decl.scope.contract}${decl.scope.function ? `.${decl.scope.function}` : " (contract-wide)"}`);
  if (decl.description) lines.push(`  description: ${decl.description}`);

  if (decl.condition) {
    let expanded = decl.condition;
    try {
      expanded = inlinePredicates(decl.condition, spec.predicates, {
        maxStepsPerInvariant: 20_000,
        maxTotalTimeMs: 10_000,
        maxPredicateDepth: 16,
        maxImportDepth: 8,
        maxReachableFunctions: 512,
      });
    } catch {
      // Fall back to the unexpanded condition; expansion errors surface during checkInvariants.
    }
    lines.push(`  condition (as written): ${decl.conditionSource}`);
    if (canonicalize(expanded) !== canonicalize(decl.condition)) {
      lines.push(`  condition (predicates expanded): ${prettyPrint(expanded)}`);
    }
  }
  if (decl.event) lines.push(`  required event: ${decl.event}`);
  if (decl.order) lines.push(`  required order: '${decl.order.before}' before '${decl.order.after}'`);

  if (decl.assumptions.length > 0) {
    lines.push(`  assumptions:`);
    for (const a of decl.assumptions) lines.push(`    - ${a}`);
  }
  if (decl.references.length > 0) {
    lines.push(`  references: ${decl.references.join(", ")}`);
  }
  lines.push(`  declared at: ${formatRange(decl.range)}`);

  return lines.join("\n");
}

// ─── Migration ───────────────────────────────────────────────────────────────

export { migrateInvariantSpecFile } from "./migrate";
export type { MigrationResult } from "./migrate";

// ─── Serialization ───────────────────────────────────────────────────────────

export { serializeReport, stableStringify } from "./serialize";

// ─── Scaffolding (`chainproof invariants init`) ─────────────────────────────

/** Build the starter spec object written by `chainproof invariants init`. */
export function scaffoldInvariantSpec(name: string, contractName = "MyContract"): InvariantSpecFileRaw {
  return {
    schemaVersion: CURRENT_SPEC_SCHEMA_VERSION,
    name,
    description: "Security invariants for " + contractName,
    predicates: {
      isOwner: "msg.sender == owner",
    },
    invariants: [
      {
        id: "INV-001",
        kind: "access",
        title: `Only the owner may call the privileged function`,
        description: "Replace 'privilegedFunction' with the function this guards.",
        severity: "high",
        scope: { contract: contractName, function: "privilegedFunction" },
        condition: "isOwner()",
        assumptions: ["'owner' is set in the constructor and is never the zero address"],
        references: [],
      },
    ],
  };
}

// ─── Public types ────────────────────────────────────────────────────────────

export type {
  InvariantKind,
  InvariantSeverity,
  InvariantScopeRaw,
  CallOrderRaw,
  InvariantDeclRaw,
  InvariantSpecFileRaw,
  InvariantDecl,
  InvariantSpec,
  PredicateDef,
  EvaluationBudget,
  CheckInvariantsOptions,
  InvariantStatus,
  Confidence,
  EvidenceLocation,
  InvariantEvidence,
  InvariantResult,
  InvariantCheckSummary,
  InvariantCheckReport,
} from "./types";
export { CURRENT_SPEC_SCHEMA_VERSION, SUPPORTED_SPEC_SCHEMA_VERSIONS, RESULT_SCHEMA_VERSION, DEFAULT_EVALUATION_BUDGET, INVARIANT_KINDS } from "./types";
export type { Diagnostic, DiagnosticCode, DiagnosticSeverity } from "./diagnostics";
export type { SourceRange, SourcePosition } from "./source";
export { formatRange } from "./source";
export {
  InvariantDslError,
  SpecParseError,
  SpecValidationError,
  BoundedEvaluationError,
  CorruptArtifactError,
  MigrationError,
} from "./errors";
