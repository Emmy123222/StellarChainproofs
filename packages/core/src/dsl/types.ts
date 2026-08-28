import type { ExprNode } from "./expr-ast";
import type { SourceRange } from "./source";
import type { Diagnostic } from "./diagnostics";

// ─── Spec schema versioning ────────────────────────────────────────────────

/** Current schema version emitted by `chainproof invariants init`. */
export const CURRENT_SPEC_SCHEMA_VERSION = "1.0.0";
/** All schema versions this build of `@chainproof/core` can parse directly (without migration). */
export const SUPPORTED_SPEC_SCHEMA_VERSIONS: readonly string[] = ["1.0.0"];
/** Versioned shape of {@link InvariantCheckReport} — bump on any breaking output change. */
export const RESULT_SCHEMA_VERSION = "1.0.0";

// ─── Raw (on-disk) spec shape ───────────────────────────────────────────────

export type InvariantKind =
  | "state"
  | "access"
  | "call-order"
  | "value-flow"
  | "event"
  | "arithmetic"
  | "cross-function";

export const INVARIANT_KINDS: readonly InvariantKind[] = [
  "state",
  "access",
  "call-order",
  "value-flow",
  "event",
  "arithmetic",
  "cross-function",
];

export type InvariantSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Which functions/contract an invariant applies to. */
export interface InvariantScopeRaw {
  contract: string;
  /** Omit for contract-wide invariants (currently only `state`/`cross-function` support this). */
  function?: string;
  /** Disambiguates overloaded functions, e.g. `"transfer(address,uint256)"`. */
  signature?: string;
}

/** Statement ordering constraint used by `kind: "call-order"`. */
export interface CallOrderRaw {
  /** Name of the call/internal-function that must occur first. */
  before: string;
  /** Name of the call/internal-function that must occur second. */
  after: string;
}

export interface InvariantDeclRaw {
  id: string;
  kind: InvariantKind;
  title: string;
  description?: string;
  severity: InvariantSeverity;
  scope: InvariantScopeRaw;
  /** Boolean guard expression, required for all kinds except `call-order`. */
  condition?: string;
  /** Event name required to be emitted, required for `kind: "event"`. */
  event?: string;
  /** Required for `kind: "call-order"`. */
  order?: CallOrderRaw;
  assumptions?: string[];
  references?: string[];
}

/** On-disk shape of a `*.cpinv.json` invariant spec file. */
export interface InvariantSpecFileRaw {
  schemaVersion: string;
  name: string;
  description?: string;
  /** Relative paths to other spec files this one imports predicates from. */
  imports?: string[];
  /** Reusable, zero-argument named boolean expressions available to `condition`. */
  predicates?: Record<string, string>;
  invariants: InvariantDeclRaw[];
}

// ─── Bound / parsed IR ──────────────────────────────────────────────────────

export interface PredicateDef {
  name: string;
  source: string;
  expr: ExprNode;
  range: SourceRange;
  /** File the predicate was ultimately defined in (may differ from the importing spec). */
  definedIn: string;
}

export interface InvariantDecl {
  id: string;
  kind: InvariantKind;
  title: string;
  description?: string;
  severity: InvariantSeverity;
  scope: InvariantScopeRaw;
  conditionSource?: string;
  condition?: ExprNode;
  event?: string;
  order?: CallOrderRaw;
  assumptions: string[];
  references: string[];
  /** Location of this invariant's declaration within the (root) spec file. */
  range: SourceRange;
}

/** Fully parsed, import-resolved, predicate-expanded invariant specification. */
export interface InvariantSpec {
  schemaVersion: string;
  name: string;
  description?: string;
  /** Absolute path of the root spec file this was parsed from. */
  file: string;
  predicates: Map<string, PredicateDef>;
  invariants: InvariantDecl[];
}

// ─── Evaluation bounds ──────────────────────────────────────────────────────

/** Resource limits applied during {@link checkInvariants} to guarantee termination. */
export interface EvaluationBudget {
  /** Max AST/call-graph query steps a single invariant may consume. */
  maxStepsPerInvariant: number;
  /** Wall-clock budget for the whole `checkInvariants` call, in milliseconds. */
  maxTotalTimeMs: number;
  /** Max recursion depth when expanding reusable predicates (guards against cycles). */
  maxPredicateDepth: number;
  /** Max depth of the spec `imports` graph. */
  maxImportDepth: number;
  /** Max functions visited when walking cross-function call-graph reachability. */
  maxReachableFunctions: number;
}

export const DEFAULT_EVALUATION_BUDGET: EvaluationBudget = {
  maxStepsPerInvariant: 20_000,
  maxTotalTimeMs: 10_000,
  maxPredicateDepth: 16,
  maxImportDepth: 8,
  maxReachableFunctions: 512,
};

// ─── Results ────────────────────────────────────────────────────────────────

export type InvariantStatus = "pass" | "fail" | "error" | "timeout" | "skipped";
export type Confidence = "high" | "medium" | "low";

export interface EvidenceLocation {
  file: string;
  line: number;
  lineEnd?: number;
  snippet?: string;
}

export interface InvariantEvidence {
  summary: string;
  locations: EvidenceLocation[];
  /** For cross-function/call-order kinds: the function call chain the evidence traverses. */
  callPath?: string[];
}

export interface InvariantResult {
  id: string;
  kind: InvariantKind;
  title: string;
  severity: InvariantSeverity;
  status: InvariantStatus;
  contract: string;
  function?: string;
  message: string;
  /** Supporting evidence for a `pass` (the guard that was found). */
  evidence: InvariantEvidence[];
  /** Concrete counterexample location/path for a `fail`. */
  counterexample?: InvariantEvidence;
  assumptions: string[];
  confidence: Confidence;
  durationMs: number;
  stepsUsed: number;
}

export interface InvariantCheckSummary {
  pass: number;
  fail: number;
  error: number;
  timeout: number;
  skipped: number;
  total: number;
}

/** Deterministically-serializable output of {@link checkInvariants}. */
export interface InvariantCheckReport {
  resultSchemaVersion: string;
  specName: string;
  specSchemaVersion: string;
  generatedAt: string;
  targets: string[];
  results: InvariantResult[];
  diagnostics: Diagnostic[];
  summary: InvariantCheckSummary;
  bounded: {
    timeExceeded: boolean;
    /** ids of invariants that hit their per-invariant step budget. */
    stepsExceededIds: string[];
  };
}

export interface CheckInvariantsOptions {
  /** `.sol` files or directories to check the spec against. */
  targets: string[];
  budget?: Partial<EvaluationBudget>;
}
