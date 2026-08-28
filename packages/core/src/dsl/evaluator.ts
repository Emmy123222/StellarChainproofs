import type { ImportGraph, MergedContractView, MergedMember } from "../ast/import-graph";
import { buildImportGraph, buildMergedContractViews } from "../ast/import-graph";
import { collectSolFiles } from "../scanner";
import { DiagnosticBag, type Diagnostic } from "./diagnostics";
import { resolveScope } from "./binder";
import { checkIdentifiersBound } from "./typechecker";
import { inlinePredicates, findUnsupportedConstruct, PredicateExpansionError } from "./predicates";
import { collectGuardsForFunction, findMatchingGuard } from "./queries/guards";
import { emitsEvent } from "./queries/events";
import { EXTERNAL_CALL_MARKER, firstCallSite } from "./queries/call-order";
import { findUnguardedParamWrites } from "./queries/taint-flow";
import { buildFunctionCallGraph, findReachableFunctions, findCallPath } from "../rules/call-graph";
import { canonicalize, collectReferencedNames } from "./expr-normalize";
import {
  DEFAULT_EVALUATION_BUDGET,
  type CheckInvariantsOptions,
  type EvaluationBudget,
  type InvariantCheckReport,
  type InvariantDecl,
  type InvariantEvidence,
  type InvariantResult,
  type InvariantSpec,
  type InvariantStatus,
  RESULT_SCHEMA_VERSION,
} from "./types";
import { BoundedEvaluationError } from "./errors";

class StepBudgetExceeded extends Error {}

const REQUIRES_FUNCTION_KINDS: ReadonlySet<InvariantDecl["kind"]> = new Set([
  "access",
  "arithmetic",
  "call-order",
  "event",
  "value-flow",
]);

/** Per-invariant step counter enforcing {@link EvaluationBudget.maxStepsPerInvariant}. */
class StepCounter {
  private used = 0;
  constructor(private readonly max: number) {}
  tick(n = 1): void {
    this.used += n;
    if (this.used > this.max) throw new StepBudgetExceeded();
  }
  get steps(): number {
    return this.used;
  }
}

/**
 * Static confidence rating per invariant kind, reflecting how directly the
 * bounded query maps to the declared semantics: single-function structural
 * guard matches (`access`/`arithmetic`/`event`/`call-order`) are exact, while
 * contract-wide aggregation (`state`/`cross-function`) and single-hop taint
 * heuristics (`value-flow`) carry more analytical assumption and so are
 * reported at `"medium"`.
 */
function confidenceForKind(kind: InvariantDecl["kind"]): "high" | "medium" | "low" {
  switch (kind) {
    case "access":
    case "arithmetic":
    case "event":
    case "call-order":
      return "high";
    case "state":
    case "cross-function":
    case "value-flow":
      return "medium";
  }
}

function locationFromGuard(file: string, g: { line: number; lineEnd: number; snippet: string }): InvariantEvidence["locations"][number] {
  return { file, line: g.line, lineEnd: g.lineEnd, snippet: g.snippet };
}

/**
 * Evaluate a single invariant against its resolved scope. Dispatches on
 * `kind` to the appropriate bounded AST/call-graph query. Never throws for
 * analysis failures — those become `status: "error"` results — but does
 * propagate {@link StepBudgetExceeded} so the caller can classify it as a
 * `timeout`-adjacent bounded-evaluation outcome.
 */
function evaluateInvariant(
  decl: InvariantDecl,
  spec: InvariantSpec,
  views: MergedContractView[],
  diagnostics: DiagnosticBag,
  budget: EvaluationBudget,
  steps: StepCounter,
  file: string,
): Omit<InvariantResult, "durationMs" | "stepsUsed"> {
  const base = {
    id: decl.id,
    kind: decl.kind,
    title: decl.title,
    severity: decl.severity,
    assumptions: decl.assumptions,
    confidence: confidenceForKind(decl.kind),
  };

  const requiresFunction = REQUIRES_FUNCTION_KINDS.has(decl.kind);
  const resolved = resolveScope(decl.scope, views, diagnostics, decl.id, requiresFunction);
  steps.tick();

  if (!resolved) {
    return {
      ...base,
      status: "error",
      contract: decl.scope.contract,
      function: decl.scope.function,
      message: `Could not resolve scope for invariant '${decl.id}' — see diagnostics for details`,
      evidence: [],
    };
  }

  const { contractView, functionMember } = resolved;

  let condition = decl.condition;
  if (condition) {
    try {
      condition = inlinePredicates(condition, spec.predicates, budget);
    } catch (err) {
      if (err instanceof PredicateExpansionError) {
        return {
          ...base,
          status: "error",
          contract: contractView.name,
          function: functionMember?.name,
          message: err.message,
          evidence: [],
        };
      }
      throw err;
    }

    const unsupported = findUnsupportedConstruct(condition);
    if (unsupported) {
      return {
        ...base,
        status: "skipped",
        contract: contractView.name,
        function: functionMember?.name,
        message: `Condition uses '${unsupported}(...)', which requires state-snapshot evaluation not yet implemented by this bounded evaluator (see docs/invariant-dsl.md#limitations)`,
        evidence: [],
      };
    }

    checkIdentifiersBound(condition, contractView, functionMember, diagnostics, decl.id);
  }

  switch (decl.kind) {
    case "access":
    case "arithmetic":
      return evaluateGuardBased(decl, base, contractView, functionMember!, condition!, file, steps);
    case "state":
      return evaluateStateWide(decl, base, contractView, condition!, file, steps, budget);
    case "cross-function":
      return evaluateCrossFunction(decl, base, contractView, functionMember, condition!, file, steps, budget);
    case "event":
      return evaluateEvent(decl, base, contractView, functionMember!, condition, file, steps);
    case "call-order":
      return evaluateCallOrder(decl, base, contractView, functionMember!, file, steps);
    case "value-flow":
      return evaluateValueFlow(decl, base, contractView, functionMember!, condition!, file, steps);
    default:
      return {
        ...base,
        status: "error",
        contract: contractView.name,
        function: functionMember?.name,
        message: `Unsupported invariant kind '${decl.kind}'`,
        evidence: [],
      };
  }
}

type PartialResult = Omit<InvariantResult, "durationMs" | "stepsUsed">;

function evaluateGuardBased(
  decl: InvariantDecl,
  base: Pick<InvariantResult, "id" | "kind" | "title" | "severity" | "assumptions" | "confidence">,
  contractView: MergedContractView,
  functionMember: MergedMember,
  condition: import("./expr-ast").ExprNode,
  file: string,
  steps: StepCounter,
): PartialResult {
  const guards = collectGuardsForFunction(functionMember, contractView);
  steps.tick(guards.length + 1);
  const match = findMatchingGuard(guards, condition);

  if (match) {
    return {
      ...base,
      status: "pass",
      contract: contractView.name,
      function: functionMember.name,
      message: `Guard enforcing '${decl.conditionSource}' found in '${match.source}'`,
      evidence: [
        {
          summary: `require/assert/if-revert guard in '${match.source}' enforces the declared condition`,
          locations: [locationFromGuard(file, match)],
        },
      ],
    };
  }

  return {
    ...base,
    status: "fail",
    contract: contractView.name,
    function: functionMember.name,
    message: `No guard found in '${functionMember.name}' (or its modifiers) enforcing '${decl.conditionSource}'`,
    evidence: [],
    counterexample: {
      summary:
        guards.length > 0
          ? `Function '${functionMember.name}' has ${guards.length} guard(s), none of which structurally match the declared condition`
          : `Function '${functionMember.name}' has no require/assert/if-revert guards at all`,
      locations: guards.map((g) => locationFromGuard(file, g)),
    },
  };
}

function stateVarNamesReferencedBy(condition: import("./expr-ast").ExprNode, contractView: MergedContractView): Set<string> {
  const referenced = collectReferencedNames(condition);
  const stateVars = new Set(
    contractView.members.filter((m) => m.kind === "stateVariable").map((m) => m.name),
  );
  const result = new Set<string>();
  for (const name of referenced) {
    if (stateVars.has(name)) result.add(name);
  }
  return result;
}

function evaluateStateWide(
  decl: InvariantDecl,
  base: Pick<InvariantResult, "id" | "kind" | "title" | "severity" | "assumptions" | "confidence">,
  contractView: MergedContractView,
  condition: import("./expr-ast").ExprNode,
  file: string,
  steps: StepCounter,
  budget: EvaluationBudget,
): PartialResult {
  const relevantVars = stateVarNamesReferencedBy(condition, contractView);
  const mutators = contractView.members.filter((m) => m.kind === "function");
  steps.tick(mutators.length);

  const evidence: InvariantEvidence[] = [];
  const failing: string[] = [];

  for (const fn of mutators) {
    if (steps.steps > budget.maxStepsPerInvariant) throw new StepBudgetExceeded();
    const writes = writesAnyOf(fn, relevantVars);
    if (!writes) continue;

    const guards = collectGuardsForFunction(fn, contractView);
    steps.tick(guards.length);
    const match = findMatchingGuard(guards, condition);
    if (match) {
      evidence.push({
        summary: `'${fn.name}' guards the invariant`,
        locations: [locationFromGuard(file, match)],
      });
    } else {
      failing.push(fn.name);
    }
  }

  if (failing.length === 0) {
    return {
      ...base,
      status: "pass",
      contract: contractView.name,
      message:
        evidence.length > 0
          ? `Every function that writes ${[...relevantVars].join(", ") || "the referenced state"} guards '${decl.conditionSource}'`
          : `No function writes ${[...relevantVars].join(", ") || "the referenced state"} — invariant holds vacuously`,
      evidence,
    };
  }

  return {
    ...base,
    status: "fail",
    contract: contractView.name,
    message: `Function(s) ${failing.join(", ")} write state referenced by '${decl.conditionSource}' without an enforcing guard`,
    evidence,
    counterexample: {
      summary: `Unguarded state-mutating function(s): ${failing.join(", ")}`,
      locations: [],
    },
  };
}

function writesAnyOf(fn: MergedMember, names: ReadonlySet<string>): boolean {
  if (names.size === 0) return false;
  const src = JSON.stringify(fn.node);
  for (const name of names) {
    if (src.includes(`"name":"${name}"`)) return true;
  }
  return false;
}

function evaluateCrossFunction(
  decl: InvariantDecl,
  base: Pick<InvariantResult, "id" | "kind" | "title" | "severity" | "assumptions" | "confidence">,
  contractView: MergedContractView,
  startFunction: MergedMember | undefined,
  condition: import("./expr-ast").ExprNode,
  file: string,
  steps: StepCounter,
  budget: EvaluationBudget,
): PartialResult {
  const callGraph = buildFunctionCallGraph(contractView);
  steps.tick(callGraph.nodes.size);

  const reachableNames = startFunction
    ? [...findReachableFunctions(startFunction.name, callGraph)].slice(0, budget.maxReachableFunctions)
    : [...callGraph.nodes.keys()].slice(0, budget.maxReachableFunctions);

  const relevantVars = stateVarNamesReferencedBy(condition, contractView);
  const evidence: InvariantEvidence[] = [];
  const failing: Array<{ name: string; callPath: string[] }> = [];

  for (const name of reachableNames) {
    if (steps.steps > budget.maxStepsPerInvariant) throw new StepBudgetExceeded();
    const fn = contractView.members.find((m) => m.kind === "function" && m.name === name);
    if (!fn) continue;
    if (!writesAnyOf(fn, relevantVars)) continue;

    const guards = collectGuardsForFunction(fn, contractView);
    steps.tick(guards.length);
    const match = findMatchingGuard(guards, condition);
    const callPath = startFunction ? findCallPath(startFunction.name, name, callGraph) ?? [name] : [name];

    if (match) {
      evidence.push({
        summary: `'${name}' guards the invariant`,
        locations: [locationFromGuard(file, match)],
        callPath,
      });
    } else {
      failing.push({ name, callPath });
    }
  }

  if (failing.length === 0) {
    return {
      ...base,
      status: "pass",
      contract: contractView.name,
      function: startFunction?.name,
      message: `Every function reachable from '${startFunction?.name ?? "(contract-wide)"}' that writes the referenced state guards '${decl.conditionSource}'`,
      evidence,
    };
  }

  return {
    ...base,
    status: "fail",
    contract: contractView.name,
    function: startFunction?.name,
    message: `Reachable function(s) ${failing.map((f) => f.name).join(", ")} write state referenced by '${decl.conditionSource}' without an enforcing guard`,
    evidence,
    counterexample: {
      summary: `Unguarded reachable function(s): ${failing.map((f) => f.name).join(", ")}`,
      locations: [],
      callPath: failing[0]?.callPath,
    },
  };
}

function evaluateEvent(
  decl: InvariantDecl,
  base: Pick<InvariantResult, "id" | "kind" | "title" | "severity" | "assumptions" | "confidence">,
  contractView: MergedContractView,
  functionMember: MergedMember,
  condition: import("./expr-ast").ExprNode | undefined,
  file: string,
  steps: StepCounter,
): PartialResult {
  steps.tick();
  const site = emitsEvent(functionMember, decl.event!);

  if (site) {
    return {
      ...base,
      status: "pass",
      contract: contractView.name,
      function: functionMember.name,
      message: `'${functionMember.name}' emits '${decl.event}'`,
      evidence: [
        {
          summary: `emit ${decl.event}(...) found`,
          locations: [{ file, line: site.line, snippet: site.snippet }],
        },
      ],
    };
  }

  void condition; // reserved for guard-conditioned emit checks in a future schema revision
  return {
    ...base,
    status: "fail",
    contract: contractView.name,
    function: functionMember.name,
    message: `'${functionMember.name}' never emits '${decl.event}'`,
    evidence: [],
    counterexample: {
      summary: `No 'emit ${decl.event}(...)' statement found in '${functionMember.name}'`,
      locations: [],
    },
  };
}

function evaluateCallOrder(
  decl: InvariantDecl,
  base: Pick<InvariantResult, "id" | "kind" | "title" | "severity" | "assumptions" | "confidence">,
  contractView: MergedContractView,
  functionMember: MergedMember,
  file: string,
  steps: StepCounter,
): PartialResult {
  steps.tick(2);
  const before = firstCallSite(functionMember, decl.order!.before);
  const after = firstCallSite(functionMember, decl.order!.after);

  const describeMissing = (label: string, name: string) =>
    `${label} ('${name === EXTERNAL_CALL_MARKER ? "any external call" : name}') was not found in '${functionMember.name}'`;

  if (!before || !after) {
    const missing = [
      !before ? describeMissing("before", decl.order!.before) : undefined,
      !after ? describeMissing("after", decl.order!.after) : undefined,
    ].filter(Boolean);
    return {
      ...base,
      status: "fail",
      contract: contractView.name,
      function: functionMember.name,
      message: missing.join("; "),
      evidence: [],
      counterexample: { summary: missing.join("; "), locations: [] },
    };
  }

  if (before.line < after.line) {
    return {
      ...base,
      status: "pass",
      contract: contractView.name,
      function: functionMember.name,
      message: `'${decl.order!.before}' (line ${before.line}) occurs before '${decl.order!.after}' (line ${after.line})`,
      evidence: [
        { summary: `before: ${decl.order!.before}`, locations: [{ file, line: before.line, snippet: before.snippet }] },
        { summary: `after: ${decl.order!.after}`, locations: [{ file, line: after.line, snippet: after.snippet }] },
      ],
    };
  }

  return {
    ...base,
    status: "fail",
    contract: contractView.name,
    function: functionMember.name,
    message: `'${decl.order!.before}' (line ${before.line}) does not occur before '${decl.order!.after}' (line ${after.line})`,
    evidence: [],
    counterexample: {
      summary: `'${decl.order!.after}' at line ${after.line} occurs at or before '${decl.order!.before}' at line ${before.line}`,
      locations: [
        { file, line: after.line, snippet: after.snippet },
        { file, line: before.line, snippet: before.snippet },
      ],
    },
  };
}

function evaluateValueFlow(
  decl: InvariantDecl,
  base: Pick<InvariantResult, "id" | "kind" | "title" | "severity" | "assumptions" | "confidence">,
  contractView: MergedContractView,
  functionMember: MergedMember,
  condition: import("./expr-ast").ExprNode,
  file: string,
  steps: StepCounter,
): PartialResult {
  const relevantVars = stateVarNamesReferencedBy(condition, contractView);
  steps.tick(relevantVars.size + 1);
  const findings = findUnguardedParamWrites(functionMember, contractView, relevantVars);

  if (findings.length === 0) {
    return {
      ...base,
      status: "pass",
      contract: contractView.name,
      function: functionMember.name,
      message: `No unguarded parameter flows into ${[...relevantVars].join(", ") || "the referenced state"} in '${functionMember.name}'`,
      evidence: [],
    };
  }

  return {
    ...base,
    status: "fail",
    contract: contractView.name,
    function: functionMember.name,
    message: `Parameter '${findings[0].paramName}' flows into '${findings[0].write.stateVar}' without a preceding guard`,
    evidence: [],
    counterexample: {
      summary: `Write to '${findings[0].write.stateVar}' at line ${findings[0].write.line} is derived directly from unguarded parameter '${findings[0].paramName}'`,
      locations: [{ file, line: findings[0].write.line, snippet: findings[0].write.snippet }],
    },
  };
}

/** Sort key ensuring output ordering is a pure function of the spec + targets (never traversal order). */
function resultSortKey(r: InvariantResult): string {
  return r.id;
}

/**
 * Evaluate every invariant in `spec` against the given `.sol` targets.
 *
 * Deterministic and bounded: results are ordered solely by invariant id
 * (never by filesystem or traversal order), and evaluation stops early —
 * marking any not-yet-evaluated invariants `"skipped"` — once
 * {@link EvaluationBudget.maxTotalTimeMs} elapses, so a pathological spec or
 * contract can never hang the caller.
 */
export async function checkInvariants(
  spec: InvariantSpec,
  options: CheckInvariantsOptions,
): Promise<InvariantCheckReport> {
  if (options.targets.length === 0) {
    throw new BoundedEvaluationError("checkInvariants requires at least one target file or directory");
  }

  const budget: EvaluationBudget = { ...DEFAULT_EVALUATION_BUDGET, ...options.budget };
  const diagnostics = new DiagnosticBag();
  const startedAt = Date.now();

  const files = collectSolFiles(options.targets);
  const emptyGraph: ImportGraph = { files: new Map(), edges: new Map(), topologicalOrder: [], warnings: [] };
  const graph = files.length > 0 ? buildImportGraph(files) : emptyGraph;
  const views = buildMergedContractViews(graph);

  const results: InvariantResult[] = [];
  const stepsExceededIds: string[] = [];
  let timeExceeded = false;

  for (const decl of spec.invariants) {
    if (Date.now() - startedAt > budget.maxTotalTimeMs) {
      timeExceeded = true;
      results.push({
        id: decl.id,
        kind: decl.kind,
        title: decl.title,
        severity: decl.severity,
        status: "skipped",
        contract: decl.scope.contract,
        function: decl.scope.function,
        message: "Skipped: evaluation exceeded the total time budget before this invariant could run",
        evidence: [],
        assumptions: decl.assumptions,
        confidence: "low",
        durationMs: 0,
        stepsUsed: 0,
      });
      continue;
    }

    const invariantStart = Date.now();
    const steps = new StepCounter(budget.maxStepsPerInvariant);
    try {
      const partial = evaluateInvariant(decl, spec, views, diagnostics, budget, steps, files[0] ?? spec.file);
      results.push({ ...partial, durationMs: Date.now() - invariantStart, stepsUsed: steps.steps });
    } catch (err) {
      if (err instanceof StepBudgetExceeded) {
        stepsExceededIds.push(decl.id);
        results.push({
          id: decl.id,
          kind: decl.kind,
          title: decl.title,
          severity: decl.severity,
          status: "timeout",
          contract: decl.scope.contract,
          function: decl.scope.function,
          message: `Evaluation exceeded the per-invariant step budget (${budget.maxStepsPerInvariant})`,
          evidence: [],
          assumptions: decl.assumptions,
          confidence: "low",
          durationMs: Date.now() - invariantStart,
          stepsUsed: steps.steps,
        });
        continue;
      }
      const message = err instanceof Error ? err.message : String(err);
      results.push({
        id: decl.id,
        kind: decl.kind,
        title: decl.title,
        severity: decl.severity,
        status: "error",
        contract: decl.scope.contract,
        function: decl.scope.function,
        message: `Evaluation error: ${message}`,
        evidence: [],
        assumptions: decl.assumptions,
        confidence: "low",
        durationMs: Date.now() - invariantStart,
        stepsUsed: steps.steps,
      });
    }
  }

  results.sort((a, b) => (resultSortKey(a) < resultSortKey(b) ? -1 : resultSortKey(a) > resultSortKey(b) ? 1 : 0));

  const summary = results.reduce(
    (acc, r) => {
      acc[r.status]++;
      acc.total++;
      return acc;
    },
    { pass: 0, fail: 0, error: 0, timeout: 0, skipped: 0, total: 0 },
  );

  const allDiagnostics: Diagnostic[] = diagnostics.all();

  return {
    resultSchemaVersion: RESULT_SCHEMA_VERSION,
    specName: spec.name,
    specSchemaVersion: spec.schemaVersion,
    generatedAt: new Date(startedAt).toISOString(),
    targets: options.targets,
    results,
    diagnostics: allDiagnostics,
    summary,
    bounded: { timeExceeded, stepsExceededIds },
  };
}

// Re-exported for callers that want to canonicalize/compare expressions directly (e.g. `explainInvariant`).
export { canonicalize };
