import * as fs from "fs";
import * as path from "path";
import { parseJsonAst, toJsValue, JsonAstParseError, getAtPath, type JsonAstNode } from "./json-ast";
import { validateSpecSchema } from "./schema";
import { DiagnosticBag, type Diagnostic } from "./diagnostics";
import { rangeFromOffsets } from "./source";
import { parseExpression, ExprParseError } from "./expr-parser";
import type { ExprNode } from "./expr-ast";
import {
  DEFAULT_EVALUATION_BUDGET,
  type EvaluationBudget,
  type InvariantDecl,
  type InvariantDeclRaw,
  type InvariantSpec,
  type InvariantSpecFileRaw,
  type PredicateDef,
} from "./types";
import { collectReferencedNames } from "./expr-normalize";
import { SpecParseError } from "./errors";

export interface ParseSpecResult {
  spec?: InvariantSpec;
  diagnostics: Diagnostic[];
}

interface LoadedFile {
  absolutePath: string;
  text: string;
  ast: JsonAstNode;
  raw: InvariantSpecFileRaw;
}

/**
 * Parse an invariant spec file from disk into a fully-resolved
 * {@link InvariantSpec}: JSON structure validated, `imports` transitively
 * merged (with cycle detection), `predicates` expression-parsed and
 * checked for recursive definitions, and every `condition`/`event`/`order`
 * expression compiled to a parsed expression AST node.
 *
 * Never throws for malformed *input* — parse/validation failures are
 * reported as diagnostics with `spec` left `undefined`. It throws only for
 * environmental failures (e.g. the root file itself cannot be read).
 */
export function parseInvariantSpecFile(
  filePath: string,
  budget: EvaluationBudget = DEFAULT_EVALUATION_BUDGET,
): ParseSpecResult {
  const diagnostics = new DiagnosticBag();
  const absoluteRoot = path.resolve(filePath);

  if (!fs.existsSync(absoluteRoot)) {
    throw new SpecParseError(`Spec file not found: ${toDisplayPath(absoluteRoot)}`);
  }

  const loaded = new Map<string, LoadedFile>();
  const importOrder: string[] = [];
  const ok = loadFileTransitively(absoluteRoot, loaded, importOrder, [], diagnostics, budget);

  if (!ok || diagnostics.hasErrors) {
    return { diagnostics: diagnostics.all() };
  }

  const rootFile = loaded.get(absoluteRoot)!;

  // Merge predicates: imports first (in import order), root file's own
  // predicates last so they take precedence on name collision.
  const predicateSources = new Map<string, PredicateSource>();
  for (const abs of importOrder) {
    if (abs === absoluteRoot) continue;
    collectPredicateSources(loaded.get(abs)!, predicateSources);
  }
  collectPredicateSources(rootFile, predicateSources);

  const predicates = compilePredicates(predicateSources, diagnostics, budget);

  if (diagnostics.hasErrors) {
    return { diagnostics: diagnostics.all() };
  }

  const invariants: InvariantDecl[] = [];
  const idSet = new Set<string>();
  rootFile.raw.invariants.forEach((rawInv, index) => {
    const decl = compileInvariant(rawInv, index, rootFile, predicates, diagnostics, budget);
    if (decl) {
      if (idSet.has(decl.id)) {
        // Already reported by schema validation; skip duplicate entry.
        return;
      }
      idSet.add(decl.id);
      invariants.push(decl);
    }
  });

  if (diagnostics.hasErrors) {
    return { diagnostics: diagnostics.all() };
  }

  const spec: InvariantSpec = {
    schemaVersion: rootFile.raw.schemaVersion,
    name: rootFile.raw.name,
    description: rootFile.raw.description,
    file: absoluteRoot,
    predicates,
    invariants,
  };

  return { spec, diagnostics: diagnostics.all() };
}

function toDisplayPath(absolutePath: string): string {
  const cwd = process.cwd();
  return absolutePath.startsWith(cwd) ? path.relative(cwd, absolutePath) : absolutePath;
}

function loadFileTransitively(
  absolutePath: string,
  loaded: Map<string, LoadedFile>,
  importOrder: string[],
  chain: string[],
  diagnostics: DiagnosticBag,
  budget: EvaluationBudget,
): boolean {
  if (chain.includes(absolutePath)) {
    diagnostics.error(
      "DSL009",
      `Import cycle detected: ${[...chain, absolutePath].map(toDisplayPath).join(" -> ")}`,
    );
    return false;
  }
  if (loaded.has(absolutePath)) return true;

  if (chain.length >= budget.maxImportDepth) {
    diagnostics.error(
      "DSL009",
      `Import depth exceeds the configured limit (${budget.maxImportDepth}) at ${toDisplayPath(absolutePath)}`,
    );
    return false;
  }

  let text: string;
  try {
    text = fs.readFileSync(absolutePath, "utf-8");
  } catch (err) {
    diagnostics.error(
      "DSL010",
      `Could not read import '${toDisplayPath(absolutePath)}': ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }

  let ast: JsonAstNode;
  try {
    ast = parseJsonAst(text);
  } catch (err) {
    const offset = err instanceof JsonAstParseError ? err.offset : 0;
    diagnostics.error(
      "DSL001",
      `Malformed JSON in ${toDisplayPath(absolutePath)}: ${err instanceof Error ? err.message : String(err)}`,
      rangeFromOffsets(absolutePath, text, offset, offset + 1),
    );
    return false;
  }

  const value = toJsValue(ast);
  validateSpecSchema(value, ast, text, absolutePath, diagnostics);
  if (diagnostics.hasErrors) return false;

  const raw = value as InvariantSpecFileRaw;
  loaded.set(absolutePath, { absolutePath, text, ast, raw });

  const dir = path.dirname(absolutePath);
  for (const imp of raw.imports ?? []) {
    const importedAbs = path.resolve(dir, imp);
    const success = loadFileTransitively(
      importedAbs,
      loaded,
      importOrder,
      [...chain, absolutePath],
      diagnostics,
      budget,
    );
    if (!success) return false;
  }

  importOrder.push(absolutePath);
  return true;
}

interface PredicateSource {
  expr: string;
  definedIn: string;
  fileText: string;
  /** Offset of the predicate expression string's opening quote, for precise error ranges. */
  baseOffset: number;
  fullRange: ReturnType<typeof rangeFromOffsets>;
}

function collectPredicateSources(file: LoadedFile, out: Map<string, PredicateSource>): void {
  for (const [name, expr] of Object.entries(file.raw.predicates ?? {})) {
    const node = getAtPath(file.ast, ["predicates", name]);
    const fullRange = node
      ? rangeFromOffsets(file.absolutePath, file.text, node.start, node.end)
      : rangeFromOffsets(file.absolutePath, file.text, 0, 0);
    out.set(name, {
      expr,
      definedIn: file.absolutePath,
      fileText: file.text,
      baseOffset: node ? node.start + 1 : 0,
      fullRange,
    });
  }
}

function compilePredicates(
  sources: Map<string, PredicateSource>,
  diagnostics: DiagnosticBag,
  budget: EvaluationBudget,
): Map<string, PredicateDef> {
  const exprs = new Map<string, ExprNode>();
  for (const [name, src] of sources) {
    try {
      exprs.set(name, parseExpression(src.expr));
    } catch (err) {
      const offset = err instanceof ExprParseError ? src.baseOffset + err.offset : src.baseOffset;
      diagnostics.error(
        "DSL004",
        `Predicate '${name}': ${err instanceof Error ? err.message : String(err)}`,
        rangeFromOffsets(src.definedIn, src.fileText, offset, offset + 1),
      );
    }
  }

  // Detect recursive predicate definitions via DFS over predicate-call references.
  const color = new Map<string, 0 | 1 | 2>(); // 0=white 1=gray 2=black
  const recursive = new Set<string>();

  const visit = (name: string, chain: string[]): void => {
    const c = color.get(name) ?? 0;
    if (c === 1) {
      const cycle = [...chain, name].join(" -> ");
      diagnostics.error(
        "DSL008",
        `Recursive predicate definition: ${cycle}`,
        sources.get(name)?.fullRange,
      );
      for (const n of chain) recursive.add(n);
      recursive.add(name);
      return;
    }
    if (c === 2) return;
    color.set(name, 1);
    const expr = exprs.get(name);
    if (expr) {
      for (const ref of collectReferencedNames(expr)) {
        if (exprs.has(ref)) visit(ref, [...chain, name]);
      }
    }
    color.set(name, 2);
  };

  for (const name of exprs.keys()) {
    if ((color.get(name) ?? 0) === 0) visit(name, []);
  }

  const predicates = new Map<string, PredicateDef>();
  for (const [name, expr] of exprs) {
    if (recursive.has(name)) continue;
    const src = sources.get(name)!;
    predicates.set(name, { name, source: src.expr, expr, range: src.fullRange, definedIn: src.definedIn });
  }
  return predicates;
}

function compileInvariant(
  raw: InvariantDeclRaw,
  index: number,
  file: LoadedFile,
  predicates: Map<string, PredicateDef>,
  diagnostics: DiagnosticBag,
  budget: EvaluationBudget,
): InvariantDecl | undefined {
  const entryNode = getAtPath(file.ast, ["invariants", index]);
  const range = entryNode
    ? rangeFromOffsets(file.absolutePath, file.text, entryNode.start, entryNode.end)
    : rangeFromOffsets(file.absolutePath, file.text, 0, 0);

  let condition: ExprNode | undefined;
  if (raw.condition !== undefined) {
    const condNode = getAtPath(file.ast, ["invariants", index, "condition"]);
    const baseOffset = condNode ? condNode.start + 1 : 0; // +1 to skip the opening quote
    try {
      condition = parseExpression(raw.condition);
      validatePredicateCallsExist(condition, predicates, file.absolutePath, file.text, baseOffset, diagnostics, raw.id);
    } catch (err) {
      const offset = err instanceof ExprParseError ? baseOffset + err.offset : baseOffset;
      diagnostics.error(
        "DSL004",
        `${raw.id}: invalid condition expression: ${err instanceof Error ? err.message : String(err)}`,
        rangeFromOffsets(file.absolutePath, file.text, offset, offset + 1),
        raw.id,
      );
      return undefined;
    }
  }

  return {
    id: raw.id,
    kind: raw.kind,
    title: raw.title,
    description: raw.description,
    severity: raw.severity,
    scope: raw.scope,
    conditionSource: raw.condition,
    condition,
    event: raw.event,
    order: raw.order,
    assumptions: raw.assumptions ?? [],
    references: raw.references ?? [],
    range,
  };
}

function validatePredicateCallsExist(
  node: ExprNode,
  predicates: Map<string, PredicateDef>,
  file: string,
  text: string,
  baseOffset: number,
  diagnostics: DiagnosticBag,
  invariantId: string,
): void {
  const walk = (n: ExprNode): void => {
    if (n.type === "Call" && n.callee.type === "Identifier") {
      const name = n.callee.name;
      if (!predicates.has(name) && !isBuiltinCallable(name)) {
        diagnostics.error(
          "DSL006",
          `${invariantId}: unknown predicate or function '${name}'`,
          rangeFromOffsets(file, text, baseOffset + n.range.start, baseOffset + n.range.end),
          invariantId,
        );
      } else if (predicates.has(name) && n.args.length !== 0) {
        diagnostics.error(
          "DSL007",
          `${invariantId}: predicate '${name}' takes no arguments`,
          rangeFromOffsets(file, text, baseOffset + n.range.start, baseOffset + n.range.end),
          invariantId,
        );
      }
    }
    if (n.type === "MemberAccess") walk(n.object);
    if (n.type === "Call") {
      walk(n.callee);
      for (const a of n.args) walk(a);
    }
    if (n.type === "Unary") walk(n.argument);
    if (n.type === "Binary") {
      walk(n.left);
      walk(n.right);
    }
  };
  walk(node);
}

const BUILTIN_CALLABLES = new Set(["old", "changed"]);
function isBuiltinCallable(name: string): boolean {
  return BUILTIN_CALLABLES.has(name);
}
