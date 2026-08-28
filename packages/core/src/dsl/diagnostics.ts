import type { SourceRange } from "./source";

/**
 * Stable diagnostic codes emitted by the invariant DSL pipeline.
 * Codes are part of the public, machine-readable surface: tooling (editors,
 * CI annotators) may match on them, so existing codes are never repurposed.
 */
export type DiagnosticCode =
  | "DSL001" // malformed JSON / unreadable spec file
  | "DSL002" // schema validation failure (structural)
  | "DSL003" // unsupported / missing schemaVersion
  | "DSL004" // expression syntax error
  | "DSL005" // unknown identifier / missing symbol
  | "DSL006" // unknown predicate call
  | "DSL007" // predicate arity mismatch
  | "DSL008" // recursive predicate definition
  | "DSL009" // import cycle
  | "DSL010" // import target not found / unreadable
  | "DSL011" // duplicate invariant id
  | "DSL012" // unknown contract in scope
  | "DSL013" // unknown function in scope
  | "DSL014" // ambiguous overloaded function reference
  | "DSL015" // type mismatch in expression
  | "DSL016" // unsupported invariant kind
  | "DSL017" // evaluation exceeded bounded step/time budget
  | "DSL018" // corrupted cache / result file
  | "DSL019" // invalid migration source/target version
  | "DSL020"; // scope missing a required field for this invariant kind

export type DiagnosticSeverity = "error" | "warning" | "info";

/** A single actionable diagnostic tied to an exact source range where possible. */
export interface Diagnostic {
  code: DiagnosticCode;
  severity: DiagnosticSeverity;
  message: string;
  range?: SourceRange;
  /** id of the invariant this diagnostic belongs to, if any. */
  invariantId?: string;
}

/** Accumulates diagnostics across the parse/bind/typecheck/compile pipeline. */
export class DiagnosticBag {
  private readonly items: Diagnostic[] = [];

  add(diagnostic: Diagnostic): void {
    this.items.push(diagnostic);
  }

  error(
    code: DiagnosticCode,
    message: string,
    range?: SourceRange,
    invariantId?: string,
  ): void {
    this.add({ code, severity: "error", message, range, invariantId });
  }

  warn(
    code: DiagnosticCode,
    message: string,
    range?: SourceRange,
    invariantId?: string,
  ): void {
    this.add({ code, severity: "warning", message, range, invariantId });
  }

  info(
    code: DiagnosticCode,
    message: string,
    range?: SourceRange,
    invariantId?: string,
  ): void {
    this.add({ code, severity: "info", message, range, invariantId });
  }

  get hasErrors(): boolean {
    return this.items.some((d) => d.severity === "error");
  }

  all(): Diagnostic[] {
    // Deterministic ordering: by file, then line/column, so output is stable
    // across runs regardless of the internal traversal order that produced it.
    return [...this.items].sort((a, b) => {
      const fa = a.range?.file ?? "";
      const fb = b.range?.file ?? "";
      if (fa !== fb) return fa < fb ? -1 : 1;
      const la = a.range?.start.line ?? 0;
      const lb = b.range?.start.line ?? 0;
      if (la !== lb) return la - lb;
      const ca = a.range?.start.column ?? 0;
      const cb = b.range?.start.column ?? 0;
      return ca - cb;
    });
  }
}
