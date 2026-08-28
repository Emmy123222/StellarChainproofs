import * as path from "path";
import type { Diagnostic } from "./diagnostics";

/**
 * Base class for all errors raised by the invariant DSL.
 *
 * Every subclass carries a stable {@link InvariantDslError.code} suitable for
 * programmatic handling, and messages are passed through `sanitizeMessage()`
 * before being thrown so that absolute filesystem paths outside the project
 * and anything resembling a credential never leak into logs, CI output, or
 * bug reports.
 */
export class InvariantDslError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(sanitizeMessage(message));
    this.code = code;
    this.name = "InvariantDslError";
  }
}

/** The spec file could not be read or parsed as JSON. */
export class SpecParseError extends InvariantDslError {
  constructor(message: string) {
    super("DSL001", message);
    this.name = "SpecParseError";
  }
}

/** The spec failed schema or semantic validation. Carries the full diagnostic list. */
export class SpecValidationError extends InvariantDslError {
  readonly diagnostics: Diagnostic[];

  constructor(message: string, diagnostics: Diagnostic[]) {
    super("DSL002", message);
    this.name = "SpecValidationError";
    this.diagnostics = diagnostics;
  }
}

/** Evaluation could not complete within its configured resource bounds. */
export class BoundedEvaluationError extends InvariantDslError {
  constructor(message: string) {
    super("DSL017", message);
    this.name = "BoundedEvaluationError";
  }
}

/** A spec/cache/report file exists but its contents are structurally corrupt. */
export class CorruptArtifactError extends InvariantDslError {
  constructor(message: string) {
    super("DSL018", message);
    this.name = "CorruptArtifactError";
  }
}

/** Migration between schema versions was requested for an unsupported version pair. */
export class MigrationError extends InvariantDslError {
  constructor(message: string) {
    super("DSL019", message);
    this.name = "MigrationError";
  }
}

const SECRET_LIKE = /\b([A-Za-z0-9_-]*(?:key|token|secret|password|credential)[A-Za-z0-9_-]*\s*[:=]\s*)(\S+)/gi;

/**
 * Strip content that must never appear in a thrown error: absolute paths
 * outside the current working directory (rewritten relative to cwd) and
 * anything shaped like a credential (`api_key: ...`, `token=...`).
 *
 * Errors are a boundary surface — they get printed in CI logs, pasted into
 * issues, and shown in editor tooltips, so this runs unconditionally rather
 * than being opt-in.
 */
export function sanitizeMessage(message: string): string {
  const cwd = process.cwd();
  let out = message.split(cwd + path.sep).join("");
  out = out.split(cwd).join(".");
  out = out.replace(SECRET_LIKE, (_m, prefix: string) => `${prefix}[REDACTED]`);
  return out;
}
