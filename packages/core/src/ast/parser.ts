import * as parser from "@solidity-parser/parser";
import type { ASTNode } from "../types";

export type { ASTNode };

export interface ParseResult {
  ast: ASTNode | null;
  error?: string;
}

/**
 * Parse a Solidity source file into an AST.
 * Returns `{ ast: null, error }` on failure instead of throwing.
 *
 * @param source - Raw Solidity source code
 * @param filePath - File path used for error messages only
 * @returns A {@link ParseResult} with either a populated `ast` or an `error` string
 *
 * @internal Used by scanning rules — prefer {@link scan} for external usage.
 */
export function parseSolidity(source: string, filePath: string): ParseResult {
  try {
    const ast = parser.parse(source, {
      loc: true,
      range: true,
      tolerant: true,
    });
    return { ast };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ast: null,
      error: `Parse error in ${filePath}: ${message}`,
    };
  }
}

/**
 * Walk an AST, calling visitor callbacks for each node type.
 * Visitor keys are node types e.g. `"FunctionDefinition"`.
 *
 * @param ast - A parsed Solidity AST node
 * @param visitors - Map of node type → visitor callback
 *
 * @internal Used by rules and import-graph — prefer {@link scan} for external usage.
 */
export function visit(
  ast: ASTNode,
  visitors: Partial<Record<string, (node: ASTNode) => void>>,
): void {
  parser.visit(ast, visitors as any);
}

/**
 * Extract the source snippet for a node using its location info.
 */
export function getSnippet(source: string, node: ASTNode): string {
  const loc = (
    node as { loc?: { start?: { line?: number }; end?: { line?: number } } }
  ).loc;
  if (!loc?.start?.line || !loc?.end?.line) return "";
  const lines = source.split("\n");
  return lines
    .slice(loc.start.line - 1, loc.end.line)
    .join("\n")
    .trim();
}
