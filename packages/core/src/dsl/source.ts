/**
 * Shared source-location primitives for the invariant DSL.
 *
 * Every diagnostic, bound symbol, and piece of evidence produced by the DSL
 * carries a {@link SourceRange} so failures can be traced back to an exact
 * span of text — either inside a `.cpinv.json` spec file or inside the
 * Solidity source it was checked against.
 */

/** A single position within a text document (1-indexed line/column). */
export interface SourcePosition {
  /** 1-indexed line number. */
  line: number;
  /** 1-indexed column number. */
  column: number;
  /** 0-indexed absolute character offset from the start of the document. */
  offset: number;
}

/** A half-open [start, end) span of text within a named document. */
export interface SourceRange {
  /** Path of the document the range belongs to (spec file or `.sol` file). */
  file: string;
  start: SourcePosition;
  end: SourcePosition;
}

/**
 * Compute 1-indexed line/column for a character offset within `text`.
 * Used to translate raw string offsets (e.g. from the expression lexer)
 * into a {@link SourcePosition}.
 */
export function offsetToPosition(text: string, offset: number): SourcePosition {
  let line = 1;
  let column = 1;
  const bound = Math.max(0, Math.min(offset, text.length));
  for (let i = 0; i < bound; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) {
      line++;
      column = 1;
    } else {
      column++;
    }
  }
  return { line, column, offset: bound };
}

/** Build a {@link SourceRange} from two character offsets within `text`. */
export function rangeFromOffsets(
  file: string,
  text: string,
  startOffset: number,
  endOffset: number,
): SourceRange {
  return {
    file,
    start: offsetToPosition(text, startOffset),
    end: offsetToPosition(text, endOffset),
  };
}

/** Render a {@link SourceRange} as `path:line:column` for diagnostics/CLI output. */
export function formatRange(range: SourceRange | undefined): string {
  if (!range) return "<unknown>";
  return `${range.file}:${range.start.line}:${range.start.column}`;
}
