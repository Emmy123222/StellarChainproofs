import type { InvariantCheckReport } from "./types";

/**
 * JSON.stringify with object keys sorted alphabetically at every level.
 *
 * `checkInvariants` already produces its own result ordering (by invariant
 * id) independent of traversal order, but nested plain objects are still
 * built via object literals whose key order is technically an
 * implementation detail. Sorting keys here removes that as a possible
 * source of non-determinism in the serialized report, so two runs over an
 * unchanged spec+contract byte-for-byte diff to nothing — required for the
 * report format to be safely committed to source control and diffed in CI.
 */
export function stableStringify(value: unknown, indent = 2): string {
  return JSON.stringify(sortKeysDeep(value), null, indent);
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/** Serialize a {@link InvariantCheckReport} to its canonical, deterministic JSON form. */
export function serializeReport(report: InvariantCheckReport): string {
  return stableStringify(report);
}
