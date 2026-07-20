import { createHash } from "crypto";
import type { Finding, ScanResult, ScanDiff } from "./types";

/**
 * Normalizes file paths for cross-platform and cross-commit comparisons.
 */
function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

/**
 * Computes a SHA-256 hash of a snippet string.
 */
function hashSnippet(snippet?: string): string {
  if (!snippet) return "";
  return createHash("sha256").update(snippet.trim()).digest("hex");
}

/**
 * Computes a unique SHA-256 fingerprint for a finding.
 * Fingerprint = SHA-256(ruleId + ":" + normalized_path + ":" + line + ":" + snippet_hash)
 */
export function computeFingerprint(finding: Finding): string {
  const normFile = normalizePath(finding.file);
  const snipHash = hashSnippet(finding.snippet);
  const raw = `${finding.id}:${normFile}:${finding.line}:${snipHash}`;
  return createHash("sha256").update(raw).digest("hex");
}

/**
 * Compares two {@link ScanResult} objects and determines introduced, resolved, and persisted findings.
 *
 * Matching strategy:
 * 1. Exact fingerprint match (ruleId + normalized file path + line + snippet hash)
 * 2. Fuzzy line match for unmatched findings (same ruleId + normalized file + line difference <= 3)
 *
 * @param oldResult - The baseline scan result
 * @param newResult - The current scan result
 * @returns A {@link ScanDiff} containing introduced, resolved, and persisted findings with summary counts
 */
export function diffScans(oldResult: ScanResult, newResult: ScanResult): ScanDiff {
  const oldFindings = oldResult.files.flatMap((f) => f.findings);
  const newFindings = newResult.files.flatMap((f) => f.findings);

  const oldMatched = new Set<number>();
  const newMatched = new Set<number>();

  // 1. Exact Fingerprint Matching
  const oldFPMap = new Map<string, number[]>();
  oldFindings.forEach((f, idx) => {
    const fp = computeFingerprint(f);
    if (!oldFPMap.has(fp)) oldFPMap.set(fp, []);
    oldFPMap.get(fp)!.push(idx);
  });

  newFindings.forEach((nf, newIdx) => {
    const fp = computeFingerprint(nf);
    const indices = oldFPMap.get(fp);
    if (indices && indices.length > 0) {
      const oldIdx = indices.shift()!;
      oldMatched.add(oldIdx);
      newMatched.add(newIdx);
    }
  });

  // 2. Line Tolerance Matching (±3 lines)
  newFindings.forEach((nf, newIdx) => {
    if (newMatched.has(newIdx)) return;
    const nfNormFile = normalizePath(nf.file);
    const nfSnipHash = hashSnippet(nf.snippet);

    for (let oldIdx = 0; oldIdx < oldFindings.length; oldIdx++) {
      if (oldMatched.has(oldIdx)) continue;
      const of = oldFindings[oldIdx];

      if (of.id === nf.id && normalizePath(of.file) === nfNormFile) {
        const lineDiff = Math.abs(nf.line - of.line);
        const ofSnipHash = hashSnippet(of.snippet);

        if (lineDiff <= 3 && (nfSnipHash === ofSnipHash || !nf.snippet || !of.snippet)) {
          oldMatched.add(oldIdx);
          newMatched.add(newIdx);
          break;
        }
      }
    }
  });

  const introduced: Finding[] = [];
  const persisted: Finding[] = [];
  const resolved: Finding[] = [];

  newFindings.forEach((f, idx) => {
    if (newMatched.has(idx)) {
      persisted.push(f);
    } else {
      introduced.push(f);
    }
  });

  oldFindings.forEach((f, idx) => {
    if (!oldMatched.has(idx)) {
      resolved.push(f);
    }
  });

  const newCritical = introduced.filter((f) => f.severity === "critical").length;
  const newHigh = introduced.filter((f) => f.severity === "high").length;
  const resolvedTotal = resolved.length;

  return {
    introduced,
    resolved,
    persisted,
    summary: {
      newCritical,
      newHigh,
      resolvedTotal,
    },
  };
}
