import { execSync, spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import type { Finding, Severity, SlitherDetectorConfig } from "../types";
import { getDetectorInfo } from "./slither-detectors";

interface SlitherDetector {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  elements?: Array<{
    name?: string;
    source_mapping?: {
      filename_short?: string;
      lines?: number[];
    };
  }>;
}

interface SlitherOutput {
  results?: {
    detectors?: SlitherDetector[];
  };
}

/**
 * Impact × confidence → ChainProof severity.
 *
 * At `high` confidence this matches Slither's impact one-to-one (the same
 * mapping ChainProof has always used). Lower confidence discounts the
 * severity, since an uncertain finding shouldn't read as urgently as a
 * confirmed one.
 *
 * @internal
 */
const SEVERITY_MATRIX: Record<string, Record<string, Severity>> = {
  high: { high: "critical", medium: "high", low: "medium" },
  medium: { high: "high", medium: "medium", low: "low" },
  low: { high: "medium", medium: "low", low: "info" },
  informational: { high: "info", medium: "info", low: "info" },
};

/**
 * Map a Slither `impact` × `confidence` pair to a ChainProof {@link Severity}.
 *
 * Unrecognized impact/confidence strings fall back to `high` confidence
 * (preserving the old impact-only behavior) and `low` impact respectively.
 *
 * @internal
 */
export function mapSeverity(impact: string, confidence: string): Severity {
  const impactRow =
    SEVERITY_MATRIX[impact.toLowerCase()] ?? SEVERITY_MATRIX.low;
  return impactRow[confidence.toLowerCase()] ?? impactRow.high;
}

/**
 * Returns `true` if the `slither` binary is available on `PATH`.
 *
 * Use this to gate optional Slither integration in {@link ScanConfig.useSlither}
 * before calling {@link scan}.
 *
 * @example
 * ```typescript
 * import { isSlitherAvailable } from '@chainproof/core';
 *
 * if (!isSlitherAvailable()) {
 *   console.warn('Slither not found — install with: pip install slither-analyzer');
 * }
 * ```
 */
export function isSlitherAvailable(): boolean {
  try {
    const result = spawnSync("slither", ["--version"], { encoding: "utf-8" });
    return result.status === 0;
  } catch {
    return false;
  }
}

/**
 * Filter raw Slither detector results by an include/exclude list of check
 * ids. `include` is an allowlist and takes precedence over `exclude`; with
 * neither set, every detector passes through unchanged.
 *
 * @internal
 */
export function filterDetectors(
  detectors: SlitherDetector[],
  config?: SlitherDetectorConfig,
): SlitherDetector[] {
  const include = config?.include;
  const exclude = config?.exclude;

  if (include && include.length > 0) {
    const allow = new Set(include.map((d) => d.toLowerCase()));
    return detectors.filter((d) => allow.has(d.check.toLowerCase()));
  }

  if (exclude && exclude.length > 0) {
    const deny = new Set(exclude.map((d) => d.toLowerCase()));
    return detectors.filter((d) => !deny.has(d.check.toLowerCase()));
  }

  return detectors;
}

/**
 * Build a ChainProof {@link Finding} from a single raw Slither detector
 * result, enriching it with the {@link DETECTOR_MAP} title/SWC reference and
 * confidence-weighted severity.
 *
 * @internal
 */
export function buildFindingFromDetector(
  d: SlitherDetector,
  filePath: string,
): Finding {
  const element = d.elements?.[0];
  const sourceMap = element?.source_mapping;
  const lines = sourceMap?.lines ?? [];
  const line = lines[0] ?? 0;
  const lineEnd = lines.length > 0 ? lines[lines.length - 1] : undefined;

  const info = getDetectorInfo(d.check);
  const severity = info?.severityOverride ?? mapSeverity(d.impact, d.confidence);

  return {
    id: `SLITHER-${d.check.toUpperCase()}`,
    title: info?.title ?? d.check.replace(/-/g, " "),
    description: d.description.trim(),
    recommendation:
      "Review the Slither detector documentation at " +
      `https://github.com/crytic/slither/wiki/Detector-Documentation#${d.check}`,
    severity,
    file: sourceMap?.filename_short ?? filePath,
    line,
    lineEnd: lineEnd !== undefined && lineEnd !== line ? lineEnd : undefined,
    swcId: info?.swcId,
  };
}

/**
 * Rule-category id used to deduplicate a finding against others covering the
 * same vulnerability class. Built-in ChainProof findings use their own `id`
 * (e.g. `"CP-107"`); Slither findings resolve through {@link DETECTOR_MAP} so
 * e.g. `reentrancy-eth` lines up with the built-in reentrancy rule's `CP-107`.
 *
 * @internal
 */
function categoryOf(finding: Finding): string {
  if (finding.id.startsWith("SLITHER-")) {
    const check = finding.id.slice("SLITHER-".length).toLowerCase();
    return getDetectorInfo(check)?.category ?? finding.id;
  }
  return finding.id;
}

function normalizedFile(file: string): string {
  return path.basename(file).toLowerCase();
}

function lineRange(finding: Finding): [number, number] {
  return [finding.line, finding.lineEnd ?? finding.line];
}

function rangesOverlap(a: [number, number], b: [number, number]): boolean {
  return a[0] <= b[1] && b[0] <= a[1];
}

/**
 * Merge Slither findings into an existing finding list, dropping any Slither
 * finding that duplicates one already present.
 *
 * Two findings are considered duplicates when they share a rule category
 * (see {@link categoryOf}), their files normalize to the same basename, and
 * their line ranges overlap — this catches both ChainProof/Slither pairs
 * covering the same vulnerability (e.g. `CP-107` vs `reentrancy-eth` on the
 * same lines) and Slither reporting the same issue once per inheritance
 * level.
 *
 * @internal
 */
export function mergeSlitherFindings(
  existingFindings: Finding[],
  slitherFindings: Finding[],
): Finding[] {
  const accepted = [...existingFindings];

  for (const sf of slitherFindings) {
    const category = categoryOf(sf);
    const file = normalizedFile(sf.file);
    const range = lineRange(sf);

    const isDuplicate = accepted.some(
      (ef) =>
        categoryOf(ef) === category &&
        normalizedFile(ef.file) === file &&
        rangesOverlap(lineRange(ef), range),
    );

    if (!isDuplicate) {
      accepted.push(sf);
    }
  }

  return accepted;
}

/**
 * Run Slither on a Solidity file and return parsed findings.
 * Requires Python and slither-analyzer to be installed:
 *   pip install slither-analyzer
 *
 * @param filePath - Path to the `.sol` file to analyze
 * @param detectorConfig - Optional include/exclude filter for Slither's
 *   built-in detectors (see {@link ScanConfig.slither}). Omit to run every
 *   detector, matching prior behavior.
 *
 * @internal
 */
export function runSlither(
  filePath: string,
  detectorConfig?: SlitherDetectorConfig,
): Finding[] {
  if (!isSlitherAvailable()) return [];

  const tmpOutput = path.join(process.cwd(), ".chainproof-slither-tmp.json");

  const cliArgs: string[] = [];
  if (detectorConfig?.include && detectorConfig.include.length > 0) {
    cliArgs.push(`--detect "${detectorConfig.include.join(",")}"`);
  } else if (detectorConfig?.exclude && detectorConfig.exclude.length > 0) {
    cliArgs.push(`--exclude-detectors "${detectorConfig.exclude.join(",")}"`);
  }

  try {
    execSync(
      `slither "${filePath}" --json "${tmpOutput}" --disable-color ${cliArgs.join(" ")} 2>/dev/null`,
      { stdio: "pipe" },
    );
  } catch {
    // Slither exits non-zero when it finds issues — that's expected
  }

  if (!fs.existsSync(tmpOutput)) return [];

  let raw: string;
  try {
    raw = fs.readFileSync(tmpOutput, "utf-8");
    fs.unlinkSync(tmpOutput);
  } catch {
    return [];
  }

  let parsed: SlitherOutput;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }

  // Defensive JS-side filter in addition to the CLI flags above, in case the
  // installed Slither version doesn't support one of them.
  const detectors = filterDetectors(
    parsed?.results?.detectors ?? [],
    detectorConfig,
  );

  return detectors.map((d) => buildFindingFromDetector(d, filePath));
}
