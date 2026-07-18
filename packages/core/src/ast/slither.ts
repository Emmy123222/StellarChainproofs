import { execSync, spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import type { Finding } from "../types";

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

/** Map Slither impact strings to our severity type */
function mapImpact(impact: string): Finding["severity"] {
  switch (impact.toLowerCase()) {
    case "high":      return "critical";
    case "medium":    return "high";
    case "low":       return "medium";
    case "informational": return "info";
    default:          return "low";
  }
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
 * Run Slither on a Solidity file and return parsed findings.
 * Requires Python and slither-analyzer to be installed:
 *   pip install slither-analyzer
 *
 * @internal
 */
export function runSlither(filePath: string): Finding[] {
  if (!isSlitherAvailable()) return [];

  const tmpOutput = path.join(process.cwd(), ".chainproof-slither-tmp.json");

  try {
    execSync(
      `slither "${filePath}" --json "${tmpOutput}" --disable-color 2>/dev/null`,
      { stdio: "pipe" }
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

  const detectors = parsed?.results?.detectors ?? [];
  const findings: Finding[] = [];

  for (const d of detectors) {
    const element = d.elements?.[0];
    const sourceMap = element?.source_mapping;
    const line = sourceMap?.lines?.[0] ?? 0;

    findings.push({
      id: `SLITHER-${d.check.toUpperCase()}`,
      title: d.check.replace(/-/g, " "),
      description: d.description.trim(),
      recommendation:
        "Review the Slither detector documentation at " +
        `https://github.com/crytic/slither/wiki/Detector-Documentation#${d.check}`,
      severity: mapImpact(d.impact),
      file: sourceMap?.filename_short ?? filePath,
      line,
      snippet: undefined,
    });
  }

  return findings;
}
