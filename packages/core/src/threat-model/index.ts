import * as path from "path";
import { collectSolFiles, scan } from "../scanner";
import type { Finding } from "../types";
import type { ThreatModelConfig, ThreatModel } from "./types";
import { extractThreatModel } from "./extractor";
import { prioritizeThreats } from "./prioritization";
import { loadAssumptions, mergeAssumptions } from "./assumptions";

export * from "./types";
export * from "./extractor";
export * from "./prioritization";
export * from "./assumptions";
export * from "./visualizer";
export * from "./reporter";

/**
 * Generates a complete threat model for the specified targets.
 */
export async function generateThreatModel(
  config: ThreatModelConfig,
  providedFindings?: Finding[]
): Promise<ThreatModel> {
  const resolvedTargets = config.targets.map((t) => path.resolve(t));
  const files = collectSolFiles(resolvedTargets);

  if (files.length === 0) {
    throw new Error(`No Solidity files found in targets: ${config.targets.join(", ")}`);
  }

  // 1. Gather findings if not provided
  let findings: Finding[] = [];
  if (providedFindings) {
    findings = providedFindings;
  } else {
    try {
      const scanRes = await scan({
        targets: resolvedTargets,
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      });
      findings = scanRes.files.flatMap((f) => f.findings);
    } catch {
      // Degraded execution: continue with empty findings if scan fails
      findings = [];
    }
  }

  // 2. Extract initial model from AST & findings
  const initialModel = extractThreatModel(files, findings);

  // 3. Prioritize threats
  const prioritized = prioritizeThreats(initialModel.threats, config.minSeverity);

  // 4. Create base ThreatModel structure
  const baseModel: ThreatModel = {
    version: "0.1.0",
    timestamp: new Date().toISOString(),
    targets: config.targets,
    assets: initialModel.assets,
    agents: initialModel.agents,
    attackSurface: initialModel.attackSurface,
    threats: prioritized,
    summary: {
      totalThreats: prioritized.length,
      bySeverity: {
        critical: prioritized.filter((t) => t.severity === "critical").length,
        high: prioritized.filter((t) => t.severity === "high").length,
        medium: prioritized.filter((t) => t.severity === "medium").length,
        low: prioritized.filter((t) => t.severity === "low").length,
      },
      mitigatedCount: prioritized.filter((t) => t.status === "mitigated").length,
      unmitigatedCount: prioritized.filter((t) => t.status !== "mitigated").length,
    },
  };

  // 5. Load and merge optional user assumptions
  const assumptions = loadAssumptions(config.assumptionsPath);
  const finalModel = mergeAssumptions(baseModel, assumptions);

  return finalModel;
}
