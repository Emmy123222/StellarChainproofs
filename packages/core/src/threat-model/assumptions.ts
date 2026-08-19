import * as fs from "fs";
import type { ThreatModel, ThreatModelAssumptions, Asset, Threat, TrustBoundary } from "./types";

/**
 * Loads user assumptions from a JSON file. Returns empty object if file does not exist or fails to parse.
 */
export function loadAssumptions(filePath?: string): ThreatModelAssumptions {
  if (!filePath || !fs.existsSync(filePath)) {
    return {};
  }
  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw) as ThreatModelAssumptions;
  } catch (err) {
    console.warn(`[ChainProof] Warning: Failed to load assumptions file from ${filePath}: ${err}`);
    return {};
  }
}

/**
 * Merges user assumptions into the generated threat model.
 */
export function mergeAssumptions(
  model: ThreatModel,
  assumptions: ThreatModelAssumptions
): ThreatModel {
  const mergedAssets = [...model.assets];
  const mergedThreats = [...model.threats];
  const mergedBoundaries = [...model.attackSurface.trustBoundaries];
  const mergedAgents = [...model.agents];

  // 1. Merge custom assets
  if (assumptions.customAssets) {
    for (const asset of assumptions.customAssets) {
      const idx = mergedAssets.findIndex((a) => a.id === asset.id);
      if (idx !== -1) {
        mergedAssets[idx] = asset;
      } else {
        mergedAssets.push(asset);
      }
    }
  }

  // 2. Merge agent overrides
  if (assumptions.agentOverrides) {
    for (const agent of assumptions.agentOverrides) {
      const idx = mergedAgents.findIndex((g) => g.id === agent.id);
      if (idx !== -1) {
        mergedAgents[idx] = agent;
      } else {
        mergedAgents.push(agent);
      }
    }
  }

  // 3. Merge custom/override trust boundaries
  if (assumptions.trustBoundaries) {
    for (const boundary of assumptions.trustBoundaries) {
      const id = boundary.name.toLowerCase().replace(/\s+/g, "-");
      const idx = mergedBoundaries.findIndex((b) => b.id === id);
      const newBoundary: TrustBoundary = {
        id,
        name: boundary.name,
        description: boundary.description,
        components: boundary.targets,
      };
      if (idx !== -1) {
        mergedBoundaries[idx] = newBoundary;
      } else {
        mergedBoundaries.push(newBoundary);
      }
    }
  }

  // 4. Merge custom threats and update mitigations/statuses
  if (assumptions.customThreats) {
    for (const threatOverride of assumptions.customThreats) {
      if (!threatOverride.id) continue;
      const idx = mergedThreats.findIndex((t) => t.id === threatOverride.id);
      if (idx !== -1) {
        // Merge fields
        mergedThreats[idx] = {
          ...mergedThreats[idx],
          ...threatOverride,
        } as Threat;
      } else {
        // Append new custom threat (require minimum fields)
        const newThreat: Threat = {
          id: threatOverride.id,
          title: threatOverride.title ?? "Custom Threat",
          strideCategory: threatOverride.strideCategory ?? "Tampering",
          defiCategory: threatOverride.defiCategory ?? "Other",
          description: threatOverride.description ?? "User identified custom threat.",
          targetAssetId: threatOverride.targetAssetId ?? "asset-unknown",
          agentId: threatOverride.agentId ?? "agent-external-attacker",
          attackVector: threatOverride.attackVector ?? "Unknown vector",
          likelihood: threatOverride.likelihood ?? "medium",
          impact: threatOverride.impact ?? "medium",
          riskScore: threatOverride.riskScore ?? 50,
          severity: threatOverride.severity ?? "medium",
          mitigations: threatOverride.mitigations ?? [],
          status: threatOverride.status ?? "unmitigated",
        };
        mergedThreats.push(newThreat);
      }
    }
  }

  // Apply mitigations mapping from assumptions (threatId -> list of mitigations)
  if (assumptions.mitigations) {
    for (const [threatId, mitigationsList] of Object.entries(assumptions.mitigations)) {
      const idx = mergedThreats.findIndex((t) => t.id === threatId);
      if (idx !== -1) {
        mergedThreats[idx].mitigations = [
          ...new Set([...mergedThreats[idx].mitigations, ...mitigationsList]),
        ];
        // If there are mitigations defined, promote status
        if (mergedThreats[idx].status === "unmitigated") {
          mergedThreats[idx].status = "partially_mitigated";
        }
      }
    }
  }

  // Apply status overrides (threatId -> status)
  if (assumptions.threatStatuses) {
    for (const [threatId, status] of Object.entries(assumptions.threatStatuses)) {
      const idx = mergedThreats.findIndex((t) => t.id === threatId);
      if (idx !== -1) {
        mergedThreats[idx].status = status;
      }
    }
  }

  // 5. Recalculate summary metrics
  const summary = {
    totalThreats: mergedThreats.length,
    bySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
    mitigatedCount: 0,
    unmitigatedCount: 0,
  };

  for (const t of mergedThreats) {
    summary.bySeverity[t.severity]++;
    if (t.status === "mitigated") {
      summary.mitigatedCount++;
    } else {
      summary.unmitigatedCount++;
    }
  }

  return {
    ...model,
    assets: mergedAssets,
    agents: mergedAgents,
    attackSurface: {
      ...model.attackSurface,
      trustBoundaries: mergedBoundaries,
    },
    threats: mergedThreats,
    summary,
  };
}
