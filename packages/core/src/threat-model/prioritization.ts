import type { Threat, STRIDECategory, DeFiCategory, AssetValue, SeverityLevel } from "./types";

const VALUE_WEIGHTS: Record<AssetValue, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Calculates a composite risk score from 0 to 100.
 * Refined by security weights for specific STRIDE and DeFi categories to match expert assessments.
 */
export function calculateRisk(
  likelihood: AssetValue,
  impact: AssetValue,
  stride: STRIDECategory,
  defi: DeFiCategory
): { riskScore: number; severity: SeverityLevel } {
  const lVal = VALUE_WEIGHTS[likelihood];
  const iVal = VALUE_WEIGHTS[impact];

  // Base score 1-9
  let baseScore = lVal * iVal;

  // Expert adjustment factors based on category severity weights
  let categoryMultiplier = 1.0;

  if (defi === "AccessControl" || stride === "ElevationOfPrivilege") {
    categoryMultiplier = 1.2; // Access control issues are extremely critical
  } else if (defi === "Reentrancy" || defi === "OracleManipulation") {
    categoryMultiplier = 1.1; // Reentrancy and Oracle manipulation are high-risk DeFi vectors
  } else if (stride === "Repudiation" || stride === "InformationDisclosure") {
    categoryMultiplier = 0.8; // Lower direct security impact
  }

  const rawScore = (baseScore / 9) * 100 * categoryMultiplier;
  const riskScore = Math.min(100, Math.max(0, Math.round(rawScore)));

  let severity: SeverityLevel = "low";
  if (riskScore >= 80) {
    severity = "critical";
  } else if (riskScore >= 60) {
    severity = "high";
  } else if (riskScore >= 35) {
    severity = "medium";
  }

  return { riskScore, severity };
}

/**
 * Sorts and filters threats based on the chosen framework and minimum severity.
 */
export function prioritizeThreats(
  threats: Threat[],
  minSeverity?: SeverityLevel
): Threat[] {
  const severityRank: Record<SeverityLevel, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };

  const processed = threats.map((t) => {
    const { riskScore, severity } = calculateRisk(
      t.likelihood,
      t.impact,
      t.strideCategory,
      t.defiCategory
    );
    return {
      ...t,
      riskScore,
      severity,
    };
  });

  // Filter by minSeverity
  const minRank = minSeverity ? severityRank[minSeverity] : 0;
  const filtered = processed.filter((t) => severityRank[t.severity] >= minRank);

  // Sort descending by riskScore
  return filtered.sort((a, b) => b.riskScore - a.riskScore);
}
