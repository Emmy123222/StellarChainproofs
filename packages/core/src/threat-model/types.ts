export type SeverityLevel = "critical" | "high" | "medium" | "low";
export type AssetValue = "high" | "medium" | "low";

export interface LocationInfo {
  line: number;
  file: string;
}

export type AssetType =
  | "token"
  | "vault"
  | "governance"
  | "oracle"
  | "access_control"
  | "logic"
  | "other";

/**
 * An identified valuable asset or target within the contract.
 */
export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  description: string;
  value: AssetValue;
  definedIn: string;
  location?: LocationInfo;
}

/**
 * An agent modeled as a potential threat actor.
 */
export interface ThreatAgent {
  id: string;
  name: string;
  description: string;
  capabilities: string[];
  motivation: string;
}

/**
 * A trust boundary segregating sections of code/actors.
 */
export interface TrustBoundary {
  id: string;
  name: string;
  description: string;
  components: string[]; // e.g., ["ContractName", "ContractName.functionName"]
}

/**
 * Entry points exposed externally.
 */
export interface EntryPoint {
  name: string;
  signature: string;
  visibility: string;
  isPayable: boolean;
  modifiers: string[];
  contract: string;
  line: number;
}

/**
 * The mapped attack surface of the contracts.
 */
export interface AttackSurface {
  entryPoints: EntryPoint[];
  trustBoundaries: TrustBoundary[];
}

export type STRIDECategory =
  | "Spoofing"
  | "Tampering"
  | "Repudiation"
  | "InformationDisclosure"
  | "DenialOfService"
  | "ElevationOfPrivilege";

export type DeFiCategory =
  | "Reentrancy"
  | "OracleManipulation"
  | "FlashloanAttack"
  | "Frontrunning"
  | "AccessControl"
  | "Governance"
  | "Other";

/**
 * A threat mapped to STRIDE/DeFi categories, evaluated for risk, and associated with mitigations.
 */
export interface Threat {
  id: string;
  title: string;
  strideCategory: STRIDECategory;
  defiCategory: DeFiCategory;
  description: string;
  targetAssetId: string;
  agentId: string;
  attackVector: string;
  likelihood: AssetValue;
  impact: AssetValue;
  riskScore: number; // 0-100 score (calculated from likelihood and impact)
  severity: SeverityLevel;
  mitigations: string[];
  status: "unmitigated" | "partially_mitigated" | "mitigated";
  location?: LocationInfo;
}

export interface ThreatModelSummary {
  totalThreats: number;
  bySeverity: Record<SeverityLevel, number>;
  mitigatedCount: number;
  unmitigatedCount: number;
}

/**
 * The final generated threat model report object.
 */
export interface ThreatModel {
  version: string;
  timestamp: string;
  targets: string[];
  assets: Asset[];
  agents: ThreatAgent[];
  attackSurface: AttackSurface;
  threats: Threat[];
  summary: ThreatModelSummary;
}

/**
 * User-provided assumptions/overrides to support team collaboration and refine analysis.
 */
export interface ThreatModelAssumptions {
  customAssets?: Asset[];
  customThreats?: Partial<Threat>[];
  mitigations?: Record<string, string[]>; // threatId -> list of mitigations or status overrides
  trustBoundaries?: { name: string; description: string; targets: string[] }[];
  agentOverrides?: ThreatAgent[];
  threatStatuses?: Record<string, "unmitigated" | "partially_mitigated" | "mitigated">;
}

export interface ThreatModelConfig {
  targets: string[];
  framework?: "stride" | "defi" | "both";
  assumptionsPath?: string;
  outputFormat?: "markdown" | "json";
  output?: string;
  minSeverity?: SeverityLevel;
}
