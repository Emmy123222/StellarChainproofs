import type { Severity } from "../types";

export const GOVERNANCE_REPORT_SCHEMA_VERSION = "1.0.0" as const;
export const GOVERNANCE_CONFIG_SCHEMA_VERSION = 1 as const;

export type GovernanceRuleId =
  | "CP-GOV-001"
  | "CP-GOV-002"
  | "CP-GOV-003"
  | "CP-GOV-004"
  | "CP-GOV-005"
  | "CP-GOV-006"
  | "CP-GOV-007"
  | "CP-GOV-008"
  | "CP-GOV-009"
  | "CP-GOV-010"
  | "CP-GOV-011"
  | "CP-GOV-012"
  | "CP-GOV-013"
  | "CP-GOV-014"
  | "CP-GOV-015"
  | "CP-GOV-016";

export type GovernanceVariableRole =
  | "governance-token"
  | "proposal-count"
  | "proposal-state"
  | "proposal-threshold"
  | "quorum"
  | "quorum-numerator"
  | "quorum-denominator"
  | "voting-delay"
  | "voting-period"
  | "vote-snapshot"
  | "vote-receipt"
  | "vote-weight"
  | "proposal-eta"
  | "minimum-delay"
  | "operation-hash"
  | "executed-state"
  | "canceled-state"
  | "nonce"
  | "salt"
  | "predecessor"
  | "proposer-role"
  | "executor-role"
  | "admin-role"
  | "guardian"
  | "signer-set"
  | "signature-threshold"
  | "chain-domain"
  | "message-id"
  | "upgrade-authority"
  | "unknown";

export type GovernanceFunctionRole =
  | "propose"
  | "cast-vote"
  | "voting-power"
  | "quorum"
  | "proposal-state"
  | "queue"
  | "schedule"
  | "execute"
  | "cancel"
  | "set-delay"
  | "hash-proposal"
  | "hash-operation"
  | "grant-role"
  | "revoke-role"
  | "emergency-execute"
  | "upgrade"
  | "cross-chain-receive"
  | "validate-signatures"
  | "multisig-execute"
  | "delegate-votes"
  | "unknown";

export type GovernanceFrameworkAdapter =
  | "openzeppelin-governor"
  | "openzeppelin-timelock-controller"
  | "compound-governor-bravo"
  | "safe-multisig"
  | "cross-chain-governor"
  | "checkpointed-governance"
  | "generic-governance"
  | "generic-timelock"
  | "none";

export interface GovernanceFrameworkAdapterDefinition {
  id: Exclude<
    GovernanceFrameworkAdapter,
    "checkpointed-governance" | "generic-governance" | "generic-timelock" | "none"
  >;
  displayName: string;
  requiredStateGroups: string[][];
  requiredFunctions: string[];
  mitigations: string[];
  limitations: string[];
}

export interface GovernanceFrameworkMatch {
  adapter: GovernanceFrameworkAdapter;
  matchedState: string[];
  matchedFunctions: string[];
}

export interface GovernanceSourceLocation {
  file: string;
  line: number;
  column: number;
  lineEnd?: number;
  columnEnd?: number;
}

export interface GovernanceEvidence {
  kind:
    | "state-read"
    | "state-write"
    | "arithmetic"
    | "branch"
    | "call"
    | "modifier"
    | "ordering"
    | "taint-flow"
    | "adapter"
    | "absence";
  description: string;
  location: GovernanceSourceLocation;
  snippet?: string;
}

export interface GovernanceStateVariable {
  name: string;
  typeName: string;
  role: GovernanceVariableRole;
  isMapping: boolean;
  location: GovernanceSourceLocation;
}

export interface GovernanceOperation {
  order: number;
  kind: "read" | "write" | "call" | "arithmetic" | "guard";
  name: string;
  expression: string;
  parameterSources: string[];
  location: GovernanceSourceLocation;
}

export interface GovernanceTransition {
  name: string;
  role: GovernanceFunctionRole;
  visibility: string;
  modifiers: string[];
  parameters: string[];
  reads: string[];
  writes: string[];
  calls: string[];
  operations: GovernanceOperation[];
  location: GovernanceSourceLocation;
  source: string;
}

export interface GovernanceContractModel {
  name: string;
  file: string;
  adapter: GovernanceFrameworkAdapter;
  stateVariables: GovernanceStateVariable[];
  transitions: GovernanceTransition[];
  privilegedCalls: GovernanceOperation[];
  proposalControlledCalls: GovernanceOperation[];
  assumptions: string[];
  location: GovernanceSourceLocation;
}

export interface GovernanceFinding {
  ruleId: GovernanceRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: Exclude<Severity, "gas">;
  confidence: "high" | "medium" | "low";
  category:
    | "voting-power"
    | "proposal-lifecycle"
    | "quorum-threshold"
    | "timelock"
    | "replay"
    | "authorization"
    | "execution"
    | "upgrade"
    | "cross-chain"
    | "multisig";
  contract: string;
  location: GovernanceSourceLocation;
  evidence: GovernanceEvidence[];
  assumptions: string[];
}

export interface GovernanceDiagnostic {
  code:
    | "GOV_PARSE_ERROR"
    | "GOV_SOURCE_LIMIT"
    | "GOV_CONTRACT_LIMIT"
    | "GOV_FUNCTION_LIMIT"
    | "GOV_OPERATION_LIMIT"
    | "GOV_FINDING_LIMIT"
    | "GOV_CANCELLED"
    | "GOV_CONFIG_INVALID"
    | "GOV_FILE_UNREADABLE";
  severity: "error" | "warning" | "info";
  message: string;
  location?: GovernanceSourceLocation;
}

export interface GovernanceAnalysisLimits {
  maxSourceBytes: number;
  maxFiles: number;
  maxContracts: number;
  maxFunctionsPerFile: number;
  maxFunctionsPerContract: number;
  maxOperationsPerFunction: number;
  maxFindings: number;
  maxEvidencePerFinding: number;
}

export interface GovernanceCancellationSignal {
  readonly aborted: boolean;
  readonly reason?: unknown;
}

export interface GovernanceAnalysisOptions {
  limits?: Partial<GovernanceAnalysisLimits>;
  signal?: GovernanceCancellationSignal;
  includeModels?: boolean;
  includeRules?: GovernanceRuleId[];
  excludeRules?: GovernanceRuleId[];
}

export interface GovernanceAnalysisConfigV1 {
  schemaVersion: 1;
  limits?: Partial<GovernanceAnalysisLimits>;
  includeModels?: boolean;
  includeRules?: GovernanceRuleId[];
  excludeRules?: GovernanceRuleId[];
}

export interface GovernanceAnalysisConfigV0 {
  version?: 0;
  maxFileSize?: number;
  maxIssues?: number;
  detectors?: GovernanceRuleId[];
  includeModels?: boolean;
}

export type GovernanceAnalysisConfigInput =
  | GovernanceAnalysisConfigV1
  | GovernanceAnalysisConfigV0
  | Record<string, unknown>;

export interface GovernanceFileAnalysis {
  file: string;
  findings: GovernanceFinding[];
  diagnostics: GovernanceDiagnostic[];
  models?: GovernanceContractModel[];
}

export interface GovernanceAnalysisReport {
  schemaVersion: typeof GOVERNANCE_REPORT_SCHEMA_VERSION;
  engineVersion: string;
  files: GovernanceFileAnalysis[];
  summary: {
    files: number;
    contracts: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
    truncated: boolean;
  };
}

export interface GovernanceSourceInput {
  file: string;
  source: string;
}

export interface ValidatedGovernanceConfig {
  config: GovernanceAnalysisConfigV1;
  diagnostics: GovernanceDiagnostic[];
}
