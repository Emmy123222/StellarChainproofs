import type { Severity } from "../types";

/** Version of the deterministic staking analysis report contract. */
export const STAKING_REPORT_SCHEMA_VERSION = "1.0.0" as const;

/** Version of the validated analysis configuration contract. */
export const STAKING_CONFIG_SCHEMA_VERSION = 1 as const;

/** Rules emitted by the staking, reward, and vesting accounting engine. */
export type StakingRuleId =
  | "CP-STK-001"
  | "CP-STK-002"
  | "CP-STK-003"
  | "CP-STK-004"
  | "CP-STK-005"
  | "CP-STK-006"
  | "CP-STK-007"
  | "CP-STK-008"
  | "CP-STK-009"
  | "CP-STK-010"
  | "CP-STK-011"
  | "CP-STK-012"
  | "CP-STK-013";

/** Semantic role inferred for a state variable. */
export type AccountingVariableRole =
  | "stake-asset"
  | "reward-asset"
  | "total-supply"
  | "user-balance"
  | "reward-rate"
  | "reward-index"
  | "user-index"
  | "accrued-reward"
  | "duration"
  | "period-finish"
  | "last-update"
  | "queued-reward"
  | "epoch"
  | "vesting-start"
  | "vesting-duration"
  | "vesting-cliff"
  | "vested-amount"
  | "claimed-amount"
  | "penalty"
  | "pause-state"
  | "administrator"
  | "unknown";

/** Semantic role inferred for a function. */
export type AccountingFunctionRole =
  | "stake"
  | "withdraw"
  | "claim-reward"
  | "exit"
  | "checkpoint"
  | "reward-index"
  | "notify-reward"
  | "set-reward-rate"
  | "emergency-withdraw"
  | "recover-token"
  | "pause"
  | "unpause"
  | "vest"
  | "claim-vested"
  | "revoke-vesting"
  | "epoch-rollover"
  | "unknown";

/** Framework/pattern adapter selected from explicit structural evidence. */
export type StakingFrameworkAdapter =
  | "synthetix-staking-rewards"
  | "masterchef-accumulator"
  | "openzeppelin-vesting-wallet"
  | "accumulated-index"
  | "generic-staking"
  | "generic-vesting"
  | "none";

/** Public description of the structural signals required by a framework adapter. */
export interface StakingFrameworkAdapterDefinition {
  id: Exclude<StakingFrameworkAdapter, "generic-staking" | "generic-vesting" | "none">;
  displayName: string;
  requiredStateGroups: string[][];
  requiredFunctions: string[];
  guarantees: string[];
  limitations: string[];
}

/** Adapter match with the exact normalized signals that selected it. */
export interface StakingFrameworkAdapterMatch {
  adapter: StakingFrameworkAdapter;
  matchedState: string[];
  matchedFunctions: string[];
}

/** A precise source range. Lines and columns are one-indexed. */
export interface StakingSourceLocation {
  file: string;
  line: number;
  column: number;
  lineEnd?: number;
  columnEnd?: number;
}

/** A provable observation used to support or suppress a finding. */
export interface StakingEvidence {
  kind:
    | "state-read"
    | "state-write"
    | "arithmetic"
    | "branch"
    | "call"
    | "modifier"
    | "ordering"
    | "adapter"
    | "absence";
  description: string;
  location: StakingSourceLocation;
  snippet?: string;
}

/** State variable in the normalized accounting model. */
export interface AccountingStateVariable {
  name: string;
  typeName: string;
  role: AccountingVariableRole;
  isMapping: boolean;
  location: StakingSourceLocation;
}

/** A state access or external call in lexical execution order. */
export interface AccountingOperation {
  order: number;
  kind: "read" | "write" | "call" | "arithmetic" | "guard";
  name: string;
  expression: string;
  location: StakingSourceLocation;
}

/** Function represented as an accounting state transition. */
export interface AccountingTransition {
  name: string;
  role: AccountingFunctionRole;
  visibility: string;
  modifiers: string[];
  parameters: string[];
  reads: string[];
  writes: string[];
  calls: string[];
  operations: AccountingOperation[];
  location: StakingSourceLocation;
  source: string;
}

/** Contract-level model consumed by the accounting rules. */
export interface StakingContractModel {
  name: string;
  file: string;
  adapter: StakingFrameworkAdapter;
  stateVariables: AccountingStateVariable[];
  transitions: AccountingTransition[];
  precisionScalars: string[];
  rewardTokens: string[];
  stakeTokens: string[];
  assumptions: string[];
  location: StakingSourceLocation;
}

/** Structured staking/vesting accounting finding. */
export interface StakingFinding {
  ruleId: StakingRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: Exclude<Severity, "gas">;
  confidence: "high" | "medium" | "low";
  category:
    | "checkpoint"
    | "precision"
    | "distribution"
    | "zero-supply"
    | "asset-accounting"
    | "vesting"
    | "authorization"
    | "emergency";
  contract: string;
  location: StakingSourceLocation;
  evidence: StakingEvidence[];
  assumptions: string[];
}

/** Non-finding diagnostic generated while building or bounding the model. */
export interface StakingDiagnostic {
  code:
    | "STK_PARSE_ERROR"
    | "STK_SOURCE_LIMIT"
    | "STK_CONTRACT_LIMIT"
    | "STK_FUNCTION_LIMIT"
    | "STK_OPERATION_LIMIT"
    | "STK_CANCELLED"
    | "STK_CONFIG_INVALID"
    | "STK_FILE_UNREADABLE";
  severity: "error" | "warning" | "info";
  message: string;
  location?: StakingSourceLocation;
}

/** Explicit resource budget applied independently to every analysis call. */
export interface StakingAnalysisLimits {
  maxSourceBytes: number;
  maxFiles: number;
  maxContracts: number;
  maxFunctionsPerFile: number;
  maxFunctionsPerContract: number;
  maxOperationsPerFunction: number;
  maxFindings: number;
  maxEvidencePerFinding: number;
}

/** Cancellation shape compatible with AbortSignal without requiring DOM types. */
export interface StakingCancellationSignal {
  readonly aborted: boolean;
  readonly reason?: unknown;
}

/** Runtime options for deterministic staking analysis. */
export interface StakingAnalysisOptions {
  limits?: Partial<StakingAnalysisLimits>;
  signal?: StakingCancellationSignal;
  includeModels?: boolean;
  includeRules?: StakingRuleId[];
  excludeRules?: StakingRuleId[];
}

/** Versioned on-disk configuration accepted by the CLI and integrations. */
export interface StakingAnalysisConfigV1 {
  schemaVersion: 1;
  limits?: Partial<StakingAnalysisLimits>;
  includeModels?: boolean;
  includeRules?: StakingRuleId[];
  excludeRules?: StakingRuleId[];
}

/** Legacy configuration migrated by {@link migrateStakingConfig}. */
export interface StakingAnalysisConfigV0 {
  version?: 0;
  maxFileSize?: number;
  maxIssues?: number;
  rules?: StakingRuleId[];
  includeModels?: boolean;
}

export type StakingAnalysisConfigInput =
  | StakingAnalysisConfigV1
  | StakingAnalysisConfigV0
  | Record<string, unknown>;

/** Per-file result; input order is not used for report serialization. */
export interface StakingFileAnalysis {
  file: string;
  findings: StakingFinding[];
  diagnostics: StakingDiagnostic[];
  models?: StakingContractModel[];
}

/** Stable aggregate result produced by all public staking analysis entry points. */
export interface StakingAnalysisReport {
  schemaVersion: typeof STAKING_REPORT_SCHEMA_VERSION;
  engineVersion: string;
  files: StakingFileAnalysis[];
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

/** Input accepted by project analysis without requiring filesystem access. */
export interface StakingSourceInput {
  file: string;
  source: string;
}

/** Validated config and any non-fatal migration notices. */
export interface ValidatedStakingConfig {
  config: StakingAnalysisConfigV1;
  diagnostics: StakingDiagnostic[];
}
