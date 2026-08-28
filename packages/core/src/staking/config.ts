import {
  STAKING_CONFIG_SCHEMA_VERSION,
  type StakingAnalysisConfigInput,
  type StakingAnalysisConfigV1,
  type StakingAnalysisLimits,
  type StakingDiagnostic,
  type StakingRuleId,
  type ValidatedStakingConfig,
} from "./types";
import * as fs from "fs";

/** Conservative defaults prevent adversarial source from exhausting CI workers. */
export const DEFAULT_STAKING_LIMITS: Readonly<StakingAnalysisLimits> = Object.freeze({
  maxSourceBytes: 2 * 1024 * 1024,
  maxFiles: 256,
  maxContracts: 128,
  maxFunctionsPerFile: 512,
  maxFunctionsPerContract: 512,
  maxOperationsPerFunction: 2048,
  maxFindings: 1024,
  maxEvidencePerFinding: 12,
});

const RULE_IDS: ReadonlySet<string> = new Set([
  "CP-STK-001",
  "CP-STK-002",
  "CP-STK-003",
  "CP-STK-004",
  "CP-STK-005",
  "CP-STK-006",
  "CP-STK-007",
  "CP-STK-008",
  "CP-STK-009",
  "CP-STK-010",
  "CP-STK-011",
  "CP-STK-012",
  "CP-STK-013",
]);

const LIMIT_KEYS: Array<keyof StakingAnalysisLimits> = [
  "maxSourceBytes",
  "maxFiles",
  "maxContracts",
  "maxFunctionsPerFile",
  "maxFunctionsPerContract",
  "maxOperationsPerFunction",
  "maxFindings",
  "maxEvidencePerFinding",
];

/** Error raised for a malformed configuration before source analysis begins. */
export class StakingConfigError extends Error {
  readonly code = "STK_CONFIG_INVALID";

  constructor(message: string) {
    super(message);
    this.name = "StakingConfigError";
  }
}

/** Error raised when cooperative cancellation is observed. */
export class StakingAnalysisCancelledError extends Error {
  readonly code = "STK_CANCELLED";

  constructor() {
    super("Staking accounting analysis was cancelled");
    this.name = "StakingAnalysisCancelledError";
  }
}

/** Merge caller limits with defaults and reject values that could disable bounds. */
export function resolveStakingLimits(
  input?: Partial<StakingAnalysisLimits>,
): StakingAnalysisLimits {
  if (input !== undefined && !isRecord(input)) {
    throw new StakingConfigError("limits must be an object");
  }

  const result: StakingAnalysisLimits = { ...DEFAULT_STAKING_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = input?.[key];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new StakingConfigError(`${key} must be a positive safe integer`);
    }
    result[key] = value;
  }
  return result;
}

/**
 * Migrate legacy v0 configuration into the current v1 schema.
 * Unknown fields are intentionally discarded so serialization stays stable.
 */
export function migrateStakingConfig(
  input: StakingAnalysisConfigInput,
): ValidatedStakingConfig {
  if (!isRecord(input)) {
    throw new StakingConfigError("configuration root must be an object");
  }

  if (input.schemaVersion === STAKING_CONFIG_SCHEMA_VERSION) {
    return validateV1(input);
  }

  if (input.schemaVersion !== undefined && input.schemaVersion !== 0) {
    throw new StakingConfigError(
      `unsupported staking configuration schemaVersion ${String(input.schemaVersion)}`,
    );
  }

  const diagnostics: StakingDiagnostic[] = [];
  const limits: Partial<StakingAnalysisLimits> = {};
  if (input.maxFileSize !== undefined) {
    limits.maxSourceBytes = asPositiveInteger(input.maxFileSize, "maxFileSize");
  }
  if (input.maxIssues !== undefined) {
    limits.maxFindings = asPositiveInteger(input.maxIssues, "maxIssues");
  }

  const includeRules = input.rules === undefined
    ? undefined
    : validateRuleList(input.rules, "rules");

  if (
    input.version === 0 ||
    input.maxFileSize !== undefined ||
    input.maxIssues !== undefined ||
    input.rules !== undefined
  ) {
    diagnostics.push({
      code: "STK_CONFIG_INVALID",
      severity: "info",
      message: "Migrated staking configuration from legacy schema v0 to v1",
    });
  }

  const config: StakingAnalysisConfigV1 = {
    schemaVersion: STAKING_CONFIG_SCHEMA_VERSION,
    ...(Object.keys(limits).length > 0 ? { limits } : {}),
    ...(typeof input.includeModels === "boolean"
      ? { includeModels: input.includeModels }
      : {}),
    ...(includeRules ? { includeRules } : {}),
  };
  resolveStakingLimits(config.limits);
  return { config, diagnostics };
}

/** Validate a current configuration and return a normalized copy. */
export function validateStakingConfig(
  input: StakingAnalysisConfigInput,
): ValidatedStakingConfig {
  return migrateStakingConfig(input);
}

/**
 * Load, parse, migrate, and validate a staking configuration artifact.
 * Parse failures deliberately omit the local path and source content.
 */
export function loadStakingConfigFile(filePath: string): ValidatedStakingConfig {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new StakingConfigError(`configuration file could not be read (${errorCode(error)})`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new StakingConfigError("configuration file contains invalid JSON");
  }
  return validateStakingConfig(parsed as StakingAnalysisConfigInput);
}

function validateV1(input: Record<string, unknown>): ValidatedStakingConfig {
  if (input.includeModels !== undefined && typeof input.includeModels !== "boolean") {
    throw new StakingConfigError("includeModels must be a boolean");
  }

  const limits = input.limits === undefined
    ? undefined
    : validateLimitsObject(input.limits);
  const includeRules = input.includeRules === undefined
    ? undefined
    : validateRuleList(input.includeRules, "includeRules");
  const excludeRules = input.excludeRules === undefined
    ? undefined
    : validateRuleList(input.excludeRules, "excludeRules");

  if (includeRules && excludeRules) {
    const overlap = includeRules.filter((rule) => excludeRules.includes(rule));
    if (overlap.length > 0) {
      throw new StakingConfigError(
        `includeRules and excludeRules overlap: ${overlap.join(", ")}`,
      );
    }
  }

  return {
    config: {
      schemaVersion: STAKING_CONFIG_SCHEMA_VERSION,
      ...(limits ? { limits } : {}),
      ...(typeof input.includeModels === "boolean"
        ? { includeModels: input.includeModels }
        : {}),
      ...(includeRules ? { includeRules } : {}),
      ...(excludeRules ? { excludeRules } : {}),
    },
    diagnostics: [],
  };
}

function validateLimitsObject(value: unknown): Partial<StakingAnalysisLimits> {
  if (!isRecord(value)) {
    throw new StakingConfigError("limits must be an object");
  }
  const result: Partial<StakingAnalysisLimits> = {};
  for (const key of LIMIT_KEYS) {
    if (value[key] !== undefined) {
      result[key] = asPositiveInteger(value[key], key);
    }
  }
  resolveStakingLimits(result);
  return result;
}

function validateRuleList(value: unknown, field: string): StakingRuleId[] {
  if (!Array.isArray(value)) {
    throw new StakingConfigError(`${field} must be an array`);
  }
  const unique = new Set<StakingRuleId>();
  for (const item of value) {
    if (typeof item !== "string" || !RULE_IDS.has(item)) {
      throw new StakingConfigError(`${field} contains unknown rule ${String(item)}`);
    }
    unique.add(item as StakingRuleId);
  }
  return [...unique].sort();
}

function asPositiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new StakingConfigError(`${field} must be a positive safe integer`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : "IO_ERROR";
}
