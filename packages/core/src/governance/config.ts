import * as fs from "fs";
import {
  GOVERNANCE_CONFIG_SCHEMA_VERSION,
  type GovernanceAnalysisConfigInput,
  type GovernanceAnalysisConfigV1,
  type GovernanceAnalysisLimits,
  type GovernanceDiagnostic,
  type GovernanceRuleId,
  type ValidatedGovernanceConfig,
} from "./types";

export const DEFAULT_GOVERNANCE_LIMITS: Readonly<GovernanceAnalysisLimits> = Object.freeze({
  maxSourceBytes: 2 * 1024 * 1024,
  maxFiles: 256,
  maxContracts: 128,
  maxFunctionsPerFile: 512,
  maxFunctionsPerContract: 512,
  maxOperationsPerFunction: 2048,
  maxFindings: 1024,
  maxEvidencePerFinding: 12,
});

const RULE_IDS = new Set<string>(Array.from({ length: 16 }, (_, index) =>
  `CP-GOV-${String(index + 1).padStart(3, "0")}`,
));

const LIMIT_KEYS: Array<keyof GovernanceAnalysisLimits> = [
  "maxSourceBytes",
  "maxFiles",
  "maxContracts",
  "maxFunctionsPerFile",
  "maxFunctionsPerContract",
  "maxOperationsPerFunction",
  "maxFindings",
  "maxEvidencePerFinding",
];

export class GovernanceConfigError extends Error {
  readonly code = "GOV_CONFIG_INVALID";

  constructor(message: string) {
    super(message);
    this.name = "GovernanceConfigError";
  }
}

export class GovernanceAnalysisCancelledError extends Error {
  readonly code = "GOV_CANCELLED";

  constructor() {
    super("Governance safety analysis was cancelled");
    this.name = "GovernanceAnalysisCancelledError";
  }
}

export function resolveGovernanceLimits(
  input?: Partial<GovernanceAnalysisLimits>,
): GovernanceAnalysisLimits {
  if (input !== undefined && !isRecord(input)) {
    throw new GovernanceConfigError("limits must be an object");
  }
  const result: GovernanceAnalysisLimits = { ...DEFAULT_GOVERNANCE_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value = input?.[key];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new GovernanceConfigError(`${key} must be a positive safe integer`);
    }
    result[key] = value;
  }
  return result;
}

export function migrateGovernanceConfig(
  input: GovernanceAnalysisConfigInput,
): ValidatedGovernanceConfig {
  if (!isRecord(input)) throw new GovernanceConfigError("configuration root must be an object");
  if (input.schemaVersion === GOVERNANCE_CONFIG_SCHEMA_VERSION) return validateV1(input);
  if (input.schemaVersion !== undefined && input.schemaVersion !== 0) {
    throw new GovernanceConfigError(
      `unsupported governance configuration schemaVersion ${String(input.schemaVersion)}`,
    );
  }
  rejectUnknownKeys(input, [
    "schemaVersion", "version", "maxFileSize", "maxIssues", "detectors", "includeModels",
  ], "configuration");

  const limits: Partial<GovernanceAnalysisLimits> = {};
  if (input.maxFileSize !== undefined) {
    limits.maxSourceBytes = positiveInteger(input.maxFileSize, "maxFileSize");
  }
  if (input.maxIssues !== undefined) {
    limits.maxFindings = positiveInteger(input.maxIssues, "maxIssues");
  }
  const includeRules = input.detectors === undefined
    ? undefined
    : validateRules(input.detectors, "detectors");
  const migrated = input.version === 0 || input.maxFileSize !== undefined ||
    input.maxIssues !== undefined || input.detectors !== undefined;
  const diagnostics: GovernanceDiagnostic[] = migrated ? [{
    code: "GOV_CONFIG_INVALID",
    severity: "info",
    message: "Migrated governance configuration from legacy schema v0 to v1",
  }] : [];

  const config: GovernanceAnalysisConfigV1 = {
    schemaVersion: GOVERNANCE_CONFIG_SCHEMA_VERSION,
    ...(Object.keys(limits).length ? { limits } : {}),
    ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
    ...(includeRules ? { includeRules } : {}),
  };
  resolveGovernanceLimits(config.limits);
  return { config, diagnostics };
}

export function validateGovernanceConfig(
  input: GovernanceAnalysisConfigInput,
): ValidatedGovernanceConfig {
  return migrateGovernanceConfig(input);
}

export function loadGovernanceConfigFile(filePath: string): ValidatedGovernanceConfig {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new GovernanceConfigError(`configuration file could not be read (${errorCode(error)})`);
  }
  try {
    return validateGovernanceConfig(JSON.parse(content) as GovernanceAnalysisConfigInput);
  } catch (error) {
    if (error instanceof GovernanceConfigError) throw error;
    throw new GovernanceConfigError("configuration file contains invalid JSON");
  }
}

function validateV1(input: Record<string, unknown>): ValidatedGovernanceConfig {
  rejectUnknownKeys(input, [
    "schemaVersion", "limits", "includeModels", "includeRules", "excludeRules",
  ], "configuration");
  if (input.includeModels !== undefined && typeof input.includeModels !== "boolean") {
    throw new GovernanceConfigError("includeModels must be a boolean");
  }
  const limits = input.limits === undefined ? undefined : validateLimits(input.limits);
  const includeRules = input.includeRules === undefined
    ? undefined
    : validateRules(input.includeRules, "includeRules");
  const excludeRules = input.excludeRules === undefined
    ? undefined
    : validateRules(input.excludeRules, "excludeRules");
  if (includeRules && excludeRules) {
    const overlap = includeRules.filter((rule) => excludeRules.includes(rule));
    if (overlap.length) {
      throw new GovernanceConfigError(`includeRules and excludeRules overlap: ${overlap.join(", ")}`);
    }
  }
  return {
    config: {
      schemaVersion: GOVERNANCE_CONFIG_SCHEMA_VERSION,
      ...(limits ? { limits } : {}),
      ...(typeof input.includeModels === "boolean" ? { includeModels: input.includeModels } : {}),
      ...(includeRules ? { includeRules } : {}),
      ...(excludeRules ? { excludeRules } : {}),
    },
    diagnostics: [],
  };
}

function validateLimits(value: unknown): Partial<GovernanceAnalysisLimits> {
  if (!isRecord(value)) throw new GovernanceConfigError("limits must be an object");
  rejectUnknownKeys(value, LIMIT_KEYS, "limits");
  const limits: Partial<GovernanceAnalysisLimits> = {};
  for (const key of LIMIT_KEYS) {
    if (value[key] !== undefined) limits[key] = positiveInteger(value[key], key);
  }
  resolveGovernanceLimits(limits);
  return limits;
}

function validateRules(value: unknown, field: string): GovernanceRuleId[] {
  if (!Array.isArray(value)) throw new GovernanceConfigError(`${field} must be an array`);
  const result = new Set<GovernanceRuleId>();
  for (const rule of value) {
    if (typeof rule !== "string" || !RULE_IDS.has(rule)) {
      throw new GovernanceConfigError(`${field} contains unknown rule ${String(rule)}`);
    }
    result.add(rule as GovernanceRuleId);
  }
  return [...result].sort();
}

function positiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new GovernanceConfigError(`${field} must be a positive safe integer`);
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

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: readonly (string | number | symbol)[],
  field: string,
): void {
  const permitted = new Set(allowed.map(String));
  const unknown = Object.keys(value).filter((key) => !permitted.has(key)).sort();
  if (unknown.length) throw new GovernanceConfigError(`${field} contains unknown field ${unknown[0]}`);
}
