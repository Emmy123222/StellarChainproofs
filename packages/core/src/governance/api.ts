import * as fs from "fs";
import * as path from "path";
import { analyzeGovernanceModel } from "./analyzer";
import {
  GovernanceAnalysisCancelledError,
  resolveGovernanceLimits,
} from "./config";
import { buildGovernanceModels } from "./model";
import type {
  GovernanceAnalysisOptions,
  GovernanceAnalysisReport,
  GovernanceContractModel,
  GovernanceDiagnostic,
  GovernanceFileAnalysis,
  GovernanceFinding,
  GovernanceSourceInput,
} from "./types";

export const GOVERNANCE_ENGINE_VERSION = "0.1.0" as const;

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

/** Analyze a single in-memory Solidity source without filesystem or network access. */
export function analyzeGovernanceSource(
  source: string,
  file = "<memory>.sol",
  options: GovernanceAnalysisOptions = {},
): GovernanceAnalysisReport {
  return analyzeGovernanceSources([{ file, source }], options);
}

/** Analyze an explicitly supplied, deterministic set of Solidity sources. */
export function analyzeGovernanceSources(
  inputs: GovernanceSourceInput[],
  options: GovernanceAnalysisOptions = {},
): GovernanceAnalysisReport {
  const limits = resolveGovernanceLimits(options.limits);
  checkCancelled(options);
  const ordered = [...inputs]
    .map((input) => ({ file: input.file, source: input.source }))
    .sort((left, right) => left.file.localeCompare(right.file));
  const files: GovernanceFileAnalysis[] = [];
  let contractCount = 0;
  let findingsRemaining = limits.maxFindings;
  let truncated = ordered.length > limits.maxFiles;

  for (const input of ordered.slice(0, limits.maxFiles)) {
    checkCancelled(options);
    const built = buildGovernanceModels(input.source, input.file, limits, options.signal);
    contractCount += built.models.length;
    const findings: GovernanceFinding[] = [];
    for (const model of built.models) {
      checkCancelled(options);
      for (const finding of analyzeGovernanceModel(model, options)) {
        if (findingsRemaining === 0) {
          truncated = true;
          break;
        }
        findings.push({
          ...finding,
          evidence: finding.evidence.slice(0, limits.maxEvidencePerFinding),
        });
        findingsRemaining -= 1;
      }
      if (findingsRemaining === 0) break;
    }
    const diagnostics = [...built.diagnostics];
    if (findingsRemaining === 0) {
      diagnostics.push(limitDiagnostic(input.file, limits.maxFindings));
    }
    files.push({
      file: input.file,
      findings: findings.sort(compareFindings),
      diagnostics: diagnostics.sort(compareDiagnostics),
      ...(options.includeModels ? { models: built.models.map(sortModel) } : {}),
    });
  }

  if (ordered.length > limits.maxFiles) {
    files.push({
      file: "<project>",
      findings: [],
      diagnostics: [{
        code: "GOV_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} Solidity files were analyzed`,
      }],
    });
  }
  return report(files, truncated, contractCount);
}

/** Recursively collect Solidity files while avoiding symlink traversal. */
export function collectGovernanceSolidityFiles(targets: string[]): string[] {
  const result = new Set<string>();
  const pending = [...targets].map((target) => path.resolve(target)).sort().reverse();
  while (pending.length) {
    const candidate = pending.pop() as string;
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(candidate);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isFile()) {
      if (candidate.endsWith(".sol")) result.add(candidate);
      continue;
    }
    if (!stat.isDirectory()) continue;
    let entries: string[];
    try {
      entries = fs.readdirSync(candidate).sort();
    } catch {
      continue;
    }
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      pending.push(path.join(candidate, entries[index]));
    }
  }
  return [...result].sort();
}

/** Read and analyze Solidity files/directories with bounded IO and sanitized diagnostics. */
export function analyzeGovernanceFiles(
  targets: string[],
  options: GovernanceAnalysisOptions = {},
): GovernanceAnalysisReport {
  const limits = resolveGovernanceLimits(options.limits);
  checkCancelled(options);
  const discovered = collectGovernanceSolidityFiles(targets);
  const inputs: GovernanceSourceInput[] = [];
  const unreadable: GovernanceFileAnalysis[] = [];
  for (const target of [...new Set(targets.map((item) => path.resolve(item)))].sort()) {
    try {
      fs.lstatSync(target);
    } catch (error) {
      unreadable.push(unreadableFile(target, error));
    }
  }
  for (const file of discovered.slice(0, limits.maxFiles)) {
    checkCancelled(options);
    try {
      inputs.push({ file, source: fs.readFileSync(file, "utf8") });
    } catch (error) {
      unreadable.push(unreadableFile(file, error));
    }
  }
  const analysis = analyzeGovernanceSources(inputs, { ...options, limits });
  const files = [...analysis.files.filter((file) => file.file !== "<project>"), ...unreadable]
    .sort((left, right) => left.file.localeCompare(right.file));
  if (discovered.length > limits.maxFiles || analysis.files.some((file) => file.file === "<project>")) {
    files.push({
      file: "<project>",
      findings: [],
      diagnostics: [{
        code: "GOV_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} Solidity files were analyzed`,
      }],
    });
  }
  return report(
    files,
    analysis.summary.truncated || discovered.length > limits.maxFiles,
    analysis.summary.contracts,
  );
}

function report(
  files: GovernanceFileAnalysis[],
  truncated: boolean,
  contractCount: number,
): GovernanceAnalysisReport {
  const summary = {
    files: files.filter((file) => file.file !== "<project>").length,
    contracts: contractCount,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
    truncated,
  };
  for (const file of files) {
    for (const finding of file.findings) {
      summary[finding.severity] += 1;
      summary.total += 1;
    }
    if (file.diagnostics.some((diagnostic) =>
      diagnostic.code === "GOV_FINDING_LIMIT" || diagnostic.code.endsWith("_LIMIT"))) {
      summary.truncated = true;
    }
  }
  return {
    schemaVersion: "1.0.0",
    engineVersion: GOVERNANCE_ENGINE_VERSION,
    files,
    summary,
  };
}

function sortModel(model: GovernanceContractModel): GovernanceContractModel {
  return {
    ...model,
    stateVariables: [...model.stateVariables].sort((left, right) =>
      left.location.line - right.location.line || left.name.localeCompare(right.name)),
    transitions: [...model.transitions].sort((left, right) =>
      left.location.line - right.location.line || left.name.localeCompare(right.name)),
    privilegedCalls: [...model.privilegedCalls].sort((left, right) => left.order - right.order),
    proposalControlledCalls: [...model.proposalControlledCalls].sort((left, right) => left.order - right.order),
  };
}

function limitDiagnostic(file: string, limit: number): GovernanceDiagnostic {
  return {
    code: "GOV_FINDING_LIMIT",
    severity: "warning",
    message: `Finding output was limited to ${limit} records`,
    location: { file, line: 1, column: 1 },
  };
}

function compareFindings(left: GovernanceFinding, right: GovernanceFinding): number {
  return left.location.line - right.location.line || left.location.column - right.location.column ||
    left.ruleId.localeCompare(right.ruleId) || left.contract.localeCompare(right.contract);
}

function compareDiagnostics(left: GovernanceDiagnostic, right: GovernanceDiagnostic): number {
  return (left.location?.line ?? 0) - (right.location?.line ?? 0) ||
    left.code.localeCompare(right.code) || left.message.localeCompare(right.message);
}

function checkCancelled(options: GovernanceAnalysisOptions): void {
  if (options.signal?.aborted) throw new GovernanceAnalysisCancelledError();
}

function safeErrorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : "IO_ERROR";
}

function unreadableFile(file: string, error: unknown): GovernanceFileAnalysis {
  return {
    file,
    findings: [],
    diagnostics: [{
      code: "GOV_FILE_UNREADABLE",
      severity: "error",
      message: `Solidity target could not be read (${safeErrorCode(error)})`,
      location: { file, line: 1, column: 1 },
    }],
  };
}

export const GOVERNANCE_SEVERITY_ORDER = SEVERITIES;
