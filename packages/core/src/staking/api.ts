import * as fs from "fs";
import * as path from "path";
import { buildStakingModels } from "./model";
import { analyzeStakingModel } from "./analyzer";
import { resolveStakingLimits, StakingAnalysisCancelledError } from "./config";
import type {
  StakingAnalysisOptions,
  StakingAnalysisReport,
  StakingDiagnostic,
  StakingFileAnalysis,
  StakingFinding,
  StakingSourceInput,
} from "./types";

const ENGINE_VERSION = "0.1.0";

/** Analyze one in-memory Solidity source without filesystem or network access. */
export function analyzeStakingSource(
  input: StakingSourceInput,
  options: StakingAnalysisOptions = {},
): StakingAnalysisReport {
  return analyzeStakingSources([input], options);
}

/**
 * Analyze an in-memory project deterministically.
 * Files, findings, evidence, and diagnostics are sorted independently of input order.
 */
export function analyzeStakingSources(
  inputs: StakingSourceInput[],
  options: StakingAnalysisOptions = {},
): StakingAnalysisReport {
  const limits = resolveStakingLimits(options.limits);
  checkCancelled(options);

  const normalized = normalizeInputs(inputs);
  const limited = normalized.slice(0, limits.maxFiles);
  const files: StakingFileAnalysis[] = [];
  let contracts = 0;
  let truncated = normalized.length > limited.length;
  let findingBudget = limits.maxFindings;
  let contractBudget = limits.maxContracts;

  for (const input of limited) {
    checkCancelled(options);
    if (contractBudget === 0) {
      truncated = true;
      files.push({
        file: input.file,
        findings: [],
        diagnostics: [{
          code: "STK_CONTRACT_LIMIT",
          severity: "warning",
          message: `The project-level ${limits.maxContracts}-contract limit was reached`,
          location: { file: input.file, line: 1, column: 1 },
        }],
      });
      continue;
    }
    const built = buildStakingModels(
      input.source,
      input.file,
      { ...limits, maxContracts: contractBudget },
      options.signal,
    );
    contracts += built.models.length;
    contractBudget -= built.models.length;
    if (built.diagnostics.some((diagnostic) => diagnostic.code.endsWith("_LIMIT"))) {
      truncated = true;
    }
    if (built.diagnostics.some((diagnostic) => diagnostic.code === "STK_CONTRACT_LIMIT")) {
      truncated = true;
      contractBudget = 0;
    }
    const candidateFindings = built.models.flatMap((model) => analyzeStakingModel(model, options));
    const accepted = candidateFindings.slice(0, findingBudget).map((finding) => ({
      ...finding,
      evidence: finding.evidence.slice(0, limits.maxEvidencePerFinding),
    }));
    if (accepted.length < candidateFindings.length) truncated = true;
    findingBudget -= accepted.length;

    files.push({
      file: input.file,
      findings: accepted.sort(compareFindings),
      diagnostics: built.diagnostics.sort(compareDiagnostics),
      ...(options.includeModels ? { models: built.models } : {}),
    });
  }

  if (normalized.length > limited.length) {
    files.push({
      file: "<analysis>",
      findings: [],
      diagnostics: [{
        code: "STK_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} files were analyzed`,
      }],
    });
  }

  return buildReport(files, contracts, truncated);
}

/** Read and analyze Solidity files. File failures become structured diagnostics. */
export function analyzeStakingFiles(
  filePaths: string[],
  options: StakingAnalysisOptions = {},
): StakingAnalysisReport {
  const limits = resolveStakingLimits(options.limits);
  const uniquePaths = [...new Set(filePaths)].sort((left, right) => left.localeCompare(right));
  const readable: StakingSourceInput[] = [];
  const failures: StakingFileAnalysis[] = [];

  for (const filePath of uniquePaths.slice(0, limits.maxFiles)) {
    checkCancelled(options);
    try {
      readable.push({ file: filePath, source: fs.readFileSync(filePath, "utf8") });
    } catch (error) {
      failures.push({
        file: filePath,
        findings: [],
        diagnostics: [{
          code: "STK_FILE_UNREADABLE",
          severity: "error",
          message: `Solidity target could not be read (${errorCode(error)})`,
          location: { file: filePath, line: 1, column: 1 },
        }],
      });
    }
  }

  const report = analyzeStakingSources(readable, {
    ...options,
    limits: { ...limits, maxFiles: limits.maxFiles },
  });
  const files = [...report.files, ...failures].sort((left, right) => left.file.localeCompare(right.file));
  const skipped = uniquePaths.length > limits.maxFiles;
  if (skipped && !files.some((file) => file.file === "<analysis>")) {
    files.push({
      file: "<analysis>",
      findings: [],
      diagnostics: [{
        code: "STK_SOURCE_LIMIT",
        severity: "warning",
        message: `Only the first ${limits.maxFiles} files were analyzed`,
      }],
    });
  }
  return buildReport(files, report.summary.contracts, report.summary.truncated || skipped);
}

/** Recursively collect Solidity targets in lexical order without following symlinks. */
export function collectStakingSolidityFiles(
  targets: string[],
  maxFiles: number = resolveStakingLimits().maxFiles,
): string[] {
  const found = new Set<string>();
  const queue = [...targets].map((target) => path.resolve(target)).sort().reverse();
  while (queue.length > 0 && found.size < maxFiles) {
    const target = queue.pop()!;
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(target);
    } catch {
      if (target.endsWith(".sol")) found.add(target);
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isFile()) {
      if (target.endsWith(".sol")) found.add(target);
      continue;
    }
    if (!stat.isDirectory()) continue;
    const entries = fs.readdirSync(target, { withFileTypes: true })
      .filter((entry) => !entry.isSymbolicLink())
      .map((entry) => path.join(target, entry.name))
      .sort()
      .reverse();
    queue.push(...entries);
  }
  return [...found].sort();
}

/** Analyze Solidity files and directories through the public project API. */
export function analyzeStakingProject(
  targets: string[],
  options: StakingAnalysisOptions = {},
): StakingAnalysisReport {
  const limits = resolveStakingLimits(options.limits);
  const files = collectStakingSolidityFiles(targets, limits.maxFiles + 1);
  return analyzeStakingFiles(files, options);
}

function buildReport(
  files: StakingFileAnalysis[],
  contracts: number,
  truncated: boolean,
): StakingAnalysisReport {
  const summary: StakingAnalysisReport["summary"] = {
    files: files.filter((file) => file.file !== "<analysis>").length,
    contracts,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
    truncated,
  };
  for (const file of files) {
    file.findings.sort(compareFindings);
    file.diagnostics.sort(compareDiagnostics);
    for (const finding of file.findings) {
      summary[finding.severity] += 1;
      summary.total += 1;
    }
  }
  return {
    schemaVersion: "1.0.0",
    engineVersion: ENGINE_VERSION,
    files: files.sort((left, right) => left.file.localeCompare(right.file)),
    summary,
  };
}

function normalizeInputs(inputs: StakingSourceInput[]): StakingSourceInput[] {
  const sorted = [...inputs].sort((left, right) =>
    left.file.localeCompare(right.file) || left.source.localeCompare(right.source),
  );
  const seen = new Set<string>();
  const result: StakingSourceInput[] = [];
  for (const input of sorted) {
    if (seen.has(input.file)) continue;
    seen.add(input.file);
    result.push({ file: input.file, source: input.source });
  }
  return result;
}

function compareFindings(left: StakingFinding, right: StakingFinding): number {
  return left.location.line - right.location.line ||
    left.location.column - right.location.column ||
    left.ruleId.localeCompare(right.ruleId) ||
    left.title.localeCompare(right.title);
}

function compareDiagnostics(left: StakingDiagnostic, right: StakingDiagnostic): number {
  return (left.location?.line ?? 0) - (right.location?.line ?? 0) ||
    left.code.localeCompare(right.code) || left.message.localeCompare(right.message);
}

function checkCancelled(options: StakingAnalysisOptions): void {
  if (options.signal?.aborted) throw new StakingAnalysisCancelledError();
}

function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : "IO_ERROR";
}
