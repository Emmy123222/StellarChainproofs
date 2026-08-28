import * as fs from "fs";
import * as path from "path";
import { parseSolidity } from "./ast/parser";
import {
  buildImportGraph,
  buildMergedContractViews,
  computeRescanSet,
  hasImportDirectives,
  type ImportGraph,
  type MergedContractView,
} from "./ast/import-graph";
import { getCacheStats, resetCacheStats } from "./ast/cache";
import { runSlither, isSlitherAvailable, mergeSlitherFindings } from "./ast/slither";
import { detectReentrancy } from "./rules/swc107-reentrancy";
import { detectCrossFunctionReentrancy } from "./rules/swc107-reentrancy-v2";
import { detectTxOrigin } from "./rules/swc115-tx-origin";
import { detectUnprotectedUpgrade } from "./rules/swc116-unprotected-upgrade";
import { detectFrontRunningMev } from "./rules/cp119-frontrunning";
import {
  detectIntegerOverflow,
  detectUncheckedReturn,
} from "./rules/swc101-overflow";
import {
  detectERCStandard,
  checkERC20Compliance,
  checkERC721Compliance,
  checkERC1155Compliance,
} from "./rules/erc-compliance";
import { detectVaultInflation } from "./rules/cp122-vault-inflation";
import { detectCallbackReentrancy } from "./rules/callback-analysis";
import { detectStakingAccounting } from "./staking";
import { RuleOptions } from "./rules/rule-context";
import { detectGasIssues } from "./rules/gas-optimizer";
import { enhanceFindingsWithLLM } from "./llm/enhancer";
import { analyzeContract } from "./metrics/complexity";
import type {
  ScanConfig,
  ScanResult,
  FileScanResult,
  Finding,
  Severity,
  ContractMetrics,
  ASTNode,
} from "./types";

const VERSION = "0.1.0";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  gas: 0,
};

function collectSolFiles(targets: string[]): string[] {
  const files: string[] = [];
  for (const target of targets) {
    if (!fs.existsSync(target)) continue;
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      const entries = fs.readdirSync(target, { recursive: true } as {
        recursive: boolean;
      }) as string[];
      entries
        .filter((e) => e.endsWith(".sol"))
        .forEach((e) => files.push(path.join(target, e)));
    } else if (target.endsWith(".sol")) {
      files.push(target);
    }
  }
  return [...new Set(files)];
}

function runERCChecks(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions
): Finding[] {
  const standard = detectERCStandard(ast);
  if (!standard) return [];
  if (standard === "ERC20") return checkERC20Compliance(ast, source, filePath, options);
  if (standard === "ERC721") return checkERC721Compliance(ast, source, filePath, options);
  if (standard === "ERC1155") return checkERC1155Compliance(ast, source, filePath, options);
  return [];
}

function runRulesOnView(
  view: ReturnType<typeof buildMergedContractViews>[number],
  config: ScanConfig
): Finding[] {
  const ruleOptions = { contractView: view };
  return [
    ...detectReentrancy(view.node, view.source, view.file, ruleOptions),
    ...detectCrossFunctionReentrancy(view.node, view.source, view.file, ruleOptions),
    ...detectTxOrigin(view.node, view.source, view.file, ruleOptions),
    ...detectUnprotectedUpgrade(view.node, view.source, view.file, ruleOptions),
    ...detectIntegerOverflow(view.node, view.source, view.file),
    ...detectUncheckedReturn(view.node, view.source, view.file),
    ...runERCChecks(view.node, view.source, view.file, ruleOptions),
    ...detectVaultInflation(view.node, view.source, view.file, ruleOptions),
    ...detectCallbackReentrancy(view.node, view.source, view.file, ruleOptions),
  ];
}

function runRulesOnFile(
  ast: NonNullable<ReturnType<typeof parseSolidity>["ast"]>,
  source: string,
  filePath: string
): Finding[] {
  return [
    ...detectReentrancy(ast, source, filePath),
    ...detectTxOrigin(ast, source, filePath),
    ...detectUnprotectedUpgrade(ast, source, filePath),
    ...detectFrontRunningMev(ast, source, filePath),
    ...detectIntegerOverflow(ast, source, filePath),
    ...detectUncheckedReturn(ast, source, filePath),
    ...runERCChecks(ast, source, filePath),
    ...detectVaultInflation(ast, source, filePath),
  ];
}

async function scanFile(
  filePath: string,
  config: ScanConfig,
  graph?: ImportGraph,
  contractViews?: MergedContractView[]
): Promise<FileScanResult> {
  // Reuse the AST already parsed while building the shared import graph
  // rather than re-reading and re-parsing the file from disk.
  const parsedFile = graph?.files.get(path.resolve(filePath));

  let source: string;
  let ast: ReturnType<typeof parseSolidity>["ast"];
  let error: string | undefined;

  if (parsedFile) {
    source = parsedFile.source;
    ast = parsedFile.ast;
  } else {
    try {
      source = fs.readFileSync(filePath, "utf-8");
    } catch (e) {
      return {
        file: filePath,
        findings: [],
        gasHints: [],
        slitherRan: false,
        parseError: `Could not read file: ${e}`,
      };
    }

    ({ ast, error } = parseSolidity(source, filePath));
  }

  if (!ast) {
    return {
      file: filePath,
      findings: [],
      gasHints: [],
      slitherRan: false,
      parseError: error,
    };
  }

  let findings: Finding[] =
    contractViews && contractViews.length > 0
      ? [
          ...contractViews.flatMap((view) => runRulesOnView(view, config)),
          ...detectIntegerOverflow(ast, source, filePath),
          ...detectUncheckedReturn(ast, source, filePath),
        ]
      : runRulesOnFile(ast, source, filePath);

  // Staking accounting is intentionally evaluated once per physical source
  // file. Its model already separates contracts, so running it per merged
  // inheritance view would duplicate evidence and findings.
  findings.push(...detectStakingAccounting(ast, source, filePath));

  if (config.plugins) {
    for (const plugin of config.plugins) {
      for (const rule of plugin.rules) {
        try {
          findings.push(...rule.detect(ast, source, filePath));
        } catch (pluginError) {
          console.warn(
            `[ChainProof] Plugin "${plugin.name}" rule "${rule.id}" failed: ${
              pluginError instanceof Error ? pluginError.message : String(pluginError)
            }`
          );
        }
      }
    }
  }

  const gasHints = detectGasIssues(ast, source, filePath);

  const slitherRan = config.useSlither && isSlitherAvailable();
  if (slitherRan) {
    const slitherFindings = runSlither(filePath, config.slither?.detectors);
    findings = mergeSlitherFindings(findings, slitherFindings);
  }

  if (config.minSeverity) {
    const minRank = SEVERITY_RANK[config.minSeverity];
    findings = findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank);
  }

  if (config.useLLM && config.apiKey && findings.length > 0) {
    findings = await enhanceFindingsWithLLM(findings, source, config);
  }

  return { file: filePath, findings, gasHints, slitherRan };
}

function generateComplexityFindings(
  metrics: ContractMetrics[],
  source: string,
  filePath: string
): Finding[] {
  const findings: Finding[] = [];

  for (const m of metrics) {
    for (const fn of m.highComplexityFunctions) {
      const lines = source.split("\n");
      let line = 0;
      for (let i = 0; i < lines.length; i++) {
        if (
          lines[i].includes(`function ${fn.name}`) ||
          lines[i].includes(`function ${fn.name}(`)
        ) {
          line = i + 1;
          break;
        }
      }

      findings.push({
        id: "CP-METRICS-CC",
        title: `High cyclomatic complexity in ${fn.name}`,
        description:
          `Function "${fn.name}" has a cyclomatic complexity of ${fn.cc} (>10). ` +
          `High complexity makes code harder to audit and more prone to hidden vulnerabilities. ` +
          `Consider breaking this function into smaller, focused sub-functions.`,
        recommendation:
          `Refactor "${fn.name}" to reduce cyclomatic complexity below 10. ` +
          `Extract nested conditionals into named helper functions with clear contracts.`,
        severity: "info",
        file: filePath,
        line,
      });
    }
  }

  return findings;
}

function computeMetricsForFile(filePath: string): ContractMetrics[] {
  const source = fs.readFileSync(filePath, "utf-8");
  const { ast } = parseSolidity(source, filePath);
  if (!ast) return [];

  const analysisResults = analyzeContract(ast, source, filePath);

  return analysisResults.map((ar) => ({
    contract: ar.contractName,
    file: ar.filePath,
    linesOfCode: ar.linesOfCode,
    functionCount: ar.totalFunctions,
    inheritanceDepth: ar.inheritanceDepth,
    avgCyclomaticComplexity:
      ar.functionMetrics.length > 0
        ? Math.round(
            (ar.functionMetrics.reduce(
              (sum, fm) => sum + fm.cyclomaticComplexity,
              0
            ) /
              ar.functionMetrics.length) *
              100
          ) / 100
        : 0,
    highComplexityFunctions: ar.highComplexityFunctions,
    externalCallsPerFunction: ar.externalCallsPerFunction,
    stateVariableCount: ar.stateVariableCount,
    visibilityDistribution: ar.visibilityDistribution,
    riskScore: ar.riskScore,
  }));
}

/**
 * Scans one or more Solidity files or directories for security vulnerabilities,
 * gas inefficiencies, and bad patterns.
 *
 * Automatically follows and expands local import graphs so inherited
 * vulnerabilities from base contracts are detected in context.
 *
 * @param config - Scan configuration specifying targets, feature flags, and output options
 * @returns A {@link ScanResult} containing per-file findings and an aggregate summary
 *
 * @example
 * ```typescript
 * const result = await scan({ targets: ['contracts/'], useSlither: false, useLLM: false, useMetrics: false });
 * console.log(result.summary.critical); // number of critical findings
 * ```
 *
 * @example With LLM enhancement
 * ```typescript
 * const result = await scan({
 *   targets: ['contracts/Vault.sol'],
 *   useSlither: true,
 *   useLLM: true,
 *   useMetrics: true,
 *   apiKey: process.env.ANTHROPIC_API_KEY,
 * });
 * ```
 */
export async function scan(config: ScanConfig): Promise<ScanResult> {
  const files = collectSolFiles(config.targets);
  const graph = files.length > 0 ? buildImportGraph(files) : undefined;
  const viewsByFile = new Map<string, MergedContractView[]>();

  if (graph && hasImportDirectives(graph)) {
    for (const view of buildMergedContractViews(graph)) {
      const views = viewsByFile.get(view.file) ?? [];
      views.push(view);
      viewsByFile.set(view.file, views);
    }
  }

  const fileResults = await Promise.all(
    files.map((f) => scanFile(f, config, graph, viewsByFile.get(path.resolve(f))))
  );

  let allMetrics: ContractMetrics[] = [];
  const complexityFindings: Finding[] = [];

  if (config.useMetrics) {
    for (const filePath of files) {
      const metrics = computeMetricsForFile(filePath);
      allMetrics.push(...metrics);

      if (metrics.length > 0) {
        try {
          const source = fs.readFileSync(filePath, "utf-8");
          complexityFindings.push(
            ...generateComplexityFindings(metrics, source, filePath)
          );
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  if (complexityFindings.length > 0 && fileResults.length > 0) {
    const targetFile = fileResults.find((f) => !f.parseError);
    if (targetFile) {
      targetFile.findings.push(...complexityFindings);
    }
  }

  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    gas: 0,
    total: 0,
  };

  for (const r of fileResults) {
    for (const f of r.findings) {
      summary[f.severity]++;
      summary.total++;
    }
    summary.gas += r.gasHints.length;
    summary.total += r.gasHints.length;
  }

  return {
    version: VERSION,
    timestamp: new Date().toISOString(),
    files: fileResults,
    summary,
    metrics: allMetrics.length > 0 ? allMetrics : undefined,
  };
}

export interface WatchScanState {
  allFiles: string[];
  result: ScanResult;
}

export interface IncrementalScanOutcome {
  state: WatchScanState;
  rescannedFiles: string[];
  cacheStats: ReturnType<typeof getCacheStats>;
}

function buildViewsByFile(graph: ImportGraph): Map<string, MergedContractView[]> {
  const viewsByFile = new Map<string, MergedContractView[]>();
  if (!hasImportDirectives(graph)) {
    return viewsByFile;
  }

  for (const view of buildMergedContractViews(graph)) {
    const views = viewsByFile.get(view.file) ?? [];
    views.push(view);
    viewsByFile.set(view.file, views);
  }

  return viewsByFile;
}

function computeSummary(fileResults: FileScanResult[]): ScanResult["summary"] {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    gas: 0,
    total: 0,
  };

  for (const r of fileResults) {
    for (const f of r.findings) {
      summary[f.severity]++;
      summary.total++;
    }
    summary.gas += r.gasHints.length;
    summary.total += r.gasHints.length;
  }

  return summary;
}

/**
 * Run an initial full scan and retain state for incremental watch re-scans.
 */
export async function createWatchScanState(config: ScanConfig): Promise<WatchScanState> {
  const result = await scan(config);
  return {
    allFiles: collectSolFiles(config.targets),
    result,
  };
}

/**
 * Re-scan only files affected by a change (changed file + import graph neighbors),
 * merging results into the previous watch state. Unchanged files reuse cached ASTs.
 */
export async function scanIncremental(
  config: ScanConfig,
  state: WatchScanState,
  changedFiles: string[]
): Promise<IncrementalScanOutcome> {
  resetCacheStats();

  const graph = buildImportGraph(state.allFiles);
  const rescanSet = computeRescanSet(changedFiles, graph);
  const viewsByFile = buildViewsByFile(graph);

  const rescannedFiles = [...rescanSet].filter((f) =>
    state.allFiles.some((known) => path.resolve(known) === f)
  );

  const newFileResults = await Promise.all(
    rescannedFiles.map((f) =>
      scanFile(f, config, graph, viewsByFile.get(path.resolve(f)))
    )
  );

  const fileMap = new Map(
    state.result.files.map((f) => [path.resolve(f.file), f])
  );
  for (const fileResult of newFileResults) {
    fileMap.set(path.resolve(fileResult.file), fileResult);
  }

  const mergedFiles = state.allFiles.map(
    (f) => fileMap.get(path.resolve(f))!
  );

  let allMetrics = state.result.metrics ? [...state.result.metrics] : [];
  const complexityFindings: Finding[] = [];

  if (config.useMetrics) {
    const rescannedAbs = new Set(rescannedFiles.map((f) => path.resolve(f)));
    allMetrics = allMetrics.filter((m) => !rescannedAbs.has(path.resolve(m.file)));

    for (const filePath of rescannedFiles) {
      const metrics = computeMetricsForFile(filePath);
      allMetrics.push(...metrics);

      if (metrics.length > 0) {
        try {
          const source = fs.readFileSync(filePath, "utf-8");
          complexityFindings.push(
            ...generateComplexityFindings(metrics, source, filePath)
          );
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  if (complexityFindings.length > 0) {
    for (const filePath of rescannedFiles) {
      const target = fileMap.get(path.resolve(filePath));
      if (target && !target.parseError) {
        target.findings = target.findings.filter((f) => f.id !== "CP-METRICS-CC");
        const fileComplexity = complexityFindings.filter(
          (f) => path.resolve(f.file) === path.resolve(filePath)
        );
        target.findings.push(...fileComplexity);
      }
    }
  }

  const result: ScanResult = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    files: mergedFiles,
    summary: computeSummary(mergedFiles),
    metrics: allMetrics.length > 0 ? allMetrics : undefined,
  };

  return {
    state: { allFiles: state.allFiles, result },
    rescannedFiles,
    cacheStats: getCacheStats(),
  };
}

export { collectSolFiles };
