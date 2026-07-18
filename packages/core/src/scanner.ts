import * as fs from "fs";
import * as path from "path";
import { parseSolidity } from "./ast/parser";
import {
  buildImportGraph,
  buildMergedContractViews,
  hasImportDirectives,
  type ImportGraph,
  type MergedContractView,
} from "./ast/import-graph";
import { runSlither, isSlitherAvailable, mergeSlitherFindings } from "./ast/slither";
import { detectReentrancy } from "./rules/swc107-reentrancy";
import { detectCrossFunctionReentrancy } from "./rules/swc107-reentrancy-v2";
import { detectTxOrigin } from "./rules/swc115-tx-origin";
import { detectUnprotectedUpgrade } from "./rules/swc116-unprotected-upgrade";
import {
  detectIntegerOverflow,
  detectUncheckedReturn,
} from "./rules/swc101-overflow";
import { detectGasIssues } from "./rules/gas-optimizer";
import { enhanceFindingsWithLLM } from "./llm/enhancer";
import { loadPlugins } from "./plugins";
import { analyzeContract } from "./metrics/complexity";
import type {
  ScanConfig,
  ScanResult,
  FileScanResult,
  Finding,
  Severity,
  ContractMetrics,
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
    ...detectIntegerOverflow(ast, source, filePath),
    ...detectUncheckedReturn(ast, source, filePath),
  ];
}

async function scanFile(
  filePath: string,
  config: ScanConfig,
  graph: ImportGraph | null,
  views: MergedContractView[],
): Promise<FileScanResult> {
  // Reuse the AST already parsed while building the shared import graph
  // rather than re-reading and re-parsing the file from disk.
  const parsedFile = graph?.files.get(filePath);

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

  // ── AST-based rules ────────────────────────────────────────────────────────
  // Merged contract views catch vulnerabilities inherited from base contracts
  // via local imports; single-file contracts use the cheaper legacy path.
  let findings: Finding[] =
    views.length > 0
      ? [
          ...views.flatMap((view) => runRulesOnView(view, config)),
          ...detectIntegerOverflow(ast, source, filePath),
          ...detectUncheckedReturn(ast, source, filePath),
        ]
      : runRulesOnFile(ast, source, filePath);

  // ── Plugin rules ───────────────────────────────────────────────────────────
  if (config.plugins) {
    for (const plugin of config.plugins) {
      for (const rule of plugin.rules) {
        try {
          findings.push(...rule.detect(ast, source, filePath));
        } catch (error) {
          console.warn(
            `[ChainProof] Plugin "${plugin.name}" rule "${rule.id}" failed: ${
              error instanceof Error ? error.message : String(error)
            }`,
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

/**
 * Extract high-complexity functions as info-severity findings.
 */
function generateComplexityFindings(
  metrics: ContractMetrics[],
  source: string,
  filePath: string
): Finding[] {
  const findings: Finding[] = [];

  for (const m of metrics) {
    for (const fn of m.highComplexityFunctions) {
      // Find approximate line in source for the function name
      const lines = source.split("\n");
      let line = 0;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(`function ${fn.name}`) || 
            lines[i].includes(`function ${fn.name}(`)) {
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

/**
 * Generate ContractMetrics for a file's parsed AST.
 */
function computeMetricsForFile(
  filePath: string
): ContractMetrics[] {
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
            (ar.functionMetrics.reduce((sum, fm) => sum + fm.cyclomaticComplexity, 0) /
              ar.functionMetrics.length) * 100
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
  const initialFiles = collectSolFiles(config.targets).map((f) => path.resolve(f));
  const graph = initialFiles.length > 0 ? buildImportGraph(initialFiles) : null;

  // Union targeted files with everything the graph discovered (locally
  // resolvable imports) so unparseable targets still surface a parseError
  // instead of silently vanishing from the results.
  const files = graph
    ? [...new Set([...initialFiles, ...graph.files.keys()])]
    : initialFiles;

  const views =
    graph && hasImportDirectives(graph) ? buildMergedContractViews(graph) : [];

  const fileResults = await Promise.all(
    files.map((f) =>
      scanFile(f, config, graph, views.filter((v) => v.file === f)),
    ),
  );

  const allMetrics: ContractMetrics[] = config.useMetrics
    ? files.flatMap((f) => computeMetricsForFile(f))
    : [];

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
