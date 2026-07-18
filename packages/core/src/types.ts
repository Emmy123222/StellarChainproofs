// ─── Severity Levels ──────────────────────────────────────────────────────────

/**
 * Severity level of a detected finding.
 *
 * Ordered from most to least severe:
 * `critical` > `high` > `medium` > `low` > `info` > `gas`
 */
export type Severity = "critical" | "high" | "medium" | "low" | "info" | "gas";

// ─── A single detected issue ──────────────────────────────────────────────────

/**
 * A single security, quality, or gas finding detected in a Solidity file.
 */
export interface Finding {
  /** Unique rule ID e.g. "SWC-107" */
  id: string;
  /** Short human-readable title */
  title: string;
  /** Full explanation of the vulnerability */
  description: string;
  /** Suggested fix */
  recommendation: string;
  severity: Severity;
  /** Source file path */
  file: string;
  /** 1-indexed line numbers */
  line: number;
  lineEnd?: number;
  /** The raw source snippet */
  snippet?: string;
  /** SWC registry reference if applicable */
  swcId?: string;
  /** Whether this was enhanced/explained by LLM */
  llmEnhanced?: boolean;
  /** File where the vulnerable code is defined */
  definedIn?: string;
  /** File of the contract that inherits the issue */
  inheritedBy?: string;
  /** Resolved import chain from inheriting file to definition file */
  importPath?: string[];
}

// ─── Gas optimization hint ────────────────────────────────────────────────────

/**
 * A gas optimization suggestion for a specific line in a Solidity file.
 */
export interface GasHint {
  file: string;
  line: number;
  description: string;
  estimatedSaving: string;
  snippet?: string;
}

// ─── Scan result for a single file ───────────────────────────────────────────

/**
 * Scan findings and metadata for a single Solidity file.
 */
export interface FileScanResult {
  file: string;
  findings: Finding[];
  gasHints: GasHint[];
  /** true if Slither was available and ran */
  slitherRan: boolean;
  parseError?: string;
}

// ─── Complexity / Maintainability Metrics ──────────────────────────────────────

/**
 * Describes a function with cyclomatic complexity above the threshold (>10).
 */
export interface HighComplexityFunction {
  name: string;
  cc: number;
}

/**
 * Complexity and maintainability metrics for a single contract.
 *
 * Produced when {@link ScanConfig.useMetrics} is `true`.
 */
export interface ContractMetrics {
  contract: string;
  file: string;
  linesOfCode: number;
  functionCount: number;
  inheritanceDepth: number;
  avgCyclomaticComplexity: number;
  highComplexityFunctions: Array<{ name: string; cc: number }>;
  externalCallsPerFunction: Record<string, number>;
  stateVariableCount: number;
  visibilityDistribution: Record<string, number>;
  riskScore: number; // 0-100 composite
}

// ─── Full scan result for a project ──────────────────────────────────────────

/**
 * The complete result of a {@link scan} call.
 *
 * Contains per-file findings, an aggregate summary, and optional metrics.
 */
export interface ScanResult {
  version: string;
  timestamp: string;
  files: FileScanResult[];
  /** Aggregated counts */
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    gas: number;
    total: number;
  };
  /** Complexity and maintainability metrics per contract */
  metrics?: ContractMetrics[];
}

// ─── Plugin API ──────────────────────────────────────────────────────────────

/**
 * Opaque AST node from `@solidity-parser/parser`.
 *
 * Used as the input type for plugin `detect` functions and internal AST visitors.
 */
export type ASTNode = any; // From @solidity-parser/parser

/**
 * A single rule contributed by a {@link ChainProofPlugin}.
 *
 * @example
 * ```typescript
 * const myRule: PluginRule = {
 *   id: 'MYTEAM-001',
 *   title: 'Unsafe delegatecall',
 *   severity: 'high',
 *   description: 'delegatecall to user-controlled address.',
 *   recommendation: 'Validate the callee address against an allowlist.',
 *   detect(ast, source, filePath) {
 *     // return Finding[] based on AST analysis
 *     return [];
 *   },
 * };
 * ```
 */
export interface PluginRule {
  /** Unique rule ID e.g. "MYTEAM-001" */
  id: string;
  /** Short human-readable title */
  title: string;
  severity: Severity;
  /** Full explanation of the vulnerability */
  description: string;
  /** Suggested fix */
  recommendation?: string;
  /** Detection function */
  detect: (ast: ASTNode, source: string, filePath: string) => Finding[];
}

/**
 * A ChainProof plugin that contributes one or more custom detection rules.
 *
 * Plugins can be loaded from npm packages or local files via {@link loadPlugin}
 * and {@link loadPlugins}, then passed to {@link scan} via {@link ScanConfig.plugins}.
 *
 * @example
 * ```typescript
 * const plugin: ChainProofPlugin = {
 *   name: 'my-team-rules',
 *   version: '1.0.0',
 *   rules: [myRule],
 * };
 * ```
 */
export interface ChainProofPlugin {
  name: string;
  version: string;
  rules: PluginRule[];
}

// ─── Scanner config ───────────────────────────────────────────────────────────

/**
 * Configuration for a {@link scan} call.
 *
 * @example Minimal scan
 * ```typescript
 * const config: ScanConfig = {
 *   targets: ['contracts/'],
 *   useSlither: false,
 *   useLLM: false,
 *   useMetrics: false,
 * };
 * ```
 *
 * @example Full scan with all features
 * ```typescript
 * const config: ScanConfig = {
 *   targets: ['contracts/'],
 *   useSlither: true,
 *   useLLM: true,
 *   useMetrics: true,
 *   apiKey: process.env.ANTHROPIC_API_KEY,
 *   minSeverity: 'medium',
 *   outputFormat: 'markdown',
 * };
 * ```
 */
export interface ScanConfig {
  /** Paths to .sol files or directories */
  targets: string[];
  /** Run Slither if installed */
  useSlither: boolean;
  /** Send findings to LLM for explanation */
  useLLM: boolean;
  /** Compute complexity metrics */
  useMetrics: boolean;
  /** Anthropic API key */
  apiKey?: string;

  /**
   * Select LLM provider (e.g. "anthropic", "openai"). Defaults to "anthropic".
   */
  llmProvider?: string;
  /** Provider/model identifier (provider-specific). */
  llmModel?: string;
  /** Provider API key (alternative to apiKey). */
  llmApiKey?: string;

  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Output format */
  outputFormat?: "json" | "markdown" | "table";
  /** Array of plugins to load */
  plugins?: ChainProofPlugin[];
}

