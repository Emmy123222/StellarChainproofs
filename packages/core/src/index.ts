/**
 * @packageDocumentation
 * @chainproof/core — Public API
 *
 * The core scanning engine that powers all ChainProof interfaces.
 * All exports from this module are considered stable public API unless
 * explicitly marked `@internal`.
 *
 * @example
 * ```typescript
 * import { scan, generateMarkdownReport } from '@chainproof/core';
 *
 * const result = await scan({ targets: ['contracts/'], useSlither: false, useLLM: false, useMetrics: false });
 * console.log(result.summary.critical);
 * console.log(generateMarkdownReport(result));
 * ```
 */

// ─── Public stable exports ────────────────────────────────────────────────────

export { scan } from "./scanner";
export { clearCache, astCache } from "./ast/cache";
export type { ASTCacheEntry } from "./ast/cache";
export {
  generateMarkdownReport,
  generateJSONReport,
  generateTableReport,
} from "./report/generator";
export { isSlitherAvailable } from "./ast/slither";
export { loadPlugin, loadPlugins } from "./plugins";
export {
  loadConfigFile,
  mergePluginsFromConfig,
  mergeSlitherConfigFromConfig,
} from "./config";
export type { ChainProofConfig } from "./config";

// ─── Public types ─────────────────────────────────────────────────────────────

export type {
  ScanConfig,
  ScanResult,
  FileScanResult,
  Finding,
  GasHint,
  Severity,
  ChainProofPlugin,
  PluginRule,
  ASTNode,
  ContractMetrics,
  HighComplexityFunction,
  SlitherConfig,
  SlitherDetectorConfig,
} from "./types";

export type {
  ImportGraph,
  ParsedSolidityFile,
  ContractInfo,
  MergedMember,
  MergedContractView,
} from "./ast/import-graph";
