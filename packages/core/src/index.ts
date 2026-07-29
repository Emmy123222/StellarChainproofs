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

export { scan, createWatchScanState, scanIncremental, collectSolFiles } from "./scanner";
export type { WatchScanState, IncrementalScanOutcome } from "./scanner";
export { clearCache, astCache, resetCacheStats, getCacheStats } from "./ast/cache";
export type { ASTCacheEntry, ASTCacheStats } from "./ast/cache";
export { enhanceFindingsWithLLM } from "./llm/enhancer";
export {
  detectERCStandard,
  checkERC20Compliance,
  checkERC721Compliance,
  checkERC1155Compliance,
} from "./rules/erc-compliance";
export { detectVaultInflation } from "./rules/cp122-vault-inflation";
export {
  generateMarkdownReport,
  generateJSONReport,
  generateTableReport,
  generateMarkdownDiffReport,
  generateJSONDiffReport,
  generateTableDiffReport,
} from "./report/generator";
export { diffScans, computeFingerprint } from "./diff";
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
  ScanDiff,
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

export {
  buildImportGraph,
  buildMergedContractViews,
  computeRescanSet,
  resolveImportPath,
  hasImportDirectives,
} from "./ast/import-graph";

export type {
  ImportGraph,
  ParsedSolidityFile,
  ContractInfo,
  MergedMember,
  MergedContractView,
} from "./ast/import-graph";
