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
  detectCallbackReentrancy,
  buildCallbackGraph,
  detectImplementedReceiverHooks,
  detectERC165Support,
  detectCallbackSpoofing,
  RECEIVER_HOOK_SIGNATURES,
} from "./rules/callback-analysis";
export type {
  CallbackStandard,
  CallbackKind,
  CallbackEdge,
  CallbackGraph,
  InterfaceEvidence,
  GuardEvidence,
} from "./rules/callback-analysis";
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
  FindingEvidenceItem,
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

// ─── Threat Modeling ─────────────────────────────────────────────────────────
export { generateThreatModel } from "./threat-model";
export {
  generateMarkdownThreatModel,
  generateJSONThreatModel,
  generateMermaidDiagram,
  generateASCIIDiagram,
  extractThreatModel,
  prioritizeThreats,
  loadAssumptions,
  mergeAssumptions,
  DEFAULT_AGENTS,
} from "./threat-model";
export type {
  ThreatModel,
  ThreatModelConfig,
  ThreatModelAssumptions,
  ThreatModelSummary,
  Asset,
  ThreatAgent,
  TrustBoundary,
  EntryPoint,
  AttackSurface,
  Threat,
  STRIDECategory,
  DeFiCategory,
  LocationInfo,
  SeverityLevel as TMSeverityLevel,
  AssetValue,
  AssetType,
} from "./threat-model";

// ─── Invariant DSL ───────────────────────────────────────────────────────────
export {
  parseInvariantSpecFile,
  validateInvariantSpecFile,
  checkInvariants,
  checkInvariantsFromFile,
  explainInvariant,
  migrateInvariantSpecFile,
  serializeReport,
  stableStringify,
  scaffoldInvariantSpec,
  formatRange,
  CURRENT_SPEC_SCHEMA_VERSION,
  SUPPORTED_SPEC_SCHEMA_VERSIONS,
  RESULT_SCHEMA_VERSION,
  DEFAULT_EVALUATION_BUDGET,
  INVARIANT_KINDS,
  InvariantDslError,
  SpecParseError,
  SpecValidationError,
  BoundedEvaluationError,
  CorruptArtifactError,
  MigrationError,
} from "./dsl";
export type {
  ParseSpecResult,
  MigrationResult,
  InvariantKind,
  InvariantSeverity,
  InvariantScopeRaw,
  CallOrderRaw,
  InvariantDeclRaw,
  InvariantSpecFileRaw,
  InvariantDecl,
  InvariantSpec,
  PredicateDef,
  EvaluationBudget,
  CheckInvariantsOptions,
  InvariantStatus,
  Confidence,
  EvidenceLocation,
  InvariantEvidence,
  InvariantResult,
  InvariantCheckSummary,
  InvariantCheckReport,
  Diagnostic,
  DiagnosticCode,
  DiagnosticSeverity,
  SourceRange,
  SourcePosition,
} from "./dsl";

