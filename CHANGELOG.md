# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Token callback/hook/reentrancy analysis (`@chainproof/core`
  `packages/core/src/rules/callback-analysis/`): models the implicit
  control-flow edges ERC-721/1155 receiver hooks, ERC-777 sender/receiver
  hooks, ERC-3156-style flash-loan callbacks, legacy ERC-223
  `tokenFallback`, and project-defined callback registries introduce, and
  detects incomplete state before the callback (`CP-CB-CEI`), cross-function
  reentrancy through it (`CP-CB-CROSSFN`), read-only reentrancy exposed via a
  `view` function (`CP-CB-READONLY`), unauthenticated callback spoofing
  (`CP-CB-SPOOF`), and unbounded batch callbacks (`CP-CB-BATCH`). Recognizes
  reentrancy-guard modifiers, hand-rolled mutexes, trusted-receiver
  allowlists, EOA-only checks, and flash-callback repayment invariants as
  suppressing guards. Findings carry `evidence`, `assumptions`, and
  `confidence`. See the [README](README.md#callback-hook--reentrancy-analysis-cp-90)
  for the full threat model and known limitations.
- Public API surface audit for `@chainproof/core`: every export is now categorized
  as public/stable or `@internal`, and the internal-only helpers (`parseSolidity`,
  `visit`, `runSlither`) are explicitly tagged as such.
- JSDoc documentation, with usage examples, on all public exports (`scan`,
  `generateMarkdownReport`, `generateJSONReport`, `generateTableReport`,
  `isSlitherAvailable`, `loadPlugin`, `loadPlugins`, `loadConfigFile`,
  `mergePluginsFromConfig`) and all public types (`ScanConfig`, `ScanResult`,
  `Finding`, `ChainProofPlugin`, `PluginRule`, etc).
- TypeDoc configuration (`packages/core/typedoc.json`) that generates an API
  reference site from the JSDoc comments.
- GitHub Actions workflow (`.github/workflows/docs.yml`) that publishes the API
  reference to GitHub Pages on every release.
- This changelog, backfilled with the project's notable history.
- Comprehensive Slither detector registry (`ast/slither-detectors.ts`, 90+
  detectors) mapping Slither's `check` ids to a title, an SWC cross-reference,
  and a rule category used for deduplication.
- Confidence-weighted severity for Slither findings: impact × confidence is
  now mapped to a ChainProof severity (e.g. High impact/Low confidence →
  `medium`, not `critical`), instead of impact alone.
- Improved Slither/built-in deduplication by rule category + normalized file +
  line-range overlap, replacing the old exact line+title match — catches
  cases like built-in `CP-107` and Slither's `reentrancy-eth` firing on the
  same lines with different titles, and Slither reporting the same issue once
  per inheritance level.
- `ScanConfig.slither.detectors.include` / `.exclude` to allowlist/denylist
  specific Slither detectors, plus `mergeSlitherConfigFromConfig()` to read
  the same setting from `.chainproofrc.json`. Omitting `slither` runs every
  detector, unchanged from prior behavior.

### Fixed

- Restored several build-breaking regressions in `@chainproof/core` left over
  from earlier merges: corrupted `detectReentrancy` / `detectTxOrigin` rule
  implementations, missing imports and undefined references in `scanner.ts`
  (`detectUnprotectedUpgrade`, `analyzeContract`, the scan/metrics wiring), a
  missing `ASTNode` re-export from `ast/parser.ts`, and a stale
  `enhanceFindingsWithLLM` call signature. `npm run build` and the test suite
  were not passing before this fix.
- `detectTxOrigin` now also inspects inherited **modifiers** (not just
  functions) when scanning merged contract views, fixing a false negative for
  `tx.origin` checks defined in a base contract's modifier.
- Removed redundant re-parsing in the scan pipeline: `scan()` now builds a
  single shared import graph up front instead of re-parsing each file up to
  three times, meaningfully reducing scan latency.

## [0.1.0] - 2026-06-22

### Added

- Symbolic execution pass for SWC-101 (integer overflow/underflow), replacing
  the previous pragma-only heuristic. Propagates `require`/`assert` bounds
  constraints to cut false positives, and extends detection to `unchecked {}`
  blocks and compound-assignment operators (`+=`, `-=`, `*=`).
- Plugin API (`ChainProofPlugin`, `PluginRule`, `loadPlugin`, `loadPlugins`) for
  third-party detection rules, loadable from npm packages, local files, or
  `.chainproofrc.json`.
- Gas optimization analysis for storage packing and struct layout.
- CodeLens and code action integration for inline fix suggestions in the VS
  Code extension.
- REST API server mode (`chainproof serve`).
- Contract complexity and maintainability metrics (cyclomatic complexity,
  inheritance depth, risk score) available via `ScanConfig.useMetrics`.
- Multi-file contract analysis: import graph resolution and merged contract
  views, so vulnerabilities inherited from base contracts are detected in
  derived contracts even when only the derived file is scanned.
- Comprehensive test suite, including property-based tests (via `fast-check`).
- Provider-agnostic LLM abstraction supporting Anthropic, OpenAI, Bedrock, and
  Ollama for finding enhancement.
- Core scanning engine: Solidity AST parsing, SWC-107 (reentrancy), SWC-115
  (`tx.origin` authentication), SWC-104 (unchecked call return value)
  detectors, optional Slither integration, and Markdown/JSON/table report
  generation.

### Deprecation policy

Starting from this release, ChainProof follows this policy for the public
`@chainproof/core` API:

- Deprecated APIs are marked with an `@deprecated` JSDoc tag (surfaced in the
  generated TypeDoc reference) in a **minor** release, and continue to work
  unchanged in that release line.
- Deprecated APIs are removed no earlier than the **next major** release.
- Breaking changes bump the **major** version, new backwards-compatible
  functionality bumps **minor**, and bug fixes bump **patch**, per
  [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[Unreleased]: https://github.com/dragoncode-01/StellarChainproofs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dragoncode-01/StellarChainproofs/releases/tag/v0.1.0
