# Production staking, reward distribution, and vesting accounting analysis

## Summary

This PR adds a production TypeScript accounting-analysis track for staking,
reward distribution, and vesting. It models persistent accounting state and
ordered transitions, emits 13 evidence-driven rules through the normal
`@chainproof/core` scanner, exposes a dedicated deterministic/versioned API,
and adds a `chainproof staking` CLI for CI and integration use.

The implementation adds 2,657 production TypeScript source lines across the
core staking module and CLI command (2,399 nonblank/non-comment lines by the
repository-local count). Tests, documentation, fixtures, generated output, and
format-only changes are excluded from that figure.

## Architecture

- **Model layer:** classifies stake/reward assets, shares/supply, user balances,
  reward rates/indexes/snapshots, epochs, queued rewards, vesting schedule,
  cliff/claims, penalties, pause state, and administrators. Each function is an
  ordered transition of reads, writes, calls, guards, and arithmetic with exact
  source locations.
- **Adapter layer:** structurally recognizes Synthetix StakingRewards,
  MasterChef reward-debt, OpenZeppelin VestingWallet, and generic accumulated
  index architectures. Matches return exact state/function evidence; adapter
  identity alone never suppresses a finding.
- **Rule layer:** 13 pure model-to-finding analyses cover checkpoint ordering,
  first-depositor/zero-supply behavior, division loss, over-distribution,
  administrative parameter changes, fee-on-transfer stake assets, emergency
  exits, protected-token recovery, cliff bypass, claim interaction ordering,
  multiple reward tokens, duration boundaries, and rebasing assets.
- **API layer:** in-memory, file, and recursive project entry points support
  typed limits, cooperative cancellation, rule selection, normalized models,
  structured diagnostics, and deterministic aggregation.
- **Presentation layer:** stable JSON schema `1.0.0`, Markdown serialization,
  and CLI threshold behavior are separate from analysis. The normal `scan()`
  path adapts accounting findings to standard ChainProof `Finding` objects.

The root build is dependency-ordered (`core -> server -> cli -> integrations`)
so a clean checkout no longer relies on stale workspace `dist` directories.
An ESLint configuration now makes the documented root lint command executable;
it reports the repository's existing unused-code/style debt as warnings while
keeping recommended correctness rules as errors.

## Precision and recall

The rules require conjunctive structural evidence instead of names alone. For
example, the fee-on-transfer rule needs a `transferFrom`, a caller-supplied
amount used by that transfer, and a supply/user write derived from the same
amount. Recovery findings need a caller-selected token transfer plus missing
exclusions for modeled stake/reward assets. Cliff bypass requires persistent
cliff state and a claim path that does not read it.

This favors reviewable, higher-precision findings. Confidence is `medium` when
coverage or per-token independence depends partly on semantic state roles; it is
`high` for direct operation ordering, missing guards, and fixed-vs-share state.
Known recall limits are assembly, delegatecall, dynamically selected function
pointers, external-library writes that are not visible in the physical source,
and highly nonstandard accounting terminology. Every finding includes its
assumptions so reviewers can invalidate an inapplicable model without hiding the
underlying evidence.

## Security boundaries

- No RPC, explorer, price, oracle, registry, LLM, or other network dependency is
  used by the accounting engine or its tests.
- The output describes provable accounting/authorization behavior and does not
  estimate or compare investment yield.
- Default resource budgets cover bytes, files, contracts, functions per file,
  functions per contract, operations per function, findings, and evidence.
- Pre-parse source-shape checks bound generated/adversarial files before the
  Solidity parser; AST/model traversal is iterative and cycle-safe.
- Directory collection does not follow symlinks. Cancellation is checked at
  project, file, contract, and model traversal boundaries.
- Malformed/corrupt configuration and Solidity become typed errors or
  diagnostics. Error messages omit source content, credentials, provider data,
  and host paths; findings retain caller-provided logical paths for review.

## Configuration and compatibility

- Report schema: `1.0.0`; recursively sorted JSON keys; no wall-clock timestamp
  or host/provider metadata.
- Config schema: `1`; strict positive integer limits, validated rule IDs, and
  rejected include/exclude overlap.
- Legacy `maxFileSize`, `maxIssues`, and `rules` migrate to
  `limits.maxSourceBytes`, `limits.maxFindings`, and `includeRules`.
- Unknown future config versions and corrupt JSON fail before source analysis.
- Existing `scan()` and `Finding` shapes remain backward-compatible; the new
  rules appear as standard `CP-STK-*` findings.

## Performance

Measured on Node `v20.20.2` in the contributor environment:

| Scenario | Input | Result |
| --- | --- | --- |
| Hot in-memory fixture suite, 50 iterations | 6 files / 9,618 bytes / 17 findings | 2.73 ms median, 4.36 ms p95 |
| Cold CLI process | Same 6-file directory | 0.93 s elapsed, 114,944 KiB max RSS |
| Generated adversarial source | 86,863 bytes / 700 functions | bounded in 0.40 ms with `STK_FUNCTION_LIMIT` before parsing |

Benchmark command: `node /tmp/staking-benchmark.js` for the 50-iteration and
generated-source run, plus `/usr/bin/time` around `chainproof staking ...
--format json --fail-on none` for the cold CLI measurement. These are local
engineering measurements rather than a cross-platform performance guarantee.

## Test evidence

Targeted coverage includes vulnerable and secure accumulated-index contracts,
reward coverage and zero-supply policies, multiple reward assets,
fee-on-transfer balance-delta accounting, rebasing shares, restaking,
emergency withdrawal, protected-token recovery, duration/epoch boundaries,
vesting cliff boundaries, checks-effects-interactions, malformed input, corrupt
and migrated config, cancellation, deterministic ordering, resource budgets,
scanner integration, CLI JSON, CLI thresholds, and artifact writing.

Final verification commands:

- [x] `npm ci`
- [x] `npm run lint` (0 errors; 17 pre-existing warnings surfaced)
- [x] `npm run build`
- [x] `npm run test`
- [x] `npm run test:ci --workspace=packages/core` (306 tests; 82.61% statements / 84.72% lines overall; staking module 87.44% statements / 90.04% lines)
- [x] `npm run build --workspace=packages/core`
- [x] `npm run test --workspace=packages/core -- --runInBand src/staking/__tests__`
- [x] `npm run build --workspace=packages/server && npm run build --workspace=packages/cli`
- [x] `npm test --workspace=packages/cli -- --runInBand src/__tests__/staking.test.ts`
- [x] `npm run docs --workspace=packages/core` (0 errors; existing TypeDoc warnings)
- [x] GitHub Action package build/bundle (covered by root build)

## Documentation

`docs/staking-accounting.md` documents the threat model, architecture, all
rules, secure patterns, framework adapters, API and CLI examples, schema and
migration policy, compatibility contract, resource/cancellation behavior,
precision/recall tradeoffs, test matrix, rule-author workflow, limitations, and
troubleshooting. README and changelog entries link to the guide.

## Follow-up work

- Add merged-inheritance staking models so dedicated reports can attribute
  checkpoint behavior inherited from another physical source as precisely as
  the general scanner's merged views.
- Add control-flow dominance for checkpoint/guard recognition across complex
  internal call graphs while retaining the current bounded evaluation model.
- Add SARIF rendering for staking-specific evidence paths when the repository's
  general SARIF surface lands.
- Extend adapters for tokenized staking vault standards after their accounting
  invariants and compatibility expectations are standardized in ChainProof.
