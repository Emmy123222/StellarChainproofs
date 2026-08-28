# Governance, Timelock, and Proposal Execution Safety

ChainProof's governance analyzer is a deterministic static-analysis pass for Solidity governance
systems. It models how proposals, voting weight, queue state, timelock operations, emergency
authority, multisig approvals, upgrades, and cross-chain messages reach privileged state changes.

The analyzer evaluates **structural implementation safety**. It does not decide whether governance
is politically legitimate, whether voters made a good choice, or whether a proposal outcome is
desirable.

## Threat model

The engine assumes an adversary may:

- borrow, transfer, or delegate voting tokens within a block;
- choose proposal targets, ETH values, calldata, salts, and action ordering;
- resubmit an approved proposal, multisig transaction, or bridge message;
- trigger reentrant callbacks from a proposal action;
- compromise one configured guardian, proposer, executor, or administrator;
- exploit integer truncation at quorum and threshold boundaries;
- collide incomplete proposal/operation identifiers;
- deliver a valid cross-chain message more than once or on the wrong domain.

The engine does not assume that any named framework is safe merely because its contract name or
inheritance list resembles that framework. Adapters recognize structure and suppress only risks
whose required guards, state, data binding, and ordering are visible in the analyzed source.

## Normalized model

For each relevant contract the analyzer records:

- state variables and semantic roles such as `vote-snapshot`, `minimum-delay`, `nonce`, `guardian`,
  `proposer-role`, `executor-role`, `message-id`, and `chain-domain`;
- transitions and roles such as `propose`, `cast-vote`, `quorum`, `schedule`, `execute`, `cancel`,
  `update-delay`, `hash-operation`, `emergency-execute`, `multisig-execute`, and
  `cross-chain-receive`;
- source-ordered reads, writes, guards, arithmetic operations, and calls;
- direct target/value/calldata taint from function parameters into low-level calls, delegatecalls,
  upgrade primitives, and generic execution entry points;
- adapter matches and the assumptions that apply to the modeled lifecycle.

The AST walk is iterative and cycle-safe. No RPC, chain state, package download, compiler process,
symbolic executor, or network request is used.

## Rule reference

| Rule | Default severity | Structural condition |
| --- | --- | --- |
| `CP-GOV-001` | critical | Voting power reads a live `balanceOf` without past checkpoints. |
| `CP-GOV-002` | critical | Voting power is acquired and read at the current block. |
| `CP-GOV-003` | high | Quorum/threshold math divides before multiplication or accepts zero. |
| `CP-GOV-004` | high | Proposal lifecycle lacks separate non-zero delay and voting period. |
| `CP-GOV-005` | critical | Privileged execution lacks queued timelock readiness proof. |
| `CP-GOV-006` | critical | Execution lacks both replay guard and pre-call consumption. |
| `CP-GOV-007` | high | Proposal identity omits action-defining fields. |
| `CP-GOV-008` | critical | Proposal-controlled target/value/calldata reaches an unbounded call. |
| `CP-GOV-009` | critical | Guardian/emergency execution bypasses normal controls. |
| `CP-GOV-010` | critical | Minimum delay is mutable outside a scheduled self-call. |
| `CP-GOV-011` | high | Execution accepts but does not enforce its predecessor. |
| `CP-GOV-012` | high | Scheduling/hashing accepts but omits the operation salt. |
| `CP-GOV-013` | medium | Scheduling and execution authority are not separated. |
| `CP-GOV-014` | critical | Proposal-controlled input reaches an immediate upgrade primitive. |
| `CP-GOV-015` | critical | Cross-chain execution lacks pre-call replay consumption or domain binding. |
| `CP-GOV-016` | critical | Multisig execution lacks threshold signature proof and nonce consumption. |

Every finding contains category, contract, exact source location, confidence, evidence, explicit
assumptions, and a remediation. Absence findings are labeled as such rather than presented as a
runtime proof.

## Framework adapters

### OpenZeppelin Governor

Recognized from proposal threshold, voting delay/period, and proposal/vote/snapshot/deadline
functions. The adapter does not assume `_getVotes` queries a safe past checkpoint and does not
assume the configured executor is a timelock.

### OpenZeppelin TimelockController

Recognized from minimum-delay and timestamp state with hash/schedule/execute/update-delay
transitions. Complete action hashing, predecessor completion, readiness, pre-call consumption,
self-authorized delay changes, and distinct roles are still checked.

### Compound Governor Bravo

Recognized from proposal count/threshold/quorum plus propose, vote, queue, execute, and state
transitions. `getPriorVotes` boundaries and guardian behavior remain independently analyzed.

### Safe-style multisig

Recognized from owners/signers, threshold, nonce, `execTransaction`, and `checkSignatures`.
ChainProof checks structural threshold use and pre-call nonce consumption. Modules, guards,
fallback handlers, owner uniqueness, signature malleability, and deployment configuration require
additional review.

### Cross-chain governor

Recognized from message replay state, source-chain/domain state, and a message receiver. Bridge
authenticity, finality, relayer incentives, and source-governor deployment correctness are external
assumptions.

## CLI

```bash
# Markdown for review
chainproof governance contracts/ --output governance-report.md --fail-on high

# Stable JSON artifact for CI
chainproof governance contracts/ --format json --output governance-report.json --fail-on critical

# Focused investigation
chainproof governance contracts/Governor.sol \
  --include-rule CP-GOV-001 \
  --include-rule CP-GOV-002 \
  --include-models \
  --fail-on none
```

### CLI options

| Option | Meaning |
| --- | --- |
| `--format json\|markdown` | Output encoding; default `markdown`. |
| `--output <file>` | Write the artifact instead of stdout. |
| `--config <file>` | Load versioned JSON configuration. |
| `--include-models` | Include normalized contract models in JSON. |
| `--include-rule <id>` | Run one rule; repeat to build an allowlist. |
| `--exclude-rule <id>` | Skip one rule; repeat to build a denylist. |
| `--max-source-bytes <n>` | Per-file UTF-8 source budget. |
| `--max-files <n>` | Project file budget. |
| `--max-contracts <n>` | Per-file contract budget. |
| `--max-functions <n>` | Per-file and per-contract function budget. |
| `--max-operations <n>` | Per-function modeled-operation budget. |
| `--max-findings <n>` | Report finding budget. |
| `--fail-on <severity>` | Exit 1 at or above the selected severity; default `high`. |

Exit code `0` means the configured threshold was not met, `1` means it was met, and `2` means
configuration/usage/analysis failed. JSON mode never prints a banner to stdout.

## Core API

```typescript
import {
  analyzeGovernanceSource,
  analyzeGovernanceSources,
  analyzeGovernanceFiles,
  generateGovernanceMarkdown,
  serializeGovernanceReport,
} from '@chainproof/core';

const report = analyzeGovernanceFiles(['contracts/Governor.sol', 'contracts/Timelock.sol'], {
  includeModels: true,
  includeRules: ['CP-GOV-005', 'CP-GOV-006', 'CP-GOV-008'],
  limits: {
    maxSourceBytes: 2 * 1024 * 1024,
    maxFiles: 100,
    maxFindings: 500,
  },
  signal: abortController.signal,
});

await fs.promises.writeFile('governance.json', serializeGovernanceReport(report));
```

`analyzeGovernanceSource` is useful for editor buffers. `analyzeGovernanceSources` accepts explicit
`{ file, source }` values and sorts them by file before analysis. `analyzeGovernanceFiles` accepts
files or directories, skips symlinks, collects `.sol` files recursively, and reports sanitized IO
diagnostics.

## Configuration

Current configuration schema:

```json
{
  "schemaVersion": 1,
  "includeModels": false,
  "includeRules": ["CP-GOV-001", "CP-GOV-002", "CP-GOV-005"],
  "excludeRules": [],
  "limits": {
    "maxSourceBytes": 2097152,
    "maxFiles": 256,
    "maxContracts": 128,
    "maxFunctionsPerFile": 512,
    "maxFunctionsPerContract": 512,
    "maxOperationsPerFunction": 2048,
    "maxFindings": 1024,
    "maxEvidencePerFinding": 12
  }
}
```

All limit values must be positive safe integers. Included and excluded rule lists may not overlap.
Rule IDs outside `CP-GOV-001` through `CP-GOV-016` are rejected.

Legacy schema v0 is migrated in memory:

| v0 field | v1 field |
| --- | --- |
| `maxFileSize` | `limits.maxSourceBytes` |
| `maxIssues` | `limits.maxFindings` |
| `detectors` | `includeRules` |

Malformed JSON, unsupported future schemas, invalid limits, rule-list conflicts, and unreadable
configuration files raise `GovernanceConfigError`. Errors contain a bounded message and stable code;
they do not include configuration contents or source contents.

## Bounds and cancellation

Default limits prevent an untrusted repository from producing unbounded AST/model/report work.
When a source, contract, function, operation, file, finding, or evidence limit is reached, the
report contains a `GOV_*_LIMIT` diagnostic and sets `summary.truncated` where output is incomplete.

Pass an `AbortSignal`-compatible `{ aborted, reason }` object in `options.signal`. Cancellation is
checked before IO, parsing, contract modeling, and each rule pass and raises
`GovernanceAnalysisCancelledError` (`GOV_CANCELLED`).

## Diagnostics

| Code | Meaning |
| --- | --- |
| `GOV_PARSE_ERROR` | Solidity parser could not produce a usable AST. |
| `GOV_SOURCE_LIMIT` | Source/file budget reached. |
| `GOV_CONTRACT_LIMIT` | Contract budget reached. |
| `GOV_FUNCTION_LIMIT` | Function budget reached. |
| `GOV_OPERATION_LIMIT` | Per-function operation budget reached. |
| `GOV_FINDING_LIMIT` | Finding output budget reached. |
| `GOV_CANCELLED` | Caller requested cancellation. |
| `GOV_CONFIG_INVALID` | Configuration failed validation/migration. |
| `GOV_FILE_UNREADABLE` | Solidity source could not be read. |

## Output stability

The report schema version is `1.0.0`. JSON serialization recursively sorts object keys, and file,
contract, transition, finding, evidence, and diagnostic ordering is deterministic. There is no
timestamp in the specialized report, so identical sources and configuration produce byte-identical
JSON. Consumers should check `schemaVersion` before deserializing future reports.

## Known limitations

- Analysis is syntactic/structural and intra-file; it is not an EVM execution proof.
- Modifier bodies inherited from unresolved imports may contain guards not visible to the model.
- Dynamic assembly, computed selectors, proxy storage aliases, and delegatecall effects can require
  manual tracing.
- Adapter matches describe recognizable structure, not correct deployment role assignments.
- Token checkpoint correctness, flash-loan availability, bridge authenticity/finality, multisig
  signer independence, and timelock role membership can depend on external contracts or deployment.
- Economic threshold adequacy and political governance design are intentionally not scored.

Use findings as auditable leads alongside tests, deployment review, formal properties, and an
independent security assessment.

## Fixtures and tests

`examples/contracts/governance/` contains paired secure/vulnerable Governor, TimelockController,
multisig, and cross-chain fixtures. Core tests cover all 16 rule paths, adapters, source ordering,
serialization, bounds, cancellation, parsing, config migration/corruption, scanner integration,
and false-positive suppression. CLI tests cover JSON cleanliness, Markdown artifacts, CI threshold
exit codes, and invalid rule handling.

Run:

```bash
npm run build
npm test
npm run lint
```
