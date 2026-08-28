# Staking, Reward Distribution, and Vesting Accounting

The staking accounting engine is a deterministic, network-free analysis in
`@chainproof/core`. It builds a contract-level state-transition model before it
evaluates rules, so findings can cite the state write, arithmetic expression,
guard, call ordering, and missing checkpoint that prove the behavior.

The engine reports accounting and authorization behavior only. It does not
calculate, predict, or compare investment yield.

## Architecture

The implementation is separated into four layers:

1. **Model extraction** (`staking/model.ts`) classifies persistent state and
   functions, then records ordered reads, writes, calls, guards, and arithmetic.
2. **Framework adapters** (`staking/adapters.ts`) recognize structural
   Synthetix, MasterChef, OpenZeppelin VestingWallet, and generic accumulated
   index patterns. Contract names and imports alone never select an adapter.
3. **Accounting rules** (`staking/analyzer.ts`) consume only normalized models
   and produce structured findings with evidence paths and assumptions.
4. **Transport/presentation** (`staking/api.ts`, `staking/serialize.ts`, and the
   CLI command) collect sources and render the versioned result. Rule logic has
   no dependency on a terminal, server, editor, CI provider, or external API.

The normal `scan()` API also runs the rules once per physical Solidity source.
The dedicated API is preferred when an integration needs models, diagnostics,
resource controls, cancellation, or stable staking-specific JSON.

## Accounting model

State roles cover stake and reward assets, total shares, user balances, reward
rates, global indexes, user snapshots, accrued rewards, durations, period
finishes, last-update timestamps, queued rewards, epochs, vesting start,
duration and cliff, vested and claimed amounts, penalties, pause state, and
administrative roles.

Transition roles cover stake/deposit/restake, withdraw/exit, reward claims,
global and user checkpoints, reward notification, rate changes, epoch rollover,
emergency withdrawal, token recovery, pause/unpause, vesting creation, vested
claims, and vesting revocation. Every operation retains its lexical order and a
one-indexed source location.

Precision scalars are recognized from named constants such as `PRECISION`,
`WAD`, and `RAY`, and from literal fixed-point forms such as `1e18` and
`10 ** 27`.

## Rules

| Rule | Behavior proven | Default severity |
| --- | --- | --- |
| `CP-STK-001` | Stake supply/user balance changes precede the user reward checkpoint | High |
| `CP-STK-002` | A zero-supply reward branch has no queued/undistributed reward policy | Medium |
| `CP-STK-003` | Division precedes multiplication, or a per-share division lacks a scalar | Medium |
| `CP-STK-004` | A reward rate changes without funded-balance coverage for the interval | High |
| `CP-STK-005` | Rate, duration, period, or epoch state changes before the old-period checkpoint | High |
| `CP-STK-006` | A nominal transfer amount, rather than received balance delta, is credited as stake | High |
| `CP-STK-007` | Emergency withdrawal returns assets without checkpoint or explicit reward disposition | High |
| `CP-STK-008` | Token recovery can select an accounted stake or reward asset | Critical |
| `CP-STK-009` | A vested-token claim does not read or enforce stored cliff state | High |
| `CP-STK-010` | A vesting transfer occurs before claimed/released state is updated | High |
| `CP-STK-011` | Multiple reward assets share insufficient global/user checkpoint state | High |
| `CP-STK-012` | Mutable reward duration is used as a divisor without a local non-zero guard | Medium |
| `CP-STK-013` | An explicitly rebasing asset is tracked with fixed nominal balances, not shares | High |

Rule selection is deterministic. `includeRules` forms an allowlist;
`excludeRules` forms a denylist. Configuration validation rejects overlapping
lists and unknown identifiers.

## Framework adapters and secure patterns

`STAKING_FRAMEWORK_ADAPTERS` is a public, immutable catalog. Each entry lists
required state groups, required functions, recognized architectural guarantees,
and limitations. `matchStakingFrameworkAdapter()` returns both the adapter ID
and exact signals that matched it. Adapter recognition never suppresses a rule
by itself; a secure ordering or guard must be present on the affected path.

Secure accumulated-index accounting normally has this order:

1. Compute the global index through the previous timestamp and rate.
2. Store the global index and last-update timestamp.
3. Accrue the affected user's old balance against the index delta.
4. Store the user's paid index.
5. Change supply or user shares.
6. Perform the external asset transfer after accounting effects, or measure the
   received balance delta before crediting shares.

For zero supply, select an explicit policy: suspend emission time, queue elapsed
rewards, or return them. For multiple rewards, keep rate, finish time, global
index, user-paid index, and accrued amount independently per reward token.

## Public TypeScript API

```ts
import {
  analyzeStakingProject,
  serializeStakingReportJSON,
  type StakingAnalysisOptions,
} from "@chainproof/core";

const options: StakingAnalysisOptions = {
  includeModels: true,
  includeRules: ["CP-STK-001", "CP-STK-006", "CP-STK-009"],
  limits: {
    maxFiles: 100,
    maxSourceBytes: 1_000_000,
    maxFindings: 500,
  },
};

const report = analyzeStakingProject(["contracts/"], options);
process.stdout.write(serializeStakingReportJSON(report));
```

In-memory tools use `analyzeStakingSource()` or `analyzeStakingSources()`.
Filesystem integrations use `analyzeStakingFiles()` or
`analyzeStakingProject()`. `buildStakingModels()` and `analyzeStakingModel()`
are public for rule authors that need to inspect or extend the intermediate
representation.

Pass an `AbortSignal`-compatible object through `options.signal`. Cancellation
throws `StakingAnalysisCancelledError` at file, contract, and model traversal
boundaries; callers can retry with the same immutable inputs.

## CLI

```bash
# Markdown report; fail CI on high/critical findings
chainproof staking contracts/ --output staking-report.md

# Stable JSON for another tool, without a finding-based failure exit
chainproof staking contracts/ --format json --fail-on none

# A bounded, selected-rule run
chainproof staking contracts/ \
  --include-rule CP-STK-001 \
  --include-rule CP-STK-006 \
  --max-files 100 \
  --max-source-bytes 1000000 \
  --max-findings 250
```

`--fail-on` accepts `critical`, `high`, `medium`, `low`, or `none`. Exit code
`1` means the report met the configured finding threshold. Exit code `2` means
configuration, input, or serialization failed. JSON stdout has no banner or
progress text, making it directly parseable.

## Configuration and migration

Current schema:

```json
{
  "schemaVersion": 1,
  "includeModels": false,
  "includeRules": ["CP-STK-001", "CP-STK-006"],
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

Legacy v0 fields migrate as follows:

| v0 field | v1 field |
| --- | --- |
| `maxFileSize` | `limits.maxSourceBytes` |
| `maxIssues` | `limits.maxFindings` |
| `rules` | `includeRules` |

Use `migrateStakingConfig()` for an in-memory object or
`loadStakingConfigFile()` to parse, migrate, and validate JSON. Unknown future
schema versions, non-positive limits, invalid rule IDs, and include/exclude
overlap produce `StakingConfigError`. Corrupt JSON is rejected before analysis;
the error excludes file contents and the local absolute path.

## Report compatibility

`StakingAnalysisReport.schemaVersion` is `1.0.0`. Minor engine releases may add
new rule IDs, but do not change the meaning or type of an existing report field.
Consumers should gate on the report schema, tolerate unknown rule IDs, and use
`serializeStakingReportJSON()` rather than relying on JavaScript insertion
order. The serializer recursively sorts object keys and always adds one trailing
newline. Reports intentionally omit wall-clock timestamps, host information,
and network/provider metadata.

Every finding contains severity, confidence, category, contract, exact source
location, ordered evidence, assumptions, description, and recommendation.
Diagnostics distinguish parse failure, unreadable input, resource truncation,
configuration failure, and cancellation.

## Resource and security boundaries

Default budgets are enforced per call and cover source bytes, files, contracts,
functions, operations, findings, and evidence. Directory collection does not
follow symbolic links. AST traversal is iterative and cycle-safe. Reaching a
budget returns a structured truncation diagnostic instead of silently treating
the unexamined region as secure.

The engine performs no RPC, price, oracle, explorer, package-registry, or LLM
requests. It does not execute Solidity, infer current token balances, or assume
an administrator is honest. Findings describe provable source behavior plus
explicit assumptions. Error messages omit source text, credentials, provider
data, and host paths; source locations still retain the caller-provided logical
file identifier because reviewers need precise evidence.

## Precision and recall

Rules intentionally require multiple structural signals. For example,
fee-on-transfer accounting requires an external `transferFrom`, a caller amount
used by that call, and a supply/user-balance write derived from the same amount.
Recovery requires a caller-selected token transfer plus missing exclusions for
modeled stake/reward assets. Cliff bypass requires persistent cliff state and a
claim path that does not read it.

This approach favors reviewable evidence over name-only alerts. Indirect writes
through unparsed external libraries, assembly, delegatecall, dynamically
selected function pointers, and unusual domain terminology can reduce recall.
Confidence is lowered where funding coverage or per-token indexing depends on
semantic naming rather than a complete control-flow proof. Rule authors should
add a vulnerable fixture, a secure suppression, and an unrelated false-positive
control whenever a new signal is introduced.

## Test and fixture matrix

`examples/contracts/staking/` includes vulnerable and secure accumulated-index,
vesting, fee-on-transfer-compatible, multiple reward, emergency withdrawal,
token recovery, and rebasing-share patterns. Tests cover rule selection,
framework matching, source order determinism, malformed Solidity, corrupt and
migrated config, cancellation, byte/file/finding budgets, unreadable input,
scanner integration, CLI JSON, CLI thresholds, and report writing.

Boundary-focused integrator tests should additionally exercise:

- timestamp `start - 1`, `start`, `cliff - 1`, `cliff`, `periodFinish`, and
  `periodFinish + 1`;
- zero duration, duration one, maximum supported finish time, and rollover with
  leftover rewards;
- deposit immediately before/after reward notification and empty-pool rollover;
- partial withdraw, full exit, claim then restake, compound/restake, pause,
  emergency exit, and recovery after the final claim window;
- positive and negative rebases between every checkpoint and balance mutation;
- fee-on-transfer stake and reward assets, including changing fee rates.

## Maintainer workflow

To add a rule:

1. Add the rule ID to `StakingRuleId`, the validated configuration catalog, CLI
   rule validation, and deterministic `RULE_ORDER`.
2. Implement a pure `StakingContractModel -> StakingFinding[]` function.
3. Require positive evidence for the risky operation and explicit absence
   evidence for the missing invariant.
4. Add vulnerable, secure, malformed, boundary, and false-positive tests.
5. Document assumptions and adapter interactions here.
6. Run core build/tests, CLI build/tests, root lint/build/test, coverage, and
   TypeDoc generation.

## Troubleshooting

- **No contracts in the report:** verify targets end in `.sol`, are regular
  files, and fall within `maxFiles` and `maxSourceBytes`.
- **`STK_PARSE_ERROR`:** compile the source with its intended Solidity version;
  tolerant parser errors are treated as malformed input rather than analyzed
  partially.
- **Unexpected truncation:** inspect diagnostics, then raise only the exhausted
  limit. Keep finite limits for untrusted pull-request input.
- **Missing inherited behavior:** analyze the full project through normal
  `scan()` as well; the staking-specific source model is physical-file scoped.
- **Unexpected adapter:** call `matchStakingFrameworkAdapter()` and inspect
  `matchedState` and `matchedFunctions`. Adapter selection does not remove
  findings.
- **CI exits 1:** lower `--fail-on` only when the review policy permits it, or
  use `--fail-on none` when a separate consumer applies the gate.
