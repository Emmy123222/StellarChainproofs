# Invariant DSL

A versioned, declarative JSON DSL for expressing protocol-specific security
invariants and checking them deterministically against Solidity source.
Implemented in `packages/core/src/dsl/` and exported from `@chainproof/core`;
exposed via the `chainproof invariants` CLI subcommands.

## Table of contents

- [Why this exists](#why-this-exists)
- [Integration boundary](#integration-boundary)
- [Quick start](#quick-start)
- [Spec file format](#spec-file-format)
- [The condition expression language](#the-condition-expression-language)
- [Invariant kinds](#invariant-kinds)
- [Evaluation model](#evaluation-model)
- [Public API](#public-api)
- [CLI reference](#cli-reference)
- [Diagnostic codes](#diagnostic-codes)
- [Threat model & security assumptions](#threat-model--security-assumptions)
- [Limitations](#limitations)
- [Compatibility & migration](#compatibility--migration)
- [Troubleshooting](#troubleshooting)

## Why this exists

Generic detectors (reentrancy, tx.origin, unchecked overflow, ...) catch
vulnerability *patterns*. They cannot know that, for a specific protocol,
`totalAssets` must never fall below `totalDebt`, or that `withdraw` must
debit a balance before making an external call, or that only the function
named `adjustAssets` may write `feeRate`. Those are protocol-specific
**invariants**, and until now the only way to check them in this codebase
was a bespoke rule (see `packages/core/src/rules/cp122-vault-inflation.ts`
for an example of exactly this problem, hand-coded).

The invariant DSL lets a spec author declare such properties in a small,
reviewable JSON file and check them with the same determinism guarantees as
the rest of ChainProof: no network calls, no LLM, same input → same output,
every run.

## Integration boundary

This DSL performs **deterministic, bounded static analysis** — parsing,
schema/type validation, and AST/call-graph pattern matching. It does not:

- translate natural language into invariants, or generate invariants with an
  LLM (that's tracked separately, see issue #52 — this DSL is the
  deterministic checking layer AI-generated invariants would eventually
  compile down to, not a replacement for it);
- perform symbolic execution or call out to an SMT solver;
- require or make any network call.

## Quick start

```bash
chainproof invariants init vault.cpinv.json --contract Vault
# edit vault.cpinv.json's invariants array
chainproof invariants validate vault.cpinv.json
chainproof invariants check vault.cpinv.json contracts/Vault.sol
```

Or programmatically:

```typescript
import { parseInvariantSpecFile, checkInvariants } from '@chainproof/core';

const { spec, diagnostics } = parseInvariantSpecFile('vault.cpinv.json');
if (!spec) {
  console.error(diagnostics);
  process.exit(1);
}

const report = await checkInvariants(spec, { targets: ['contracts/Vault.sol'] });
for (const result of report.results) {
  console.log(result.id, result.status, result.message);
}
```

A complete worked example — one spec exercising all seven invariant kinds,
checked against a secure and a deliberately vulnerable fixture — lives at
[`examples/invariant-specs/vault.cpinv.json`](../examples/invariant-specs/vault.cpinv.json)
and [`examples/contracts/invariants/`](../examples/contracts/invariants/).

## Spec file format

A spec is a JSON file, conventionally named `*.cpinv.json`:

```json
{
  "schemaVersion": "1.0.0",
  "name": "vault-core-invariants",
  "description": "Core security invariants for Vault",
  "imports": ["./common-predicates.cpinv.json"],
  "predicates": {
    "isOwner": "msg.sender == owner"
  },
  "invariants": [
    {
      "id": "VAULT-ACCESS-001",
      "kind": "access",
      "title": "Only the owner may adjust reserves",
      "description": "optional longer explanation",
      "severity": "high",
      "scope": { "contract": "Vault", "function": "adjustAssets" },
      "condition": "isOwner()",
      "assumptions": ["'owner' is set once in the constructor and is never the zero address"],
      "references": ["SWC-105"]
    }
  ]
}
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `schemaVersion` | string | yes | Currently only `"1.0.0"` is accepted directly; older shapes need `chainproof invariants migrate` first. |
| `name` | string | yes | Non-empty. |
| `description` | string | no | |
| `imports` | string[] | no | Relative paths to other spec files, resolved from this file's directory. Only `predicates` are imported (not `invariants`). Cyclic imports are rejected (`DSL009`). |
| `predicates` | object | no | Map of reusable, zero-argument named boolean expressions. A predicate may reference other predicates as long as there's no cycle (`DSL008`). |
| `invariants` | array | yes | See below. |

Each entry in `invariants`:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | string | yes | Unique within the spec (`DSL011` on duplicate). Stable — used as the sort key for deterministic report ordering and as the `explain` lookup key. |
| `kind` | string | yes | One of `state`, `access`, `call-order`, `value-flow`, `event`, `arithmetic`, `cross-function`. See [Invariant kinds](#invariant-kinds). |
| `title` | string | yes | |
| `description` | string | no | |
| `severity` | string | yes | `critical` \| `high` \| `medium` \| `low` \| `info`. |
| `scope.contract` | string | yes | Contract name as it appears in the Solidity source (post-inheritance-resolution — an inherited-but-undefined-locally function still resolves). |
| `scope.function` | string | kind-dependent | Required for every kind except `state`/`cross-function`, where omitting it makes the invariant contract-wide. |
| `scope.signature` | string | only for overloads | `"transfer(address,uint256)"` — required when `scope.function` is ambiguous (`DSL014`). |
| `condition` | string | kind-dependent | A boolean expression in the [condition language](#the-condition-expression-language). Required for `state`, `access`, `arithmetic`, `cross-function`, `value-flow`. |
| `event` | string | `event` kind only | Event name that must be emitted. |
| `order` | `{ before, after }` | `call-order` kind only | Names of two calls; `before` must occur at an earlier line than `after`. Use the sentinel `"<external-call>"` to match any `.call`/`.send`/`.transfer`. |
| `assumptions` | string[] | no | Free text — surfaced in `explain` output and the check report, never evaluated. Document what the checker *can't* verify (e.g. "owner is never the zero address"). |
| `references` | string[] | no | e.g. SWC ids, free text. |

## The condition expression language

A small, deterministic boolean-expression grammar — not Solidity, a
strict subset shaped for it:

```
expr        := or
or          := and ("||" and)*
and         := equality ("&&" equality)*
equality    := comparison (("==" | "!=") comparison)*
comparison  := additive (("<" | "<=" | ">" | ">=") additive)*
additive    := multiplicative (("+" | "-") multiplicative)*
multiplicative := unary (("*" | "/" | "%") unary)*
unary       := ("!" | "-") unary | postfix
postfix     := primary ("." identifier | "[" expr "]" | "(" args ")")*
primary     := number | string | "true" | "false" | identifier | "(" expr ")"
```

Examples: `msg.sender == owner`, `balances[msg.sender] >= amount`,
`totalAssets >= totalDebt + pendingWithdrawals`, `isOwner() && !paused`.

Predicate/function calls (`isOwner()`) are ordinary call expressions —
`old(x)` and `changed(x)` parse and type-check but currently have **no
evaluation semantics** (see [Limitations](#limitations)); an invariant using
them reports `status: "skipped"` rather than a potentially-wrong verdict.

## Invariant kinds

Every kind compiles to a **bounded AST/call-graph query** — never a live
symbolic executor. All of them are conservative: an inability to find a
matching guard is reported as `fail`, not silently ignored, and a guard is
only considered a match if it's **structurally equivalent** to the declared
condition (see below) — not merely implied by it.

| Kind | `scope.function` | What it checks |
| --- | --- | --- |
| `access` | required | `condition` must be structurally enforced by a `require`/`assert`/`if (...) revert` guard in the function body **or** one of its applied modifiers. |
| `arithmetic` | required | Same guard-matching as `access`, for arithmetic/relational conditions scoped to one function. |
| `state` | optional (omit for contract-wide) | Every function that writes a state variable referenced by `condition` must contain a matching guard. Vacuously `pass`es if no function writes those variables. |
| `cross-function` | optional | Same as `state`, but restricted to functions reachable (via the internal call graph) from `scope.function`; evidence includes the concrete call path. |
| `event` | required | The function must contain an `emit <event>(...)` statement anywhere in its body. |
| `call-order` | required | `order.before` must occur at a strictly earlier source line than `order.after` within the function. Use `"<external-call>"` for either side to match any low-level `.call`/`.send`/`.transfer`. |
| `value-flow` | required | For each write to a state variable referenced by `condition`, if the written value is derived **directly** from a function parameter, that parameter must be referenced by a guard at or before the write's line. Single-hop only (see [Limitations](#limitations)). |

### Structural guard matching, precisely

A `require(EXPR)` / `assert(EXPR)` / `if (cond) revert(...)` /
`if (!cond) revert(...)` is translated into the same expression-AST shape as
`condition` and compared via a canonical form that treats `==`/`!=`/`&&`/`||`/`+`/`*`
as commutative and normalizes flipped comparisons (`a >= b` ≡ `b <= a`).
It does **not** perform algebraic reasoning: `a + b >= c` will *not* match
`a >= c - b`, even though they're mathematically equivalent — the evaluator
is deliberately biased toward false negatives (reporting `fail` when it
can't prove a match) over false positives (see
[Threat model](#threat-model--security-assumptions)).

## Evaluation model

`checkInvariants(spec, { targets, budget? })`:

1. Parses the target `.sol` files into merged, inheritance-resolved contract
   views (the same `buildMergedContractViews` machinery the rest of
   ChainProof uses — an invariant scoped to a function only present via
   inheritance still resolves, and reports the file it's actually defined
   in).
2. For each invariant, resolves `scope` against those views (`DSL012`
   unknown contract, `DSL013` unknown function, `DSL014` ambiguous
   overload), expands any predicate calls in `condition` (bounded by
   `budget.maxPredicateDepth`; cycles are rejected at parse time), and
   dispatches to the kind-specific query above.
3. Every invariant runs under a **step budget**
   (`budget.maxStepsPerInvariant`, default 20 000) — exceeding it reports
   `status: "timeout"` for that invariant rather than hanging.
4. The whole call runs under a **wall-clock budget**
   (`budget.maxTotalTimeMs`, default 10 000 ms) — once exceeded, remaining
   invariants report `status: "skipped"` and `report.bounded.timeExceeded`
   is `true`.
5. Results are sorted by invariant `id` — **never** by filesystem or
   traversal order — so two runs over an unchanged spec+contract produce
   byte-identical JSON via `serializeReport()`.

Result statuses: `pass`, `fail`, `error` (scope/predicate resolution
failure — see `report.diagnostics`), `timeout` (step budget), `skipped`
(time budget, or an unsupported construct like `old()`).

## Public API

All exported from `@chainproof/core`:

| Export | Purpose |
| --- | --- |
| `parseInvariantSpecFile(path, budget?)` | Parse + validate + bind a spec file. Never throws for malformed *content* — returns `{ spec: undefined, diagnostics }`. Throws `SpecParseError` only if the root file itself can't be read. |
| `validateInvariantSpecFile(path)` | Thin wrapper: `{ valid, diagnostics }`, no contract needed. |
| `checkInvariants(spec, options)` | Evaluate an already-parsed spec. See [Evaluation model](#evaluation-model). |
| `checkInvariantsFromFile(specPath, options)` | Parse + check in one call; throws `SpecValidationError` (carries `.diagnostics`) if the spec itself is invalid. |
| `explainInvariant(spec, id)` | Human-readable explanation: resolved scope, expanded condition, assumptions. |
| `migrateInvariantSpecFile(path)` | Upgrade a legacy spec to the current schema. Throws `CorruptArtifactError`/`MigrationError`. |
| `scaffoldInvariantSpec(name, contract?)` | Build the object `chainproof invariants init` writes. |
| `serializeReport(report)` / `stableStringify(value)` | Deterministic, key-sorted JSON serialization. |
| `CURRENT_SPEC_SCHEMA_VERSION`, `SUPPORTED_SPEC_SCHEMA_VERSIONS`, `RESULT_SCHEMA_VERSION` | Version constants. |
| `DEFAULT_EVALUATION_BUDGET` | The default `EvaluationBudget`. |

Types: `InvariantSpecFileRaw`, `InvariantSpec`, `InvariantDecl`,
`InvariantCheckReport`, `InvariantResult`, `EvidenceLocation`, `Diagnostic`,
`SourceRange`, `EvaluationBudget`, and more — see
`packages/core/src/dsl/types.ts` (JSDoc'd) or the generated TypeDoc site.

## CLI reference

See the [`chainproof invariants`](../README.md#chainproof-invariants) entry
in the main README for the flag table. All subcommands that emit a report
support `--format json` for machine-readable, diffable output; `check`'s
exit code is `1` iff any invariant `fail`ed or `error`ed.

## Diagnostic codes

| Code | Meaning |
| --- | --- |
| `DSL001` | Spec file is not valid JSON. |
| `DSL002` | Structural schema violation (wrong type, missing required field). |
| `DSL003` | Missing/unsupported `schemaVersion`. |
| `DSL004` | Condition/predicate expression failed to parse. |
| `DSL005` | Identifier doesn't resolve to a state variable, parameter, function, or known global. |
| `DSL006` | Unknown predicate or function call. |
| `DSL007` | Predicate called with arguments (predicates are zero-arity). |
| `DSL008` | Recursive predicate definition. |
| `DSL009` | Import cycle, or import depth exceeds the budget. |
| `DSL010` | Import target could not be read. |
| `DSL011` | Duplicate invariant `id`. |
| `DSL012` | `scope.contract` doesn't match any scanned contract. |
| `DSL013` | `scope.function` doesn't match any function on that contract. |
| `DSL014` | `scope.function` is ambiguous (overloaded) and `scope.signature` is missing or doesn't match. |
| `DSL015` | *(reserved for future stricter type checking)* |
| `DSL016` | Unknown/unsupported `kind`. |
| `DSL017` | Evaluation exceeded its bounded step/time budget. |
| `DSL018` | A spec/report artifact is structurally corrupt. |
| `DSL019` | No migration path from the given `schemaVersion`. |
| `DSL020` | A field required for this invariant `kind` is missing (e.g. `scope.function`, `order`, `event`). |

## Threat model & security assumptions

- **Deterministic by construction**: no network I/O, no randomness, no
  wall-clock-dependent behavior in the *result* (only in whether a bounded
  bail-out triggers).
- **False-negative biased**: the evaluator only reports `pass` when it finds
  a syntactically matching guard. It never tries to *prove* an invariant
  holds through reasoning it can't fully verify — an unmatched but
  semantically-valid guard reports `fail`, which is the safer failure mode
  for a security tool (a spec author sees a false alarm and can adjust the
  condition or the code; a false `pass` would hide a real gap).
- **Trusts the parser, not the source**: like the rest of ChainProof, this
  analyzes source text — it cannot see through proxies, off-chain
  components, or bytecode-level manipulation.
- **Assumptions are documentation, not verification**: the `assumptions`
  field is never evaluated. It exists so a spec author can record what the
  checker *can't* verify (e.g. "owner is never the zero address") — treat
  gaps between an invariant's assumptions and reality as spec-author
  responsibility, the same way a code comment is.

## Limitations

These are deliberate scope boundaries, not bugs:

- **No `old()`/`changed()` semantics.** They parse and type-check (useful
  for forward-compatible spec authoring) but evaluating them requires
  state-snapshot tracking this bounded evaluator doesn't do. Any invariant
  using them reports `status: "skipped"` with an explanatory message,
  never a guessed verdict.
- **Structural, not algebraic, equivalence.** See
  [Structural guard matching](#structural-guard-matching-precisely) above.
- **`value-flow` is single-hop.** It checks whether a state write derives
  *directly* from an unguarded parameter — it does not trace taint through
  intermediate local variables or across function calls. A vulnerability
  reachable only through an indirection will not be caught.
- **`call-order` is a two-point ordering check** on line numbers within one
  function body — it does not understand branches, loops, or early
  returns. A `before`/`after` pair inside different `if` branches will
  still be compared by raw line number.
- **No cross-contract invariants.** `scope.contract` is a single contract
  name per invariant; there's no way to express "Vault.totalAssets tracks
  Oracle.price" in one invariant today.
- **Predicates are zero-arity.** No parameterized/generic predicates in
  this schema version.

## Compatibility & migration

`schemaVersion` follows semver-shaped strings; `SUPPORTED_SPEC_SCHEMA_VERSIONS`
lists what this build parses directly. `chainproof invariants migrate` (or
`migrateInvariantSpecFile()`) upgrades an older shape — currently a
pre-release `"0.9"` shape (`rules[]` + `expr` + flat `contract`/`function`)
to `"1.0.0"` — and reports every transformation it applied. A file with
neither a recognized `schemaVersion` nor a known legacy shape throws
`MigrationError`; malformed/unreadable JSON throws `CorruptArtifactError`.
Both are typed errors from `@chainproof/core`, safe to catch and branch on.

`RESULT_SCHEMA_VERSION` versions the *output* shape (`InvariantCheckReport`)
independently of the spec's `schemaVersion` — a future evaluator change that
alters the report shape bumps this, not `CURRENT_SPEC_SCHEMA_VERSION`.

## Troubleshooting

**"unknown contract" (`DSL012`) even though the contract is in my file** —
`scope.contract` must match the Solidity `contract` name exactly, not the
filename. Check for a typo or a name collision across multiple targets.

**"is overloaded" (`DSL014`)** — add `scope.signature` with the exact
parameter type list, e.g. `"transfer(address,uint256)"`. Run
`chainproof invariants explain` after fixing — it echoes the resolved scope.

**An invariant I expect to `pass` reports `fail`** — the guard-matching is
structural, not semantic (see [Limitations](#limitations)). Run
`chainproof invariants explain <spec> <id>` to see the exact
predicate-expanded condition being matched, then compare it token-for-token
against your `require`/`assert` statement — a difference as small as
`a >= b` vs `a > b - 1` will not match.

**`status: "skipped"` with a message about `old()`/`changed()`** — expected;
see [Limitations](#limitations). Rephrase the invariant as a guard-based
check if possible, or track it manually until snapshot evaluation ships.

**`status: "timeout"`** — the invariant hit `maxStepsPerInvariant`. This
should only happen on pathological specs/contracts; if it happens on a
reasonably-sized contract, please file an issue — it likely indicates a
missing bound in a query rather than genuine complexity.

**CI passes locally but the report JSON differs between runs** — this
should never happen (see [Evaluation model](#evaluation-model)); if it
does, it's a determinism bug. Compare with `durationMs`/`generatedAt`
stripped first (those legitimately vary), then file an issue with both
reports attached.
