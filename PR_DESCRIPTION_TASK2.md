## Summary

Closes #84.

Implements Task 2: a production-grade, deterministic governance, timelock, multisig, and proposal
execution safety analyzer for ChainProof.

## What changed

- Added a normalized governance state-transition/data-flow model and framework adapters for
  OpenZeppelin Governor/TimelockController, Compound Governor Bravo, Safe-style multisigs, and
  cross-chain governance receivers.
- Added 16 evidence-backed rules (`CP-GOV-001`–`CP-GOV-016`) covering live/same-block voting power,
  snapshots, quorum/window math, timelock readiness, replay, complete proposal/operation identity,
  arbitrary target/value/calldata flow, guardian bypasses, delay updates, predecessors, salts, role
  separation, upgrades, cross-chain domains, and threshold signatures.
- Added bounded/cancellable public APIs, schema-versioned deterministic JSON/Markdown reports,
  sanitized diagnostics, configuration validation, and v0→v1 migration.
- Added `chainproof governance` with rule selection, resource limits, model output, report artifacts,
  and configurable CI severity exit thresholds.
- Integrated governance findings into the normal scanner exactly once per physical file.
- Added paired secure/vulnerable fixtures and comprehensive core/scanner/CLI tests.
- Added user/developer documentation and fixed clean-checkout lint/build ordering.

## Scope

The analyzer reports structural implementation safety. It does not score political legitimacy,
voter preferences, or proposal outcomes.

## Architecture and security boundaries

`model.ts` performs a bounded, cycle-safe AST walk and emits semantic state/transition/operation
records. `adapters.ts` recognizes framework structure without treating a name as proof of safety.
`analyzer.ts` runs pure rules over that model; `api.ts` owns budgets, cancellation, deterministic
ordering, and sanitized filesystem diagnostics; `serialize.ts` and the CLI are transport/presentation
only. The feature performs no RPC, network, package download, compiler subprocess, symbolic
execution, or provider call. Deployment role membership, bridge finality/authenticity, economic
adequacy, and political outcomes remain outside the static source boundary.

## Precision / recall considerations

- A cheap, comment/string-stripped governance prefilter protects ordinary scan performance; the
  dedicated API skips it and can model generic implementations directly.
- Findings require semantic function/state roles plus ordered guards, writes, calls, or parameter
  taint. Framework adapters suppress only mitigations visible in source.
- Secure checkpointed Governor, predecessor-aware/salted TimelockController, Safe-style multisig,
  and domain-separated cross-chain fixtures are zero-finding false-positive controls.
- Unresolved inherited modifiers, assembly/computed selectors, proxy storage aliases, deployment
  configuration, and external bridge/token behavior may require manual review and are documented.

## Performance

Local Node.js benchmark on the final implementation (100 copies of `VulnerableGovernor.sol`, 1,024
finding cap): **599.2 ms**, **17.4 MiB heap delta**. Preflight source/contract/function checks and
per-function operation, per-finding evidence, project file, and total finding limits provide
deterministic adversarial bounds. Regression tests enforce early contract limiting, an eight-operation
cap on a 200-statement function, cancellation, and a 5-second guardrail for the bounded fixture.

## Validation

- `npm run build`
- `npm test`
- `npm run lint`
- `npm run test:ci --workspace=packages/core`
- affected workspace builds/tests and TypeDoc generation

Latest local evidence after updating from target `master`: **41 core suites / 332 tests** and
**6 CLI suites / 24 tests** pass. Core coverage is 83.9% statements overall and 91.78% statements
for `src/governance`.

## Follow-up work

- Add cross-file modifier/body expansion to the governance model using the shared import graph.
- Add optional deployment-manifest checks for concrete role membership and open-executor policy.
- Add assembly-aware selector/value-flow summaries while retaining the current bounded guarantees.

## Review guide

1. Start with `packages/core/src/governance/model.ts` and `analyzer.ts`.
2. Review deterministic bounds/config/reporting in `api.ts`, `config.ts`, and `serialize.ts`.
3. Exercise `chainproof governance examples/contracts/governance --format json --fail-on none`.
4. Compare the vulnerable and secure fixtures under `examples/contracts/governance/`.
