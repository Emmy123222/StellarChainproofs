import type { ASTNode } from "../../types";
import type { MergedMember } from "../../ast/import-graph";

/**
 * How certain the analysis is about a piece of evidence or a finding.
 * `high` — structural/signature match (e.g. exact standard function selector).
 * `medium` — strong heuristic (e.g. naming convention + behavior match).
 * `low` — weak heuristic offered for triage, not auto-actionable.
 */
export type Confidence = "high" | "medium" | "low";

/**
 * ERC/EIP standard whose callback semantics produced a given edge or finding.
 * `CUSTOM` covers project-specific hook/callback registration patterns that
 * don't map to a ratified standard (e.g. `onTokenTransfer`, bespoke
 * `IHook.onCallback`, or Aave-style `executeOperation`).
 */
export type CallbackStandard = "ERC721" | "ERC1155" | "ERC777" | "ERC3156" | "CUSTOM";

/**
 * The shape of the implicit control-flow edge a callback introduces.
 */
export type CallbackKind =
  | "receiver-hook" // onERC721Received / onERC1155Received / tokensReceived
  | "batch-receiver-hook" // onERC1155BatchReceived and loop-driven batch acceptance checks
  | "sender-hook" // ERC-777 tokensToSend (pre-transfer hook on the sender side)
  | "flash-callback" // ERC-3156 onFlashLoan / Aave-style executeOperation
  | "fallback" // raw call/transfer/send that may hit a receive/fallback function
  | "custom-hook"; // project-defined callback registration (IHook, transferAndCall, ...)

/**
 * A single piece of evidence supporting an interface/standard-detection
 * conclusion. Findings carry a list of these so a reviewer can see *why*
 * the analysis believes a given callback path exists, without having to
 * re-derive it from the source.
 */
export interface InterfaceEvidence {
  kind:
    | "function-signature"
    | "erc165-selector"
    | "low-level-selector"
    | "helper-name"
    | "naming-heuristic";
  detail: string;
  confidence: Confidence;
  line?: number;
}

/**
 * One place in the contract where control implicitly leaves to an
 * attacker-influenceable address as part of a standard token/vault
 * operation (not a raw low-level call, but a spec-mandated hook).
 */
export interface CallbackEdge {
  /** Name of the function whose external, standards-mandated entry point this is. */
  entryFunction: string;
  /** Name of the function whose body actually contains the callback statement. */
  triggerFunction: string;
  /** Call chain from entryFunction to triggerFunction (both inclusive; length 1 when they're the same). */
  viaPath: string[];
  standard: CallbackStandard;
  kind: CallbackKind;
  /** 1-indexed source line of the triggering statement, inside triggerFunction's own body. */
  line: number;
  /**
   * 1-indexed line, inside entryFunction's own body, where control first
   * hands off toward the callback (equal to `line` when entryFunction ===
   * triggerFunction). This is the line CEI-style analyses use as their
   * "before/after" cutoff, since it's the point beyond which entryFunction's
   * own state writes become exposed to reentrancy.
   */
  entryCallSiteLine: number;
  /** True when the callback is invoked once per loop iteration (batch operation). */
  isBatch: boolean;
  /** True when a batch callback's iteration count has no provable upper bound. */
  isUnboundedBatch: boolean;
  evidence: InterfaceEvidence[];
}

export interface CallbackGraph {
  edges: CallbackEdge[];
  byEntryFunction: Map<string, CallbackEdge[]>;
  /**
   * Function name -> evidence, for functions *implemented by this contract*
   * that match a known receiver/callback hook signature (i.e. this contract
   * is itself a callback target for some other token/vault).
   */
  implementedHooks: Map<string, InterfaceEvidence[]>;
  /** True if {@link walkWithLoopContext}'s node budget was exhausted while building this graph. */
  truncated: boolean;
}

export type GuardKind =
  | "reentrancy-guard-modifier"
  | "manual-mutex"
  | "trusted-receiver-allowlist"
  | "eoa-only-check"
  | "atomic-invariant-check";

export interface GuardEvidence {
  kind: GuardKind;
  detail: string;
  line?: number;
}

export interface StateAccessRecord {
  varName: string;
  line: number;
  isWrite: boolean;
}

/** Minimal shape shared by both AST-only functions and merged-view members. */
export interface AnalyzableFunction {
  name: string;
  node: ASTNode;
  source: string;
  definedIn?: string;
  /** Present when built from a {@link MergedContractView} (import-graph-aware analysis). */
  member?: MergedMember;
}
