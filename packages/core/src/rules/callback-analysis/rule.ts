import type { ASTNode, Finding, FindingEvidenceItem } from "../../types";
import type { MergedContractView } from "../../ast/import-graph";
import { applyFindingContext, type RuleOptions } from "../rule-context";
import { buildFunctionCallGraph } from "../call-graph";
import { analyzableFunctionsFromView, buildCallbackGraph } from "./callback-graph";
import { evaluateGuards, isSuppressedByGuards } from "./guards";
import { detectCallbackSpoofing } from "./spoofing";
import {
  collectStateAccesses,
  varsReadBeforeLineWithoutPriorWrite,
  varsWrittenAtOrAfterLine,
} from "./state-access";
import type { AnalyzableFunction, CallbackEdge, GuardEvidence, InterfaceEvidence } from "./types";

const STANDARD_LABEL: Record<CallbackEdge["standard"], string> = {
  ERC721: "ERC-721",
  ERC1155: "ERC-1155",
  ERC777: "ERC-777",
  ERC3156: "ERC-3156 flash loan",
  CUSTOM: "custom",
};

function lineSnippet(source: string, line: number): string {
  if (!line) return "";
  const lines = source.split("\n");
  return (lines[line - 1] ?? "").trim();
}

function toEvidenceItems(items: InterfaceEvidence[], file: string): FindingEvidenceItem[] {
  return items.map((e) => ({ description: `[${e.confidence}] ${e.detail}`, file, line: e.line }));
}

function guardAssumptions(guards: GuardEvidence[]): string[] {
  return guards.map((g) => `Assumed satisfied: ${g.detail}`);
}

function callPathFor(edge: CallbackEdge): string[] {
  return edge.viaPath;
}

function fnStateMutability(fn: AnalyzableFunction): string | null {
  return (fn.node as { stateMutability?: string | null }).stateMutability ?? null;
}

/**
 * CP-90 callback/hook reentrancy analysis: models standards-mandated
 * implicit callback edges (ERC-721/1155 receiver hooks, ERC-777
 * sender/receiver hooks, ERC-3156-style flash-loan callbacks, and
 * project-defined callback registration) and evaluates each one for:
 *
 *  - incomplete state updates before the callback (CP-CB-CEI),
 *  - cross-function reentrancy entered through the callback (CP-CB-CROSSFN),
 *  - read-only reentrancy exposed through a `view` getter (CP-CB-READONLY),
 *  - unauthenticated callback-spoofing entry points (CP-CB-SPOOF), and
 *  - unbounded batch callbacks (CP-CB-BATCH).
 *
 * Findings are suppressed when a recognized guard (reentrancy-guard
 * modifier, hand-rolled mutex, trusted-receiver allowlist, EOA-only check,
 * or — for flash-callbacks specifically — an atomic repayment/invariant
 * check) applies to the edge; the guard is instead recorded as an
 * assumption on any finding it doesn't fully suppress.
 *
 * Requires a {@link MergedContractView} (via `options.contractView`) to run
 * its call-graph-based analysis; returns no findings without one, matching
 * {@link import("../swc107-reentrancy-v2").detectCrossFunctionReentrancy}.
 */
export function detectCallbackReentrancy(
  _ast: ASTNode,
  _source: string,
  filePath: string,
  options?: RuleOptions,
): Finding[] {
  const view = options?.contractView;
  if (!view) return [];

  const functions = analyzableFunctionsFromView(view);
  if (functions.length === 0) return [];

  const stateVarNames = new Set(view.members.filter((m) => m.kind === "stateVariable").map((m) => m.name));
  const byName = new Map(functions.map((f) => [f.name, f]));

  const callGraph = buildFunctionCallGraph(view);
  const callbackGraph = buildCallbackGraph(view, callGraph);

  const findings: Finding[] = [];

  if (callbackGraph.truncated) {
    findings.push(
      applyFindingContext(
        {
          id: "CP-CB-TRUNCATED",
          title: "Callback analysis truncated for this contract",
          description:
            "The callback/hook reentrancy analysis stopped exploring the call graph after hitting its " +
            "bounded traversal budget. Results for this contract may be incomplete.",
          recommendation:
            "Consider splitting very large contracts into smaller units, or re-run analysis focused on " +
            "the specific functions of interest.",
          severity: "info",
          file: filePath,
          line: 1,
          confidence: "high",
          assumptions: ["Traversal budget exceeded; some callback paths may not have been analyzed."],
        },
        undefined,
        view,
      ),
    );
  }

  for (const edge of callbackGraph.edges) {
    const entryFn = byName.get(edge.entryFunction);
    const triggerFn = byName.get(edge.triggerFunction);
    if (!entryFn || !triggerFn) continue;

    const guards = evaluateGuards(entryFn, edge);
    const suppressed = isSuppressedByGuards(guards, edge.kind);

    if (edge.kind === "flash-callback") {
      if (!suppressed) {
        findings.push(buildFlashCallbackFinding(entryFn, edge, guards, filePath, view));
      }
      continue;
    }

    if (edge.isBatch && edge.isUnboundedBatch && !suppressed) {
      findings.push(buildBatchFinding(entryFn, triggerFn, edge, guards, filePath, view));
    }

    if (suppressed) continue;

    const accesses = collectStateAccesses(entryFn.node, stateVarNames);
    const staleReadCandidates = varsReadBeforeLineWithoutPriorWrite(accesses, edge.entryCallSiteLine);
    const finalizedAfterCall = varsWrittenAtOrAfterLine(accesses, edge.entryCallSiteLine);

    if (finalizedAfterCall.size > 0) {
      findings.push(
        buildCeiFinding(entryFn, triggerFn, edge, guards, [...finalizedAfterCall], filePath, view),
      );
    }

    if (staleReadCandidates.size > 0 || finalizedAfterCall.size > 0) {
      for (const sibling of functions) {
        if (sibling.name === entryFn.name) continue;
        const isView = fnStateMutability(sibling) === "view";
        const siblingAccesses = collectStateAccesses(sibling.node, stateVarNames);
        const siblingVarNames = new Set(siblingAccesses.map((a) => a.varName));

        if (isView) {
          // Read-only reentrancy: a `view` function exposes a value that
          // entryFn only finalizes *after* handing control to the callback.
          const touchedVars = [...finalizedAfterCall].filter((v) => siblingVarNames.has(v));
          if (touchedVars.length > 0) {
            findings.push(
              buildReadOnlyFinding(entryFn, sibling, edge, guards, touchedVars, filePath, view),
            );
          }
        } else {
          // Cross-function reentrancy: a mutating sibling touches state
          // entryFn read before the callback without having finalized it
          // first, so re-entering through that sibling observes/produces
          // an inconsistent value.
          const touchedVars = [...staleReadCandidates].filter((v) => siblingVarNames.has(v));
          if (touchedVars.length > 0) {
            findings.push(
              buildCrossFunctionFinding(entryFn, sibling, edge, guards, touchedVars, filePath, view),
            );
          }
        }
      }
    }
  }

  const spoofingHits = detectCallbackSpoofing(functions, stateVarNames);
  for (const hit of spoofingHits) {
    findings.push(
      applyFindingContext(
        {
          id: "CP-CB-SPOOF",
          title: `Unauthenticated callback: ${hit.hookName}`,
          description:
            `"${hit.hookName}" is ${hit.isStandardHook ? "a standard receiver-hook" : "a hook-shaped function"} ` +
            `that mutates sensitive state (${hit.sensitiveVars.join(", ")}) without verifying that ` +
            `msg.sender is the token/vault/operator contract it expects to be called back by. Any address ` +
            "can call this function directly and make the contract believe a transfer/deposit happened.",
          recommendation:
            `Verify the caller inside "${hit.hookName}" (e.g. require(msg.sender == expectedToken)) before ` +
            "trusting its arguments, or restrict it with an auth modifier bound to the expected caller.",
          severity: "high",
          file: filePath,
          line: hit.line,
          snippet: lineSnippet(hit.fn.source, hit.line),
          confidence: hit.isStandardHook ? "high" : "medium",
          evidence: [
            {
              description: hit.isStandardHook
                ? `Function name/signature matches the standard hook "${hit.hookName}"`
                : `Function name "${hit.hookName}" matches callback-hook naming convention`,
            },
          ],
        },
        hit.fn.member,
        view,
      ),
    );
  }

  return findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.id.localeCompare(b.id));
}

function buildCeiFinding(
  entryFn: AnalyzableFunction,
  triggerFn: AnalyzableFunction,
  edge: CallbackEdge,
  guards: GuardEvidence[],
  incompleteVars: string[],
  filePath: string,
  view: MergedContractView,
): Finding {
  const standard = STANDARD_LABEL[edge.standard];
  return applyFindingContext(
    {
      id: "CP-CB-CEI",
      title: `Incomplete state update before ${standard} callback`,
      description:
        `Function "${entryFn.name}" leaves state variable(s) ${incompleteVars.join(", ")} unfinalized ` +
        `before invoking the ${standard} ${edge.kind.replace("-", " ")} (in "${triggerFn.name}"${
          edge.viaPath.length > 1 ? ` via ${edge.viaPath.join(" → ")}` : ""
        }, line ${edge.line}). The callback hands control to an address the contract does not control; ` +
        "if that address is a malicious contract, it can re-enter before these variables are finalized.",
      recommendation:
        "Apply Checks-Effects-Interactions: finalize all state writes before invoking the callback. " +
        "If the callback is intentionally atomic (e.g. a flash mint), add an explicit post-callback " +
        "invariant check instead of relying on ordering alone.",
      severity: "critical",
      file: filePath,
      line: edge.entryCallSiteLine,
      snippet: lineSnippet(entryFn.source, edge.entryCallSiteLine),
      callPath: callPathFor(edge),
      confidence: edge.evidence[0]?.confidence ?? "medium",
      evidence: toEvidenceItems(edge.evidence, filePath),
      assumptions: guardAssumptions(guards),
    },
    entryFn.member,
    view,
  );
}

function buildCrossFunctionFinding(
  entryFn: AnalyzableFunction,
  sibling: AnalyzableFunction,
  edge: CallbackEdge,
  guards: GuardEvidence[],
  vars: string[],
  filePath: string,
  view: MergedContractView,
): Finding {
  const standard = STANDARD_LABEL[edge.standard];
  return applyFindingContext(
    {
      id: "CP-CB-CROSSFN",
      title: `Cross-function reentrancy via ${standard} callback`,
      description:
        `"${entryFn.name}" invokes a ${standard} ${edge.kind.replace("-", " ")} before finalizing ${vars.join(", ")}. ` +
        `Re-entering through "${sibling.name}" during that callback lets an attacker read or mutate state that ` +
        `"${entryFn.name}" has not yet updated.`,
      recommendation:
        "Finalize all state used by other functions before making the callback, or apply a reentrancy " +
        "guard shared across the affected functions.",
      severity: "critical",
      file: filePath,
      line: edge.entryCallSiteLine,
      snippet: lineSnippet(entryFn.source, edge.entryCallSiteLine),
      callPath: [...callPathFor(edge), sibling.name],
      confidence: edge.evidence[0]?.confidence ?? "medium",
      evidence: toEvidenceItems(edge.evidence, filePath),
      assumptions: guardAssumptions(guards),
    },
    entryFn.member,
    view,
  );
}

function buildReadOnlyFinding(
  entryFn: AnalyzableFunction,
  sibling: AnalyzableFunction,
  edge: CallbackEdge,
  guards: GuardEvidence[],
  vars: string[],
  filePath: string,
  view: MergedContractView,
): Finding {
  const standard = STANDARD_LABEL[edge.standard];
  return applyFindingContext(
    {
      id: "CP-CB-READONLY",
      title: `Read-only reentrancy via ${standard} callback`,
      description:
        `View function "${sibling.name}" reads ${vars.join(", ")}, which "${entryFn.name}" only finalizes after ` +
        `invoking a ${standard} ${edge.kind.replace("-", " ")}. An integrator calling "${sibling.name}" during the ` +
        "callback observes a stale/inconsistent value even though the call itself cannot revert or lock funds — " +
        "the classic read-only reentrancy pattern used to manipulate price/exchange-rate oracles.",
      recommendation:
        `Either finalize ${vars.join(", ")} before the callback, or make "${sibling.name}" revert while a ` +
        "reentrancy guard is active (OpenZeppelin's ReentrancyGuard exposes a view-safe check for this).",
      severity: "high",
      file: filePath,
      line: edge.entryCallSiteLine,
      snippet: lineSnippet(entryFn.source, edge.entryCallSiteLine),
      callPath: [...callPathFor(edge), sibling.name],
      confidence: "medium",
      evidence: toEvidenceItems(edge.evidence, filePath),
      assumptions: [
        `"${sibling.name}" is assumed to be consumed off-chain or by another on-chain integrator during the callback.`,
        ...guardAssumptions(guards),
      ],
    },
    entryFn.member,
    view,
  );
}

function buildBatchFinding(
  entryFn: AnalyzableFunction,
  triggerFn: AnalyzableFunction,
  edge: CallbackEdge,
  guards: GuardEvidence[],
  filePath: string,
  view: MergedContractView,
): Finding {
  const standard = STANDARD_LABEL[edge.standard];
  return applyFindingContext(
    {
      id: "CP-CB-BATCH",
      title: `Unbounded batch ${standard} callback`,
      description:
        `"${entryFn.name}" invokes a ${standard} callback once per loop iteration (via "${triggerFn.name}") ` +
        "over a caller-supplied array with no explicit upper bound. Besides the per-iteration reentrancy " +
        "surface this multiplies, an attacker can supply an oversized array to grief the transaction (gas " +
        "exhaustion / block-gas-limit denial of service).",
      recommendation:
        "Cap the batch size with an explicit require(array.length <= MAX_BATCH_SIZE) before the loop, or " +
        "restructure to a pull-based per-item claim pattern.",
      severity: "medium",
      file: filePath,
      line: edge.entryCallSiteLine,
      snippet: lineSnippet(entryFn.source, edge.entryCallSiteLine),
      callPath: callPathFor(edge),
      confidence: "medium",
      evidence: toEvidenceItems(edge.evidence, filePath),
      assumptions: guardAssumptions(guards),
    },
    entryFn.member,
    view,
  );
}

function buildFlashCallbackFinding(
  entryFn: AnalyzableFunction,
  edge: CallbackEdge,
  guards: GuardEvidence[],
  filePath: string,
  view: MergedContractView,
): Finding {
  return applyFindingContext(
    {
      id: "CP-CB-CEI",
      title: "Flash-loan/mint callback missing repayment invariant check",
      description:
        `"${entryFn.name}" invokes a flash-loan/mint style callback (line ${edge.line}) without a detectable ` +
        "post-callback invariant check (e.g. verifying the balance increased by at least the borrowed amount " +
        "plus fee). Without this check, the atomicity guarantee flash-loan safety depends on does not hold.",
      recommendation:
        "Add an explicit post-callback check, e.g. require(token.balanceOf(address(this)) >= balanceBefore + " +
        "amount + fee), or verify the borrower's return value against the expected ERC-3156 magic value.",
      severity: "critical",
      file: filePath,
      line: edge.entryCallSiteLine,
      snippet: lineSnippet(entryFn.source, edge.entryCallSiteLine),
      callPath: callPathFor(edge),
      confidence: edge.evidence[0]?.confidence ?? "medium",
      evidence: toEvidenceItems(edge.evidence, filePath),
      assumptions: [
        "A flash-loan/mint callback is expected to be atomic by design; this only fires when no repayment " +
          "invariant check was found.",
        ...guardAssumptions(guards),
      ],
    },
    entryFn.member,
    view,
  );
}

