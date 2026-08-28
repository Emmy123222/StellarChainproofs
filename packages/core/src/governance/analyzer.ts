import type {
  GovernanceAnalysisOptions,
  GovernanceContractModel,
  GovernanceEvidence,
  GovernanceFinding,
  GovernanceOperation,
  GovernanceRuleId,
  GovernanceStateVariable,
  GovernanceTransition,
  GovernanceVariableRole,
} from "./types";

type Rule = (model: GovernanceContractModel) => GovernanceFinding[];

const RULE_ORDER: readonly GovernanceRuleId[] = Array.from({ length: 16 }, (_, index) =>
  `CP-GOV-${String(index + 1).padStart(3, "0")}` as GovernanceRuleId,
);

const RULES: Record<GovernanceRuleId, Rule> = {
  "CP-GOV-001": detectLiveBalanceVoting,
  "CP-GOV-002": detectSameBlockVoting,
  "CP-GOV-003": detectWeakQuorumArithmetic,
  "CP-GOV-004": detectUnsafeVotingWindow,
  "CP-GOV-005": detectMissingTimelockReadiness,
  "CP-GOV-006": detectReplayableExecution,
  "CP-GOV-007": detectIncompleteProposalIdentity,
  "CP-GOV-008": detectArbitraryProposalExecution,
  "CP-GOV-009": detectGuardianBypass,
  "CP-GOV-010": detectUnsafeDelayUpdate,
  "CP-GOV-011": detectMissingPredecessorDependency,
  "CP-GOV-012": detectSaltCollision,
  "CP-GOV-013": detectCollapsedRoles,
  "CP-GOV-014": detectProposalControlledUpgrade,
  "CP-GOV-015": detectCrossChainReplay,
  "CP-GOV-016": detectWeakMultisigExecution,
};

export function analyzeGovernanceModel(
  model: GovernanceContractModel,
  options: GovernanceAnalysisOptions = {},
): GovernanceFinding[] {
  const include = options.includeRules ? new Set(options.includeRules) : null;
  const exclude = new Set(options.excludeRules ?? []);
  const findings: GovernanceFinding[] = [];
  for (const id of RULE_ORDER) {
    if (include && !include.has(id)) continue;
    if (exclude.has(id)) continue;
    findings.push(...RULES[id](model));
  }
  return findings.sort(compareFindings);
}

function detectLiveBalanceVoting(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["voting-power", "cast-vote"])) {
    const balanceCall = transition.operations.find((operation) =>
      operation.kind === "call" && operation.name.toLowerCase() === "balanceof",
    );
    if (!balanceCall) continue;
    const source = codeText(transition.source);
    if (/getpastvotes|getpriorvotes|checkpoints?\s*\[/i.test(source)) continue;
    findings.push(finding({
      ruleId: "CP-GOV-001",
      title: `Live token balance determines voting power in ${transition.name}`,
      description:
        "Voting weight is read from the token's current balance rather than a proposal snapshot. " +
        "Borrowed or temporarily transferred tokens can vote and then leave without preserving the " +
        "economic state on which the vote was authorized.",
      recommendation:
        "Use checkpointed delegated voting and query getPastVotes/getPriorVotes at a proposal snapshot " +
        "strictly before the current block. Keep the snapshot fixed for the entire voting period.",
      severity: "critical",
      confidence: "high",
      category: "voting-power",
      model,
      transition,
      evidence: [operationEvidence(balanceCall, "Voting path reads a live token balance")],
      assumptions: ["Governance tokens can be transferred or borrowed during the voting lifecycle"],
    }));
  }
  return findings;
}

function detectSameBlockVoting(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["cast-vote", "voting-power"])) {
    const source = codeText(transition.source);
    const usesCurrentBlock = /\bblock\.number\b/.test(source) &&
      !/block\.number\s*-\s*1/.test(source) && !/getPastVotes|getPriorVotes/i.test(source) &&
      !/proposalSnapshot|snapshotBlock|startBlock/i.test(source);
    const currentVoteCall = transition.operations.find((operation) =>
      operation.kind === "call" && /getvotes|getpastvotes|getpriorvotes/i.test(operation.name) &&
      /block\.number/.test(operation.expression) && !/block\.number\s*-\s*1/.test(operation.expression),
    );
    if (!usesCurrentBlock && !currentVoteCall) continue;
    findings.push(finding({
      ruleId: "CP-GOV-002",
      title: `Voting power can be acquired and used in the same block`,
      description:
        `${transition.name} resolves voting power at the current block rather than a finalized earlier ` +
        "snapshot. A flash-loan or atomic delegation can therefore acquire voting power, cast a vote, " +
        "and unwind before the transaction or block completes.",
      recommendation:
        "Set proposal snapshots at least one block after creation and only query finalized checkpoints " +
        "from a block strictly less than block.number. Reject future/current timepoints in vote tokens.",
      severity: "critical",
      confidence: "high",
      category: "voting-power",
      model,
      transition,
      evidence: currentVoteCall
        ? [operationEvidence(currentVoteCall, "Vote lookup uses the current block")]
        : [absenceEvidence(transition, "Current-block lookup has no earlier proposal snapshot")],
      assumptions: ["Voting power can be delegated or borrowed atomically"],
    }));
  }
  return findings;
}

function detectWeakQuorumArithmetic(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  const quorumVariables = variables(model, ["quorum", "quorum-numerator", "quorum-denominator"]);
  for (const transition of byRoles(model, ["quorum", "proposal-state"])) {
    const badDivision = transition.operations.find((operation) =>
      operation.kind === "arithmetic" && divisionBeforeMultiplication(operation.expression),
    );
    const source = codeText(transition.source);
    const zeroAcceptance = /(?:quorum|threshold)\s*(?:==|<=)\s*0|return\s+0\s*;/i.test(source);
    if (!badDivision && !zeroAcceptance) continue;
    findings.push(finding({
      ruleId: "CP-GOV-003",
      title: `Quorum or threshold arithmetic can collapse to zero`,
      description:
        "Governance acceptance math truncates before multiplication or explicitly permits a zero " +
        "threshold. Small supplies and low numerator values can reduce the required participation to " +
        "zero or materially below the configured fraction.",
      recommendation:
        "Multiply total checkpointed supply by the quorum numerator before division using full-precision " +
        "mulDiv, require a non-zero denominator and result, and define inclusive boundary behavior.",
      severity: "high",
      confidence: "high",
      category: "quorum-threshold",
      model,
      transition,
      evidence: [
        ...(badDivision ? [operationEvidence(badDivision, "Division occurs before quorum multiplication")] : []),
        ...(quorumVariables[0] ? [variableEvidence(quorumVariables[0], "Governance quorum state")] : []),
      ],
      assumptions: ["Solidity integer truncation applies to the quorum calculation"],
    }));
  }
  return findings;
}

function detectUnsafeVotingWindow(model: GovernanceContractModel): GovernanceFinding[] {
  const proposals = byRoles(model, ["propose"]);
  if (!proposals.length) return [];
  const delays = variables(model, ["voting-delay"]);
  const periods = variables(model, ["voting-period"]);
  const findings: GovernanceFinding[] = [];
  for (const transition of proposals) {
    const source = codeText(transition.source);
    const sameBlockWindow = /(?:startBlock|voteStart|snapshot)\s*=\s*block\.number[^;]*;[^}]*(?:endBlock|deadline)\s*=\s*block\.number\s*;/i.test(source);
    if (delays.length && periods.length && !sameBlockWindow) continue;
    findings.push(finding({
      ruleId: "CP-GOV-004",
      title: "Proposal lifecycle lacks a complete non-zero voting window",
      description:
        "Proposal creation does not expose both an independent voting delay and voting period, or " +
        "sets snapshot and deadline to the same block. Reviewers and delegates may have no stable " +
        "interval in which to observe, delegate, and vote on the proposal.",
      recommendation:
        "Persist a future snapshot and a strictly later deadline. Validate votingDelay > 0 and " +
        "votingPeriod > 0 at configuration and proposal creation boundaries.",
      severity: "high",
      confidence: delays.length || periods.length ? "medium" : "high",
      category: "proposal-lifecycle",
      model,
      transition,
      evidence: [absenceEvidence(transition, "A complete delayed voting window was not modeled")],
      assumptions: ["Proposal creation is expected to provide delegates time to react"],
    }));
  }
  return findings;
}

function detectMissingTimelockReadiness(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["execute", "multisig-execute"])) {
    const call = privilegedCall(transition);
    if (!call || transition.role === "multisig-execute") continue;
    const ready = hasTimelockReadiness(transition);
    if (ready) continue;
    findings.push(finding({
      ruleId: "CP-GOV-005",
      title: `Proposal execution has no queued timelock readiness proof`,
      description:
        `${transition.name} reaches a privileged external call without proving that the proposal was ` +
        "queued and its execution delay elapsed. A passing vote or privileged caller can execute " +
        "immediately, removing the reaction period expected from governance.",
      recommendation:
        "Require a proposal-specific queued operation ID, eta, and ready state from a timelock. Consume " +
        "the queued operation before the call and enforce grace-period/expiry policy explicitly.",
      severity: "critical",
      confidence: "high",
      category: "timelock",
      model,
      transition,
      evidence: [
        operationEvidence(call, "Privileged external call is reachable"),
        absenceEvidence(transition, "No queued-operation readiness guard was identified"),
      ],
      assumptions: ["Governance execution is intended to be delayed after approval"],
    }));
  }
  return findings;
}

function detectReplayableExecution(model: GovernanceContractModel): GovernanceFinding[] {
  const executed = new Set(variables(model, ["executed-state", "operation-hash", "nonce"]).map((item) => item.name));
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["execute", "multisig-execute"])) {
    const call = privilegedCall(transition);
    if (!call) continue;
    const write = firstWrite(transition, executed);
    const guard = transition.operations.find((operation) =>
      operation.kind === "guard" && [...executed].some((name) => operation.expression.includes(name)),
    );
    const signedNonce = transition.role === "multisig-execute" && write && write.order < call.order &&
      /checksignatures|validatesignatures|recover\s*\(/i.test(codeText(transition.source)) &&
      /\bnonce\b/i.test(codeText(transition.source));
    if ((guard && write && write.order < call.order) || signedNonce) continue;
    findings.push(finding({
      ruleId: "CP-GOV-006",
      title: `Proposal or transaction can be replayed through ${transition.name}`,
      description:
        "Execution does not both reject an already-consumed proposal/nonce and mark it consumed before " +
        "the external interaction. The same approved action can be replayed directly or through reentry.",
      recommendation:
        "Bind execution to a unique proposal/operation hash or nonce, require it unused, and consume it " +
        "before external calls. Preserve the consumed state even when actions contain callbacks.",
      severity: "critical",
      confidence: "high",
      category: "replay",
      model,
      transition,
      evidence: [
        operationEvidence(call, "External proposal action executes"),
        ...(write ? [operationEvidence(write, "Consumption state is written after or without a guard")] :
          [absenceEvidence(transition, "No proposal/operation consumption write was identified")]),
      ],
      assumptions: ["The same execution parameters can be submitted more than once"],
    }));
  }
  return findings;
}

function detectIncompleteProposalIdentity(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["hash-proposal"])) {
    const actionParameters = transition.parameters.filter((parameter) =>
      /target|value|calldata|signature|description|salt/i.test(parameter),
    );
    const missing = actionParameters.filter((parameter) =>
      !new RegExp(`\\b${escapeRegExp(parameter)}\\b`).test(codeText(transition.source).replace(/function[^{]+{/, "")),
    );
    if (!missing.length) continue;
    findings.push(finding({
      ruleId: "CP-GOV-007",
      title: "Proposal identity omits action-defining fields",
      description:
        `The proposal hash omits ${missing.join(", ")}. Distinct or duplicate action batches can ` +
        "share an identifier, overwrite state, reuse approvals, or execute calldata different from " +
        "what voters reviewed.",
      recommendation:
        "Hash the complete ordered targets, values, calldata/signatures, description hash, predecessor, " +
        "salt, and domain as applicable. Reject duplicate action tuples in one proposal.",
      severity: "high",
      confidence: "high",
      category: "proposal-lifecycle",
      model,
      transition,
      evidence: [absenceEvidence(transition, `Hash body omits: ${missing.join(", ")}`)],
      assumptions: ["The hash is used as the authoritative proposal identity"],
    }));
  }
  for (const transition of byRoles(model, ["execute"])) {
    const seen = new Map<string, GovernanceOperation>();
    for (const operation of transition.operations.filter((item) =>
      item.kind === "call" && /call|delegatecall|functioncall|execute|upgradeto/i.test(item.name),
    )) {
      const identity = operation.expression.replace(/\s+/g, " ").trim();
      const previous = seen.get(identity);
      if (!previous) {
        seen.set(identity, operation);
        continue;
      }
      findings.push(finding({
        ruleId: "CP-GOV-007",
        title: "Proposal execution contains a duplicate action",
        description:
          "The same target/value/calldata expression is executed more than once in one proposal path. " +
          "A duplicated transfer or privileged selector can apply an approved state transition twice.",
        recommendation:
          "Reject duplicate action tuples during proposal creation and bind the ordered, length-prefixed " +
          "action array into the proposal hash. If repetition is intentional, document and test it explicitly.",
        severity: "high",
        confidence: "high",
        category: "proposal-lifecycle",
        model,
        transition,
        location: operation.location,
        evidence: [
          operationEvidence(previous, "First occurrence of the proposal action"),
          operationEvidence(operation, "Duplicate occurrence of the same proposal action"),
        ],
        assumptions: ["Both statically identical actions are reachable in the same execution"],
      }));
    }
  }
  return findings;
}

function detectArbitraryProposalExecution(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["execute"])) {
    const call = transition.operations.find((operation) =>
      operation.kind === "call" && operation.parameterSources.some((name) => /target|value|data|calldata/i.test(name)) &&
      /call|execute|functioncall/i.test(operation.name),
    );
    if (!call) continue;
    const source = codeText(transition.source);
    const bounded = /isoperationready|timelock|allowlist|whitelist|approvedtarget/i.test(source) ||
      hasTimelockReadiness(transition);
    if (bounded) continue;
    findings.push(finding({
      ruleId: "CP-GOV-008",
      title: "Proposal-controlled target, value, and calldata reach an arbitrary call",
      description:
        "Action parameters controlled by a proposal flow directly into a privileged low-level call " +
        "without a timelock or target/selector policy. Any governance capture immediately becomes " +
        "arbitrary asset transfer, configuration, or authorization control.",
      recommendation:
        "Execute only operation hashes queued in a separate timelock, bind the complete calldata/value " +
        "to the approved proposal ID, and consider selector/target restrictions for sensitive systems.",
      severity: "critical",
      confidence: "high",
      category: "execution",
      model,
      transition,
      evidence: [taintEvidence(call, "Proposal parameters flow into a privileged external call")],
      assumptions: ["A proposal author can choose the modeled action arrays"],
    }));
  }
  return findings;
}

function detectGuardianBypass(model: GovernanceContractModel): GovernanceFinding[] {
  const guardians = variables(model, ["guardian"]);
  if (!guardians.length) return [];
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["emergency-execute", "cancel", "upgrade"])) {
    const call = privilegedCall(transition);
    if (!call) continue;
    const source = codeText(transition.source);
    if (/timelock|isoperationready|multisig|threshold/i.test(source)) continue;
    findings.push(finding({
      ruleId: "CP-GOV-009",
      title: `Guardian path bypasses governance execution controls`,
      description:
        `${transition.name} gives a guardian or emergency council a privileged execution path without ` +
        "the proposal, quorum, timelock, or multisig conditions applied to normal governance.",
      recommendation:
        "Limit emergency authority to narrowly enumerated pause/cancel selectors, require multisig " +
        "approval, prevent upgrades/asset transfers, and route any broader action through the timelock.",
      severity: "critical",
      confidence: "high",
      category: "authorization",
      model,
      transition,
      evidence: [
        variableEvidence(guardians[0], "Guardian authority is persistent state"),
        operationEvidence(call, "Guardian path reaches a privileged call"),
      ],
      assumptions: ["The guardian can satisfy the path's access-control condition"],
    }));
  }
  return findings;
}

function detectUnsafeDelayUpdate(model: GovernanceContractModel): GovernanceFinding[] {
  const delays = new Set(variables(model, ["minimum-delay"]).map((item) => item.name));
  if (!delays.size) return [];
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["set-delay"])) {
    const write = firstWrite(transition, delays);
    if (!write) continue;
    const source = codeText(transition.source);
    const onlySelf = /msg\.sender\s*==\s*address\s*\(\s*this\s*\)|onlyself/i.test(source) ||
      transition.modifiers.some((modifier) => /onlyself|timelock/i.test(modifier));
    if (onlySelf) continue;
    findings.push(finding({
      ruleId: "CP-GOV-010",
      title: "Timelock delay can be changed outside the timelock lifecycle",
      description:
        "The minimum delay is directly mutable by a caller rather than only by a scheduled self-call. " +
        "An administrator can reduce the delay and execute a privileged action before users can react.",
      recommendation:
        "Require msg.sender == address(this) for delay updates, schedule the update with the current " +
        "delay, and impose a non-zero minimum or bounded reduction policy.",
      severity: "critical",
      confidence: "high",
      category: "timelock",
      model,
      transition,
      evidence: [
        operationEvidence(write, "Minimum-delay state is updated"),
        absenceEvidence(transition, "No scheduled self-call authorization was identified"),
      ],
      assumptions: ["A privileged role can invoke the delay update path"],
    }));
  }
  return findings;
}

function detectMissingPredecessorDependency(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["execute"])) {
    const predecessor = transition.parameters.find((parameter) => /predecessor/i.test(parameter));
    if (!predecessor) continue;
    const sourceBody = codeText(transition.source).replace(/function[^{]+{/, "");
    const enforced = /isoperationdone|missingdependency|timelock\.execute|predecessor\s*==\s*bytes32\s*\(\s*0\s*\)/i.test(sourceBody) ||
      transition.operations.some((operation) => operation.kind === "guard" &&
        /predecessor/i.test(operation.expression) && /timestamp|done|completed/i.test(operation.expression));
    if (enforced) continue;
    findings.push(finding({
      ruleId: "CP-GOV-011",
      title: "Timelock predecessor is accepted but not enforced",
      description:
        `${transition.name} accepts a predecessor operation but does not require it to be completed. ` +
        "Dependent governance actions can execute out of order and violate staged migration or upgrade invariants.",
      recommendation:
        "Before any external action, require predecessor == bytes32(0) or isOperationDone(predecessor), " +
        "and include the predecessor in the operation hash.",
      severity: "high",
      confidence: "high",
      category: "timelock",
      model,
      transition,
      evidence: [absenceEvidence(transition, "Predecessor parameter has no completion guard")],
      assumptions: ["Callers rely on predecessor ordering for dependent operations"],
    }));
  }
  return findings;
}

function detectSaltCollision(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["hash-operation", "schedule"])) {
    const salt = transition.parameters.find((parameter) => /salt/i.test(parameter));
    if (!salt) continue;
    const body = codeText(transition.source).replace(/function[^{]+{/, "");
    if (new RegExp(`\\b${escapeRegExp(salt)}\\b`).test(body)) continue;
    findings.push(finding({
      ruleId: "CP-GOV-012",
      title: "Timelock operation identity omits its salt",
      description:
        "The operation accepts a salt but does not bind it into scheduling or hashing. Identical action " +
        "tuples collide, preventing independent scheduling or allowing old operation state to authorize a new action.",
      recommendation:
        "Include the caller-provided salt, predecessor, target, value, calldata, and chain/domain in the " +
        "operation hash. Require an unused operation ID before scheduling.",
      severity: "high",
      confidence: "high",
      category: "replay",
      model,
      transition,
      evidence: [absenceEvidence(transition, "Operation body does not use the salt parameter")],
      assumptions: ["Operation hashes identify queue and execution state"],
    }));
  }
  return findings;
}

function detectCollapsedRoles(model: GovernanceContractModel): GovernanceFinding[] {
  const schedules = byRoles(model, ["schedule", "queue"]);
  const executes = byRoles(model, ["execute"]);
  if (!schedules.length || !executes.length) return [];
  const roleState = variables(model, ["proposer-role", "executor-role"]);
  if (roleState.length >= 2) return [];
  for (const schedule of schedules) {
    for (const execute of executes) {
      const common = schedule.modifiers.filter((modifier) => execute.modifiers.includes(modifier));
      if (!common.length && (schedule.modifiers.length || execute.modifiers.length)) continue;
      return [finding({
        ruleId: "CP-GOV-013",
        title: "Proposal scheduling and execution authority are not separated",
        description:
          "The same access-control path can schedule and execute operations without distinct proposer " +
          "and executor roles. A single compromised administrator controls both admission and completion.",
        recommendation:
          "Separate proposer, canceller, executor, and default-admin roles. Renounce bootstrap admin after " +
          "configuration and document whether the executor role is intentionally open.",
        severity: "medium",
        confidence: "medium",
        category: "authorization",
        model,
        transition: execute,
        evidence: [absenceEvidence(execute, "Distinct proposer and executor role state was not modeled")],
        assumptions: ["Role separation is part of the intended governance trust model"],
      })];
    }
  }
  return [];
}

function detectProposalControlledUpgrade(model: GovernanceContractModel): GovernanceFinding[] {
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["execute", "emergency-execute", "upgrade"])) {
    const call = transition.operations.find((operation) =>
      operation.kind === "call" && /delegatecall|upgradeto|upgradetoandcall/i.test(operation.name + operation.expression) &&
      operation.parameterSources.length > 0,
    );
    if (!call) continue;
    const source = codeText(transition.source);
    if (/timelock|isoperationready/i.test(source) && transition.role === "execute") continue;
    findings.push(finding({
      ruleId: "CP-GOV-014",
      title: "Proposal-controlled calldata reaches an immediate upgrade primitive",
      description:
        "A proposal, guardian, or caller controls data passed to delegatecall/upgradeTo without a proven " +
        "timelock boundary. Governance capture can replace implementation logic immediately.",
      recommendation:
        "Bind implementation and initialization calldata to a queued proposal hash, enforce the timelock, " +
        "and keep upgrade authorization independent from emergency execution authority.",
      severity: "critical",
      confidence: "high",
      category: "upgrade",
      model,
      transition,
      evidence: [taintEvidence(call, "Caller/proposal parameters flow into an upgrade primitive")],
      assumptions: ["The called target is or can control an upgradeable proxy"],
    }));
  }
  return findings;
}

function detectCrossChainReplay(model: GovernanceContractModel): GovernanceFinding[] {
  const messageState = new Set(variables(model, ["message-id", "nonce"]).map((item) => item.name));
  const domains = variables(model, ["chain-domain"]);
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["cross-chain-receive"])) {
    const call = privilegedCall(transition);
    if (!call) continue;
    const write = firstWrite(transition, messageState);
    const source = codeText(transition.source);
    const domainGuard = domains.some((domain) => source.includes(domain.name)) ||
      /sourcechain|domainseparator|block\.chainid/i.test(source);
    if (write && write.order < call.order && domainGuard) continue;
    findings.push(finding({
      ruleId: "CP-GOV-015",
      title: "Cross-chain governance message lacks replay or domain protection",
      description:
        "A received governance message reaches privileged execution without consuming a unique message ID " +
        "before the call and binding authorization to a source chain/domain. Relayers or bridges can redeliver it.",
      recommendation:
        "Authenticate the bridge and source governor, include source/destination chain IDs and nonce in the " +
        "message hash, reject consumed IDs, and mark the ID consumed before external execution.",
      severity: "critical",
      confidence: "high",
      category: "cross-chain",
      model,
      transition,
      evidence: [
        operationEvidence(call, "Cross-chain path reaches a privileged call"),
        ...(write ? [] : [absenceEvidence(transition, "No pre-call message consumption write was identified")]),
        ...(!domainGuard ? [absenceEvidence(transition, "No source-chain/domain binding was identified")] : []),
      ],
      assumptions: ["The transport can deliver duplicate or cross-domain messages"],
    }));
  }
  return findings;
}

function detectWeakMultisigExecution(model: GovernanceContractModel): GovernanceFinding[] {
  const thresholds = variables(model, ["signature-threshold"]);
  const nonces = new Set(variables(model, ["nonce"]).map((item) => item.name));
  const signers = variables(model, ["signer-set"]);
  if (!thresholds.length && !signers.length) return [];
  const findings: GovernanceFinding[] = [];
  for (const transition of byRoles(model, ["multisig-execute"])) {
    const call = privilegedCall(transition);
    if (!call) continue;
    const source = codeText(transition.source);
    const checksSignatures = /checksignatures|validatesignatures|recover\s*\(/i.test(source);
    const readsThreshold = thresholds.some((threshold) => source.includes(threshold.name));
    const nonceWrite = firstWrite(transition, nonces);
    if (checksSignatures && readsThreshold && nonceWrite && nonceWrite.order < call.order) continue;
    findings.push(finding({
      ruleId: "CP-GOV-016",
      title: "Multisig execution does not prove threshold signatures and nonce consumption",
      description:
        "The multisig execution path reaches an external call without visibly validating distinct signer " +
        "approvals against the stored threshold and consuming a nonce before interaction.",
      recommendation:
        "Hash the full transaction and domain with a monotonic nonce, recover unique sorted owners, require " +
        "valid signatures >= threshold, increment the nonce, then execute. Bound threshold to [1, owners.length].",
      severity: "critical",
      confidence: "high",
      category: "multisig",
      model,
      transition,
      evidence: [
        operationEvidence(call, "Multisig path reaches an external call"),
        absenceEvidence(transition, "Complete threshold-signature and pre-call nonce proof was not identified"),
      ],
      assumptions: ["No inherited modifier performs the missing signature validation"],
    }));
  }
  return findings;
}

interface FindingInput {
  ruleId: GovernanceRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: GovernanceFinding["severity"];
  confidence: GovernanceFinding["confidence"];
  category: GovernanceFinding["category"];
  model: GovernanceContractModel;
  transition?: GovernanceTransition;
  location?: GovernanceFinding["location"];
  evidence: GovernanceEvidence[];
  assumptions: string[];
}

function finding(input: FindingInput): GovernanceFinding {
  return {
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    recommendation: input.recommendation,
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    contract: input.model.name,
    location: input.location ?? input.transition?.location ?? input.model.location,
    evidence: input.evidence,
    assumptions: input.assumptions,
  };
}

function byRoles(
  model: GovernanceContractModel,
  roles: GovernanceTransition["role"][],
): GovernanceTransition[] {
  const selected = new Set(roles);
  return model.transitions.filter((transition) => selected.has(transition.role));
}

function variables(
  model: GovernanceContractModel,
  roles: GovernanceVariableRole[],
): GovernanceStateVariable[] {
  const selected = new Set(roles);
  return model.stateVariables.filter((variable) => selected.has(variable.role));
}

function privilegedCall(transition: GovernanceTransition): GovernanceOperation | undefined {
  return transition.operations.find((operation) =>
    operation.kind === "call" && (/call|delegatecall|functioncall|execute|upgradeto/i.test(operation.name) ||
      /\.call\s*\{|\.delegatecall\s*\(/i.test(operation.expression)),
  );
}

function hasTimelockReadiness(transition: GovernanceTransition): boolean {
  const source = codeText(transition.source);
  if (/isoperationready|isoperationdone|eta|queuedat|minimumdelay|mindelay|timelock\.execute|block\.timestamp\s*>=/i.test(source)) {
    return true;
  }
  if (transition.modifiers.some((modifier) => /timelock|onlyready|queued/i.test(modifier))) return true;
  return transition.operations.some((operation) => operation.kind === "guard" &&
    /block\.timestamp/i.test(operation.expression) && /timestamp|operation|eta|queued/i.test(operation.expression));
}

function firstWrite(
  transition: GovernanceTransition,
  names: Set<string>,
): GovernanceOperation | undefined {
  return transition.operations.find((operation) =>
    operation.kind === "write" && [...names].some((name) =>
      operation.name.split(",").includes(name) || operation.expression.includes(name),
    ),
  );
}

function operationEvidence(operation: GovernanceOperation, description: string): GovernanceEvidence {
  return {
    kind: operation.kind === "write" ? "state-write" : operation.kind === "arithmetic" ?
      "arithmetic" : operation.kind === "guard" ? "branch" : "call",
    description,
    location: operation.location,
    snippet: operation.expression,
  };
}

function taintEvidence(operation: GovernanceOperation, description: string): GovernanceEvidence {
  return {
    kind: "taint-flow",
    description: `${description}; sources: ${operation.parameterSources.join(", ")}`,
    location: operation.location,
    snippet: operation.expression,
  };
}

function variableEvidence(variable: GovernanceStateVariable, description: string): GovernanceEvidence {
  return {
    kind: "state-read",
    description,
    location: variable.location,
    snippet: `${variable.typeName} ${variable.name}`,
  };
}

function absenceEvidence(transition: GovernanceTransition, description: string): GovernanceEvidence {
  return { kind: "absence", description, location: transition.location };
}

function divisionBeforeMultiplication(expression: string): boolean {
  const value = expression.replace(/\s+/g, "");
  return /^[^;=]+\/[^;=]+\*/.test(value) || /\([^()]+\/[^()]+\)\s*\*/.test(expression);
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}

function compareFindings(left: GovernanceFinding, right: GovernanceFinding): number {
  return left.location.file.localeCompare(right.location.file) || left.location.line - right.location.line ||
    left.location.column - right.location.column || left.ruleId.localeCompare(right.ruleId) ||
    left.title.localeCompare(right.title);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
