import type {
  AccountingOperation,
  AccountingStateVariable,
  AccountingTransition,
  StakingAnalysisOptions,
  StakingContractModel,
  StakingEvidence,
  StakingFinding,
  StakingRuleId,
} from "./types";

type Rule = (model: StakingContractModel) => StakingFinding[];

const RULE_ORDER: readonly StakingRuleId[] = [
  "CP-STK-001",
  "CP-STK-002",
  "CP-STK-003",
  "CP-STK-004",
  "CP-STK-005",
  "CP-STK-006",
  "CP-STK-007",
  "CP-STK-008",
  "CP-STK-009",
  "CP-STK-010",
  "CP-STK-011",
  "CP-STK-012",
  "CP-STK-013",
];

const RULES: Record<StakingRuleId, Rule> = {
  "CP-STK-001": detectMissingUserCheckpoint,
  "CP-STK-002": detectZeroSupplyLossOrCapture,
  "CP-STK-003": detectDivisionLoss,
  "CP-STK-004": detectUnfundedRewardRate,
  "CP-STK-005": detectStaleAdministrativeCheckpoint,
  "CP-STK-006": detectNominalTransferAccounting,
  "CP-STK-007": detectUnsafeEmergencyWithdrawal,
  "CP-STK-008": detectProtectedTokenRecovery,
  "CP-STK-009": detectCliffBypass,
  "CP-STK-010": detectVestingInteractionBeforeEffects,
  "CP-STK-011": detectSharedMultiRewardIndex,
  "CP-STK-012": detectUnsafeDurationBoundary,
  "CP-STK-013": detectRebasingAssetShareMismatch,
};

/** Run all selected accounting rules on an already normalized contract model. */
export function analyzeStakingModel(
  model: StakingContractModel,
  options: StakingAnalysisOptions = {},
): StakingFinding[] {
  const include = options.includeRules ? new Set(options.includeRules) : null;
  const exclude = new Set(options.excludeRules ?? []);
  const findings: StakingFinding[] = [];

  for (const ruleId of RULE_ORDER) {
    if (include && !include.has(ruleId)) continue;
    if (exclude.has(ruleId)) continue;
    findings.push(...RULES[ruleId](model));
  }

  return findings.sort(compareFindings);
}

function detectMissingUserCheckpoint(model: StakingContractModel): StakingFinding[] {
  if (!hasRewardIndexAccounting(model)) return [];
  const findings: StakingFinding[] = [];
  const balanceNames = variablesByRole(model, "user-balance").map((item) => item.name);
  const supplyNames = variablesByRole(model, "total-supply").map((item) => item.name);
  const accountingNames = new Set([...balanceNames, ...supplyNames]);

  for (const transition of transitionsByRoles(model, ["stake", "withdraw", "exit"])) {
    const mutation = firstWriteTo(transition, accountingNames);
    if (!mutation || hasCheckpointBefore(transition, mutation.order)) continue;

    const snapshot = variablesByRole(model, "user-index")[0] ??
      variablesByRole(model, "accrued-reward")[0];
    findings.push(makeFinding({
      ruleId: "CP-STK-001",
      title: `Reward checkpoint missing before ${transition.name}`,
      description:
        `${transition.name} changes stake supply or a user balance before any accumulated-index ` +
        "checkpoint. A depositor or withdrawing account can therefore be measured against a " +
        "stake weight that did not exist for the elapsed reward interval, enabling reward theft " +
        "or causing already-earned rewards to be lost.",
      recommendation:
        "Checkpoint the global reward-per-token index and the affected user's accrued reward " +
        "before changing total supply or user shares. Apply the same ordering to stake, withdraw, " +
        "exit, transfer, restake, and delegated stake paths.",
      severity: "high",
      confidence: "high",
      category: "checkpoint",
      model,
      transition,
      evidence: [
        operationEvidence(mutation, "State mutation occurs without an earlier checkpoint"),
        ...(snapshot ? [variableEvidence(snapshot, "A per-user reward snapshot is stored")] : []),
        absenceEvidence(transition, "No checkpoint modifier or checkpoint call precedes the mutation"),
      ],
      assumptions: ["Rewards accrue as a function of stake weight over time"],
    }));
  }
  return findings;
}

function detectZeroSupplyLossOrCapture(model: StakingContractModel): StakingFinding[] {
  if (!hasRewardIndexAccounting(model)) return [];
  if (variablesByRole(model, "queued-reward").length > 0) return [];
  const supplyNames = variablesByRole(model, "total-supply").map((item) => item.name);
  if (supplyNames.length === 0) return [];

  const candidates = transitionsByRoles(model, ["reward-index", "checkpoint"])
    .filter((transition) => {
      const source = codeText(transition.source);
      return supplyNames.some((name) =>
        new RegExp(`\\b${escapeRegExp(name)}\\b\\s*(?:==|<=)\\s*0`).test(source) ||
        new RegExp(`0\\s*==\\s*\\b${escapeRegExp(name)}\\b`).test(source),
      );
    });
  if (candidates.length === 0) return [];

  const transition = candidates[0];
  const zeroGuard = transition.operations.find((operation) =>
    operation.kind === "guard" && supplyNames.some((name) => operation.expression.includes(name)),
  );
  return [makeFinding({
    ruleId: "CP-STK-002",
    title: "Zero-supply rewards have no explicit carry policy",
    description:
      "The reward index has a zero-supply branch, but the contract has no queued-reward or " +
      "undistributed-reward state. Depending on last-update ordering, emissions during an empty " +
      "pool are either stranded or become claimable by the first later depositor.",
    recommendation:
      "Define and implement a zero-supply policy: pause emission time, queue elapsed rewards for " +
      "a future funded period, or return them to the distributor. Update the global timestamp in " +
      "the same transaction and test the first deposit immediately before and after epoch rollover.",
    severity: "medium",
    confidence: "high",
    category: "zero-supply",
    model,
    transition,
    evidence: [
      ...(zeroGuard ? [operationEvidence(zeroGuard, "Reward calculation branches on zero supply")] : []),
      absenceEvidence(transition, "No queued or undistributed reward accumulator is modeled"),
    ],
    assumptions: ["Reward emission time continues while total staked supply is zero"],
  })];
}

function detectDivisionLoss(model: StakingContractModel): StakingFinding[] {
  const findings: StakingFinding[] = [];
  const relevant = transitionsByRoles(model, ["reward-index", "checkpoint", "claim-reward", "claim-vested"]);
  for (const transition of relevant) {
    const arithmetic = transition.operations.find((operation) =>
      operation.kind === "arithmetic" && isDivisionBeforeMultiplication(operation.expression),
    );
    if (arithmetic) {
      findings.push(makeFinding({
        ruleId: "CP-STK-003",
        title: `Division truncates reward precision in ${transition.name}`,
        description:
          "An integer division is evaluated before a later multiplication in accounting math. " +
          "Solidity truncates the quotient, systematically under-crediting small positions and " +
          "leaving the accumulated remainder stranded in the contract.",
        recommendation:
          "Multiply before dividing and use an explicit full-precision mulDiv implementation when " +
          "intermediate multiplication can overflow. Document the rounding direction and retain or " +
          "redistribute remainders deliberately.",
        severity: "medium",
        confidence: "high",
        category: "precision",
        model,
        transition,
        evidence: [operationEvidence(arithmetic, "Division result participates in a later multiplication")],
        assumptions: ["All operands use Solidity integer arithmetic"],
      }));
      continue;
    }

    if (transition.role === "reward-index" && model.precisionScalars.length === 0) {
      const indexDivision = transition.operations.find((operation) =>
        operation.kind === "arithmetic" && operation.name === "/" &&
        variablesByRole(model, "total-supply").some((variable) =>
          operation.expression.includes(variable.name),
        ),
      );
      if (indexDivision) {
        findings.push(makeFinding({
          ruleId: "CP-STK-003",
          title: `Reward index in ${transition.name} has no precision scalar`,
          description:
            "The per-share index divides by total supply without a visible fixed-point scalar. " +
            "Low emission rates or large stake supply can round every update to zero.",
          recommendation:
            "Scale the numerator before division (for example with a documented 1e18 scalar), " +
            "use full-precision multiplication/division, and carry division remainders across updates.",
          severity: "medium",
          confidence: "medium",
          category: "precision",
          model,
          transition,
          evidence: [
            operationEvidence(indexDivision, "Reward index divides by total stake supply"),
            absenceEvidence(transition, "No fixed-point precision scalar was identified"),
          ],
          assumptions: ["The reward index is stored as an integer"],
        }));
      }
    }
  }
  return findings;
}

function detectUnfundedRewardRate(model: StakingContractModel): StakingFinding[] {
  const findings: StakingFinding[] = [];
  const rateNames = variablesByRole(model, "reward-rate").map((item) => item.name);
  if (rateNames.length === 0) return [];

  for (const transition of transitionsByRoles(model, ["notify-reward", "set-reward-rate", "epoch-rollover"])) {
    if (!transition.writes.some((name) => rateNames.includes(name))) continue;
    const source = codeText(transition.source);
    const hasBalanceProof = /balanceof\s*\(\s*address\s*\(\s*this\s*\)\s*\)/i.test(source) ||
      /balanceof\s*\(\s*this\s*\)/i.test(source);
    const hasFundingPull = /(?:safe)?transferfrom\s*\(/i.test(source);
    const hasCoverageGuard = /require\s*\([^;]*(?:rewardrate|reward)[^;]*(?:balance|available|received|fund)/i.test(source) ||
      /(?:rewardrate|reward)\s*\*[^;]*(?:duration|period)[^;]*(?:<=|<)[^;]*(?:balance|available|received|fund)/i.test(source);
    if ((hasBalanceProof && hasCoverageGuard) || (hasFundingPull && hasCoverageGuard)) continue;

    const rateWrite = firstWriteTo(transition, new Set(rateNames));
    findings.push(makeFinding({
      ruleId: "CP-STK-004",
      title: `Reward rate set without a funding coverage proof in ${transition.name}`,
      description:
        "The configured reward rate is changed without proving that funded reward assets cover " +
        "the full remaining distribution interval. Claims can become insolvent, revert for later " +
        "users, or distribute more accounting credit than the contract can transfer.",
      recommendation:
        "After checkpointing existing rewards, compute the new rate from the actual received or " +
        "available reward balance and require rate * duration to be bounded by that balance. Include " +
        "leftover rewards from an active period and fee-on-transfer behavior in the calculation.",
      severity: "high",
      confidence: "medium",
      category: "distribution",
      model,
      transition,
      evidence: [
        ...(rateWrite ? [operationEvidence(rateWrite, "Reward emission state is changed")] : []),
        absenceEvidence(transition, "No funded-balance coverage condition was identified"),
      ],
      assumptions: ["Reward claims are paid from assets held by this contract"],
    }));
  }
  return findings;
}

function detectStaleAdministrativeCheckpoint(model: StakingContractModel): StakingFinding[] {
  if (!hasRewardIndexAccounting(model)) return [];
  const sensitiveRoles = new Set(["reward-rate", "duration", "period-finish", "epoch"]);
  const names = new Set(model.stateVariables
    .filter((variable) => sensitiveRoles.has(variable.role))
    .map((variable) => variable.name));
  if (names.size === 0) return [];

  const findings: StakingFinding[] = [];
  for (const transition of transitionsByRoles(model, ["notify-reward", "set-reward-rate", "epoch-rollover"])) {
    const write = firstWriteTo(transition, names);
    if (!write || hasCheckpointBefore(transition, write.order)) continue;
    findings.push(makeFinding({
      ruleId: "CP-STK-005",
      title: `Administrative reward change skips the old-period checkpoint`,
      description:
        `${transition.name} changes reward rate, duration, epoch, or period state before persisting ` +
        "rewards earned under the previous parameters. The administrator can retroactively price " +
        "elapsed time at a new rate, shifting rewards between users or epochs.",
      recommendation:
        "Checkpoint the global index at min(block.timestamp, periodFinish) before updating any " +
        "rate, duration, or epoch boundary. Preserve leftover rewards using the old rate and then " +
        "start the new period from the checkpoint timestamp.",
      severity: "high",
      confidence: "high",
      category: "checkpoint",
      model,
      transition,
      evidence: [
        operationEvidence(write, "Administrative accounting field is written"),
        absenceEvidence(transition, "No global checkpoint occurs before the parameter change"),
      ],
      assumptions: ["The changed parameter affects rewards for elapsed wall-clock time"],
    }));
  }
  return findings;
}

function detectNominalTransferAccounting(model: StakingContractModel): StakingFinding[] {
  const findings: StakingFinding[] = [];
  const accountingNames = new Set([
    ...variablesByRole(model, "total-supply").map((item) => item.name),
    ...variablesByRole(model, "user-balance").map((item) => item.name),
  ]);
  for (const transition of transitionsByRoles(model, ["stake"])) {
    const source = codeText(transition.source);
    const transfer = transition.operations.find((operation) =>
      operation.kind === "call" && /transferfrom/i.test(operation.name),
    );
    if (!transfer || accountingNames.size === 0) continue;
    const parameter = transition.parameters.find((name) =>
      new RegExp(`\\b${escapeRegExp(name)}\\b`).test(transfer.expression),
    );
    if (!parameter) continue;
    const nominalWrite = transition.operations.find((operation) =>
      operation.kind === "write" && [...accountingNames].some((name) => operation.name.includes(name)) &&
      new RegExp(`\\b${escapeRegExp(parameter)}\\b`).test(operation.expression),
    );
    const measuresReceived = /balancebefore|balanceafter|received|actualamount|actualreceived/i.test(source) &&
      /balanceof\s*\(/i.test(source);
    if (!nominalWrite || measuresReceived) continue;

    findings.push(makeFinding({
      ruleId: "CP-STK-006",
      title: `Nominal stake amount is credited before measuring received assets`,
      description:
        `${transition.name} transfers a caller-supplied amount and credits stake accounting with ` +
        "that nominal value without measuring the token balance delta. Fee-on-transfer assets can " +
        "mint more stake weight than the contract received, diluting rewards and making exits insolvent.",
      recommendation:
        "Measure stakeAsset.balanceOf(address(this)) before and after transferFrom, then credit only " +
        "the received delta. Otherwise explicitly reject fee-on-transfer assets and enforce the " +
        "assumption at configuration time and in documentation.",
      severity: "high",
      confidence: "high",
      category: "asset-accounting",
      model,
      transition,
      evidence: [
        operationEvidence(transfer, "Stake asset is pulled using the requested amount"),
        operationEvidence(nominalWrite, "Stake supply or shares are credited from the same amount"),
      ],
      assumptions: ["The configured stake asset may deduct a transfer fee"],
    }));
  }
  return findings;
}

function detectUnsafeEmergencyWithdrawal(model: StakingContractModel): StakingFinding[] {
  const findings: StakingFinding[] = [];
  const rewardNames = new Set([
    ...variablesByRole(model, "user-index").map((item) => item.name),
    ...variablesByRole(model, "accrued-reward").map((item) => item.name),
  ]);
  for (const transition of transitionsByRoles(model, ["emergency-withdraw"])) {
    const source = codeText(transition.source);
    const transfersAsset = transition.operations.some((operation) =>
      operation.kind === "call" && /(?:safe)?transfer/.test(operation.name.toLowerCase()),
    );
    if (!transfersAsset) continue;
    const hasCheckpoint = hasCheckpointBefore(transition, Number.POSITIVE_INFINITY);
    const writesRewardDisposition = transition.writes.some((name) => rewardNames.has(name));
    const explicitForfeit = /forfeit|forgo|discardreward|rewardforfeited|emergencywithdrawn/i.test(source);
    if (hasCheckpoint || writesRewardDisposition || explicitForfeit) continue;

    findings.push(makeFinding({
      ruleId: "CP-STK-007",
      title: "Emergency withdrawal leaves reward ownership unresolved",
      description:
        "The emergency path returns assets without checkpointing accrued rewards or explicitly " +
        "recording a reward-forfeiture policy. Later users or the administrator may capture rewards " +
        "earned by the exiting account, and global supply can diverge from user snapshots.",
      recommendation:
        "Checkpoint the user before reducing stake and either preserve claimable rewards or zero them " +
        "with an explicit forfeiture event and documented policy. Update total supply, user shares, " +
        "and all reward-token debts atomically before transferring assets.",
      severity: "high",
      confidence: "high",
      category: "emergency",
      model,
      transition,
      evidence: [absenceEvidence(transition, "No checkpoint or explicit reward disposition is present")],
      assumptions: ["Emergency withdrawals are expected to maintain reward-accounting invariants"],
    }));
  }
  return findings;
}

function detectProtectedTokenRecovery(model: StakingContractModel): StakingFinding[] {
  const protectedNames = [...model.stakeTokens, ...model.rewardTokens];
  if (protectedNames.length === 0) return [];
  const findings: StakingFinding[] = [];
  for (const transition of transitionsByRoles(model, ["recover-token"])) {
    const source = codeText(transition.source);
    const tokenParameter = transition.parameters.find((name) => /token|asset/i.test(name));
    const transfers = transition.operations.find((operation) =>
      operation.kind === "call" && /(?:safe)?transfer/.test(operation.name.toLowerCase()),
    );
    if (!tokenParameter || !transfers) continue;
    const guardsEveryProtectedAsset = protectedNames.every((name) =>
      new RegExp(`(?:require|if)\\s*\\([^;]*\\b${escapeRegExp(tokenParameter)}\\b[^;]*!=[^;]*\\b${escapeRegExp(name)}\\b`, "i").test(source) ||
      new RegExp(`(?:require|if)\\s*\\([^;]*\\b${escapeRegExp(name)}\\b[^;]*!=[^;]*\\b${escapeRegExp(tokenParameter)}\\b`, "i").test(source),
    );
    if (guardsEveryProtectedAsset) continue;

    findings.push(makeFinding({
      ruleId: "CP-STK-008",
      title: `Token recovery can select accounted stake or reward assets`,
      description:
        `${transition.name} accepts an arbitrary token and transfers it without excluding every ` +
        "stake and reward asset. An administrator can remove principal or funded rewards while user " +
        "liabilities remain recorded.",
      recommendation:
        "Reject recovery of the stake asset and every active reward asset. For surplus reward " +
        "recovery, calculate liabilities from accrued indexes and permit only a proven excess after " +
        "the reward period and claim window have ended.",
      severity: "critical",
      confidence: "high",
      category: "authorization",
      model,
      transition,
      evidence: [
        operationEvidence(transfers, "Caller-selected token is transferred"),
        absenceEvidence(transition, `Missing exclusions for: ${protectedNames.join(", ")}`),
      ],
      assumptions: ["The recovery function is reachable by an administrative role"],
    }));
  }
  return findings;
}

function detectCliffBypass(model: StakingContractModel): StakingFinding[] {
  const cliffVariables = variablesByRole(model, "vesting-cliff");
  if (cliffVariables.length === 0) return [];
  const findings: StakingFinding[] = [];
  for (const transition of transitionsByRoles(model, ["claim-vested"])) {
    const source = codeText(transition.source);
    const enforcesCliff = cliffVariables.some((variable) =>
      new RegExp(`\\b${escapeRegExp(variable.name)}\\b`).test(source),
    );
    if (enforcesCliff) continue;
    findings.push(makeFinding({
      ruleId: "CP-STK-009",
      title: `Vesting claim bypasses the stored cliff`,
      description:
        `${transition.name} releases vested assets without reading the contract's cliff state. ` +
        "A beneficiary can claim linear accrual before the configured cliff timestamp, bypassing " +
        "the schedule's intended authorization boundary.",
      recommendation:
        "Require block.timestamp >= start + cliff (or the per-grant cliff timestamp) before computing " +
        "a releasable amount. Exercise exactly cliff-1, cliff, and cliff+1 timestamps in tests and " +
        "define whether the boundary is inclusive.",
      severity: "high",
      confidence: "high",
      category: "vesting",
      model,
      transition,
      evidence: [
        variableEvidence(cliffVariables[0], "A cliff is part of persistent vesting state"),
        absenceEvidence(transition, "The claim path does not read or enforce that cliff"),
      ],
      assumptions: ["The stored cliff is intended to prevent all earlier beneficiary claims"],
    }));
  }
  return findings;
}

function detectVestingInteractionBeforeEffects(model: StakingContractModel): StakingFinding[] {
  const claimedNames = new Set(variablesByRole(model, "claimed-amount").map((item) => item.name));
  if (claimedNames.size === 0) return [];
  const findings: StakingFinding[] = [];
  for (const transition of transitionsByRoles(model, ["claim-vested"])) {
    const transfer = transition.operations.find((operation) =>
      operation.kind === "call" && /(?:safe)?transfer|sendvalue|call/.test(operation.name.toLowerCase()),
    );
    const claimedWrite = firstWriteTo(transition, claimedNames);
    if (!transfer || !claimedWrite || claimedWrite.order < transfer.order) continue;
    findings.push(makeFinding({
      ruleId: "CP-STK-010",
      title: `Vesting claim records released amount after the token interaction`,
      description:
        `${transition.name} transfers assets before increasing claimed or released state. A callback-` +
        "capable asset or recipient can re-enter while the same amount remains releasable and claim " +
        "it more than once.",
      recommendation:
        "Apply checks-effects-interactions: validate the schedule, calculate the releasable amount, " +
        "increase claimed state, emit the release event, and only then transfer. Add a reentrancy " +
        "guard as defense in depth for callback-capable assets.",
      severity: "high",
      confidence: "high",
      category: "vesting",
      model,
      transition,
      evidence: [
        operationEvidence(transfer, "External token interaction occurs first"),
        operationEvidence(claimedWrite, "Released-state effect occurs after the interaction"),
      ],
      assumptions: ["The reward or vesting asset can invoke untrusted code during transfer"],
    }));
  }
  return findings;
}

function detectSharedMultiRewardIndex(model: StakingContractModel): StakingFinding[] {
  const explicitRewardAssets = model.rewardTokens;
  if (explicitRewardAssets.length < 2) return [];
  const indexes = variablesByRole(model, "reward-index");
  const snapshots = variablesByRole(model, "user-index");
  const indexIsTokenKeyed = indexes.some((variable) => variable.isMapping) &&
    snapshots.some((variable) => variable.typeName.includes("mapping") && variable.typeName.split("mapping").length > 2);
  if (indexIsTokenKeyed || (indexes.length >= explicitRewardAssets.length && snapshots.length >= explicitRewardAssets.length)) {
    return [];
  }

  const anchor = indexes[0] ?? explicitRewardAssets
    .map((name) => model.stateVariables.find((variable) => variable.name === name))
    .find((value): value is AccountingStateVariable => Boolean(value));
  if (!anchor) return [];
  return [makeFinding({
    ruleId: "CP-STK-011",
    title: "Multiple reward assets share insufficient checkpoint state",
    description:
      `The model contains ${explicitRewardAssets.length} reward assets but does not contain an ` +
      "independent token-keyed or per-token global index and user snapshot for each one. Updates to " +
      "one reward stream can overwrite or reuse another stream's checkpoint.",
    recommendation:
      "Store rate, period finish, last update, reward-per-token, and user-paid index independently " +
      "for each reward asset. Checkpoint every active token before stake changes and bound iteration " +
      "over the configured reward-token set.",
    severity: "high",
    confidence: "medium",
    category: "checkpoint",
    model,
    transition: model.transitions[0],
    locationOverride: anchor.location,
    evidence: [
      variableEvidence(anchor, "Shared reward checkpoint state"),
      ...explicitRewardAssets.slice(0, 3).map((name) => {
        const variable = model.stateVariables.find((item) => item.name === name)!;
        return variableEvidence(variable, `Reward asset ${name}`);
      }),
    ],
    assumptions: ["All identified reward assets can accrue during overlapping periods"],
  })];
}

function detectUnsafeDurationBoundary(model: StakingContractModel): StakingFinding[] {
  const durationNames = variablesByRole(model, "duration").map((item) => item.name);
  if (durationNames.length === 0) return [];
  const findings: StakingFinding[] = [];
  for (const transition of transitionsByRoles(model, ["notify-reward", "set-reward-rate", "epoch-rollover"])) {
    const source = codeText(transition.source);
    const division = transition.operations.find((operation) =>
      operation.kind === "arithmetic" && operation.name === "/" &&
      durationNames.some((name) => operation.expression.includes(name)),
    );
    if (!division) continue;
    const guardsNonZero = durationNames.some((name) =>
      new RegExp(`(?:require|if)\\s*\\([^;]*\\b${escapeRegExp(name)}\\b\\s*>\\s*0`, "i").test(source) ||
      new RegExp(`(?:require|if)\\s*\\([^;]*0\\s*<\\s*\\b${escapeRegExp(name)}\\b`, "i").test(source),
    );
    if (guardsNonZero) continue;
    findings.push(makeFinding({
      ruleId: "CP-STK-012",
      title: `Reward duration is used as a divisor without a local non-zero guard`,
      description:
        `${transition.name} divides reward funding by a mutable duration without proving it is ` +
        "non-zero on this path. A zero-duration configuration can permanently block epoch rollover " +
        "or reward notification, including recovery attempts made while paused.",
      recommendation:
        "Validate duration > 0 both when duration is configured and immediately before division. " +
        "Use checked timestamp addition for periodFinish and test duration 0, duration 1, and the " +
        "maximum supported timestamp boundary.",
      severity: "medium",
      confidence: "high",
      category: "distribution",
      model,
      transition,
      evidence: [
        operationEvidence(division, "Mutable duration participates in division"),
        absenceEvidence(transition, "No local duration > 0 guard was identified"),
      ],
      assumptions: ["An administrator or initialization path can set the stored duration"],
    }));
  }
  return findings;
}

function detectRebasingAssetShareMismatch(model: StakingContractModel): StakingFinding[] {
  const rebasingAssets = variablesByRole(model, "stake-asset").filter((variable) =>
    /rebas|elastic|steth|scaled/i.test(variable.typeName) || /rebas|elastic|steth|scaled/i.test(variable.name),
  );
  if (rebasingAssets.length === 0) return [];
  const balances = variablesByRole(model, "user-balance");
  const supplies = variablesByRole(model, "total-supply");
  if (balances.length === 0 || supplies.length === 0) return [];
  const hasShareRepresentation = model.stateVariables.some((variable) =>
    /shares?|scaledbalance|scaledamount/i.test(variable.name),
  ) || model.transitions.some((transition) =>
    /getshares|sharesof|scaledbalanceof|converttoshares/i.test(transition.source),
  );
  if (hasShareRepresentation) return [];

  const stake = transitionsByRoles(model, ["stake"])[0];
  return [makeFinding({
    ruleId: "CP-STK-013",
    title: "Rebasing stake asset is tracked as fixed nominal balances",
    description:
      "The stake asset exposes an explicit rebasing or scaled-balance signal, while the pool stores " +
      "fixed user amounts and cached total supply without a share representation. Asset rebases can " +
      "make recorded principal diverge from assets held, misweight rewards, and make withdrawals fail.",
    recommendation:
      "Account in invariant shares or the asset's scaled units and convert to assets only at transfer " +
      "boundaries. Reconcile total shares rather than caching nominal token amounts, and test positive " +
      "and negative rebases between checkpoint, restake, claim, and exit transitions.",
    severity: "high",
    confidence: "high",
    category: "asset-accounting",
    model,
    transition: stake,
    locationOverride: rebasingAssets[0].location,
    evidence: [
      variableEvidence(rebasingAssets[0], "Stake asset has an explicit rebasing/scaled-unit type signal"),
      variableEvidence(balances[0], "User stake is stored as a nominal balance"),
      variableEvidence(supplies[0], "Total stake is stored as a cached nominal supply"),
    ],
    assumptions: ["The identified stake asset can change balances without a pool transfer"],
  })];
}

interface FindingInput {
  ruleId: StakingRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: StakingFinding["severity"];
  confidence: StakingFinding["confidence"];
  category: StakingFinding["category"];
  model: StakingContractModel;
  transition?: AccountingTransition;
  locationOverride?: StakingFinding["location"];
  evidence: StakingEvidence[];
  assumptions: string[];
}

function makeFinding(input: FindingInput): StakingFinding {
  return {
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    recommendation: input.recommendation,
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    contract: input.model.name,
    location: input.locationOverride ?? input.transition?.location ?? input.model.location,
    evidence: input.evidence,
    assumptions: input.assumptions,
  };
}

function variablesByRole(
  model: StakingContractModel,
  role: AccountingStateVariable["role"],
): AccountingStateVariable[] {
  return model.stateVariables.filter((variable) => variable.role === role);
}

function transitionsByRoles(
  model: StakingContractModel,
  roles: AccountingTransition["role"][],
): AccountingTransition[] {
  const selected = new Set(roles);
  return model.transitions.filter((transition) => selected.has(transition.role));
}

function hasRewardIndexAccounting(model: StakingContractModel): boolean {
  return variablesByRole(model, "reward-index").length > 0 &&
    (variablesByRole(model, "user-index").length > 0 ||
      variablesByRole(model, "accrued-reward").length > 0);
}

function firstWriteTo(
  transition: AccountingTransition,
  names: Set<string>,
): AccountingOperation | undefined {
  return transition.operations.find((operation) =>
    operation.kind === "write" && [...names].some((name) =>
      operation.name.split(",").includes(name) || operation.expression.includes(name),
    ),
  );
}

function hasCheckpointBefore(transition: AccountingTransition, order: number): boolean {
  if (transition.modifiers.some((modifier) =>
    /update(reward|pool)|checkpoint|accrue|syncreward/i.test(modifier),
  )) return true;
  return transition.operations.some((operation) =>
    operation.order < order && operation.kind === "call" &&
    /update(reward|pool)|checkpoint|accrue|syncreward/i.test(operation.name),
  );
}

function operationEvidence(
  operation: AccountingOperation,
  description: string,
): StakingEvidence {
  return {
    kind: operation.kind === "write" ? "state-write" :
      operation.kind === "read" ? "state-read" :
      operation.kind === "arithmetic" ? "arithmetic" :
      operation.kind === "guard" ? "branch" : "call",
    description,
    location: operation.location,
    snippet: operation.expression,
  };
}

function variableEvidence(
  variable: AccountingStateVariable,
  description: string,
): StakingEvidence {
  return {
    kind: "state-read",
    description,
    location: variable.location,
    snippet: `${variable.typeName} ${variable.name}`,
  };
}

function absenceEvidence(
  transition: AccountingTransition,
  description: string,
): StakingEvidence {
  return {
    kind: "absence",
    description,
    location: transition.location,
  };
}

function isDivisionBeforeMultiplication(expression: string): boolean {
  const compact = expression.replace(/\s+/g, "");
  return /^[^;=]+\/[^;=]+\*/.test(compact) || /\([^()]+\/[^()]+\)\s*\*/.test(expression);
}

function codeText(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\/\/[^\n\r]*/g, " ")
    .replace(/\s+/g, " ");
}

function compareFindings(left: StakingFinding, right: StakingFinding): number {
  return left.location.file.localeCompare(right.location.file) ||
    left.location.line - right.location.line ||
    left.location.column - right.location.column ||
    left.ruleId.localeCompare(right.ruleId) ||
    left.title.localeCompare(right.title);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
