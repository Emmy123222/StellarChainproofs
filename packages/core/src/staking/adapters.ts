import type {
  StakingContractModel,
  StakingFrameworkAdapterDefinition,
  StakingFrameworkAdapterMatch,
} from "./types";

/** Explicit structural adapters; matching an architecture is not an audit pass. */
export const STAKING_FRAMEWORK_ADAPTERS: readonly StakingFrameworkAdapterDefinition[] = Object.freeze([
  {
    id: "synthetix-staking-rewards",
    displayName: "Synthetix StakingRewards accumulated index",
    requiredStateGroups: [
      ["rewardPerTokenStored"],
      ["userRewardPerTokenPaid"],
      ["periodFinish"],
      ["rewardRate"],
    ],
    requiredFunctions: ["rewardPerToken", "notifyRewardAmount"],
    guarantees: [
      "Global reward-per-token and per-user paid indexes are represented separately",
      "A bounded reward period and rate are represented in persistent state",
    ],
    limitations: [
      "The adapter does not assume updateReward is applied to every supply-changing path",
      "The adapter does not assume notification funding covers the configured reward period",
    ],
  },
  {
    id: "masterchef-accumulator",
    displayName: "MasterChef accumulated reward-per-share",
    requiredStateGroups: [
      ["accRewardPerShare", "accTokenPerShare", "accRewardsPerShare"],
      ["rewardDebt"],
    ],
    requiredFunctions: ["updatePool"],
    guarantees: [
      "Pool-level accumulated rewards and user reward debt are represented separately",
    ],
    limitations: [
      "The adapter does not prove pool allocation points sum to the emission denominator",
      "The adapter does not treat massUpdatePools as bounded without a separate loop analysis",
    ],
  },
  {
    id: "openzeppelin-vesting-wallet",
    displayName: "OpenZeppelin VestingWallet-style release accounting",
    requiredStateGroups: [
      ["duration", "vestingDuration"],
      ["released", "claimed"],
    ],
    requiredFunctions: ["release"],
    guarantees: [
      "Released value is represented separately from the vesting schedule",
    ],
    limitations: [
      "A cliff is an extension-specific condition and must be enforced independently",
      "Revocation and fee-on-transfer behavior are not provided by the base pattern",
    ],
  },
  {
    id: "accumulated-index",
    displayName: "Generic accumulated reward index",
    requiredStateGroups: [
      ["rewardIndex", "globalIndex", "rewardPerShare", "rewardPerTokenStored"],
      ["userIndex", "indexPaid", "userRewardPerTokenPaid", "rewardDebt"],
    ],
    requiredFunctions: [],
    guarantees: [
      "Global and per-user reward checkpoints are represented separately",
    ],
    limitations: [
      "Ordering, precision, zero-supply behavior, and funding remain rule-level concerns",
    ],
  },
]);

/** Match a normalized contract model against the public adapter catalog. */
export function matchStakingFrameworkAdapter(
  model: Pick<StakingContractModel, "stateVariables" | "transitions">,
): StakingFrameworkAdapterMatch {
  const stateByNormalized = new Map(
    model.stateVariables.map((variable) => [normalize(variable.name), variable.name]),
  );
  const functionByNormalized = new Map(
    model.transitions.map((transition) => [normalize(transition.name), transition.name]),
  );

  for (const adapter of STAKING_FRAMEWORK_ADAPTERS) {
    const matchedState: string[] = [];
    let stateMatches = true;
    for (const group of adapter.requiredStateGroups) {
      const match = group
        .map((signal) => stateByNormalized.get(normalize(signal)))
        .find((value): value is string => Boolean(value));
      if (!match) {
        stateMatches = false;
        break;
      }
      matchedState.push(match);
    }
    if (!stateMatches) continue;

    const matchedFunctions: string[] = [];
    let functionMatches = true;
    for (const required of adapter.requiredFunctions) {
      const match = functionByNormalized.get(normalize(required));
      if (!match) {
        functionMatches = false;
        break;
      }
      matchedFunctions.push(match);
    }
    if (!functionMatches) continue;

    return {
      adapter: adapter.id,
      matchedState: matchedState.sort(),
      matchedFunctions: matchedFunctions.sort(),
    };
  }

  const roles = new Set(model.transitions.map((transition) => transition.role));
  if (roles.has("stake")) {
    return { adapter: "generic-staking", matchedState: [], matchedFunctions: [] };
  }
  if (roles.has("claim-vested") || roles.has("vest")) {
    return { adapter: "generic-vesting", matchedState: [], matchedFunctions: [] };
  }
  return { adapter: "none", matchedState: [], matchedFunctions: [] };
}

/** Retrieve adapter documentation for a matched framework, when available. */
export function getStakingFrameworkAdapter(
  id: StakingFrameworkAdapterDefinition["id"],
): StakingFrameworkAdapterDefinition {
  const adapter = STAKING_FRAMEWORK_ADAPTERS.find((candidate) => candidate.id === id);
  if (!adapter) throw new Error(`Unknown staking framework adapter: ${id}`);
  return adapter;
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}
