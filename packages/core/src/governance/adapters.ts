import type {
  GovernanceContractModel,
  GovernanceFrameworkAdapterDefinition,
  GovernanceFrameworkMatch,
} from "./types";

export const GOVERNANCE_FRAMEWORK_ADAPTERS: readonly GovernanceFrameworkAdapterDefinition[] =
  Object.freeze([
    {
      id: "openzeppelin-governor",
      displayName: "OpenZeppelin Governor with checkpointed votes",
      requiredStateGroups: [["proposalThreshold"], ["votingDelay"], ["votingPeriod"]],
      requiredFunctions: ["propose", "castVote", "proposalSnapshot", "proposalDeadline"],
      mitigations: [
        "Proposal lifecycle has explicit snapshot and deadline functions",
        "Voting delay and voting period are independently represented",
      ],
      limitations: [
        "The adapter does not prove _getVotes uses a past checkpoint",
        "Queue and execution safety depend on the configured executor/timelock",
      ],
    },
    {
      id: "openzeppelin-timelock-controller",
      displayName: "OpenZeppelin TimelockController operation lifecycle",
      requiredStateGroups: [["_minDelay", "minDelay"], ["timestamps", "_timestamps"]],
      requiredFunctions: ["hashOperation", "schedule", "execute", "updateDelay"],
      mitigations: [
        "Operations are identified by target, value, calldata, predecessor, and salt",
        "Delay updates are expected to execute through the timelock itself",
      ],
      limitations: [
        "Role assignments and open executor policy remain deployment-specific",
        "The adapter does not prove predecessor checks dominate external calls",
      ],
    },
    {
      id: "compound-governor-bravo",
      displayName: "Compound Governor Bravo proposal lifecycle",
      requiredStateGroups: [["proposalCount"], ["proposalThreshold"], ["quorumVotes"]],
      requiredFunctions: ["propose", "castVote", "queue", "execute", "state"],
      mitigations: [
        "Proposal state, queue, and execution are represented as separate transitions",
      ],
      limitations: [
        "The adapter does not assume token.getPriorVotes uses safe block boundaries",
        "Guardian cancellation and abdication need independent review",
      ],
    },
    {
      id: "safe-multisig",
      displayName: "Safe-style threshold multisignature execution",
      requiredStateGroups: [["threshold"], ["owners", "signers"], ["nonce"]],
      requiredFunctions: ["execTransaction", "checkSignatures"],
      mitigations: [
        "Execution carries a nonce and a separately validated signature set",
      ],
      limitations: [
        "Modules, guards, fallback handlers, and owner uniqueness remain configuration-sensitive",
      ],
    },
    {
      id: "cross-chain-governor",
      displayName: "Domain-separated cross-chain governance receiver",
      requiredStateGroups: [["messageId", "processedMessages"], ["sourceChainId", "chainId", "domain"]],
      requiredFunctions: ["receiveMessage"],
      mitigations: [
        "Messages have replay state and an explicit source-chain or domain signal",
      ],
      limitations: [
        "The adapter does not establish bridge authenticity or finality assumptions",
      ],
    },
  ]);

export function matchGovernanceFramework(
  model: Pick<GovernanceContractModel, "stateVariables" | "transitions">,
): GovernanceFrameworkMatch {
  const states = new Map(model.stateVariables.map((variable) => [normalize(variable.name), variable.name]));
  const functions = new Map(model.transitions.map((transition) => [normalize(transition.name), transition.name]));
  for (const adapter of GOVERNANCE_FRAMEWORK_ADAPTERS) {
    const matchedState: string[] = [];
    let complete = true;
    for (const group of adapter.requiredStateGroups) {
      const match = group
        .map((name) => states.get(normalize(name)))
        .find((value): value is string => value !== undefined);
      if (!match) {
        complete = false;
        break;
      }
      matchedState.push(match);
    }
    if (!complete) continue;
    const matchedFunctions: string[] = [];
    for (const name of adapter.requiredFunctions) {
      const match = functions.get(normalize(name));
      if (!match) {
        complete = false;
        break;
      }
      matchedFunctions.push(match);
    }
    if (!complete) continue;
    return {
      adapter: adapter.id,
      matchedState: matchedState.sort(),
      matchedFunctions: matchedFunctions.sort(),
    };
  }

  const roles = new Set(model.transitions.map((transition) => transition.role));
  const stateRoles = new Set(model.stateVariables.map((variable) => variable.role));
  if (stateRoles.has("vote-snapshot") && roles.has("cast-vote")) {
    return { adapter: "checkpointed-governance", matchedState: [], matchedFunctions: [] };
  }
  if (roles.has("schedule") || stateRoles.has("minimum-delay")) {
    return { adapter: "generic-timelock", matchedState: [], matchedFunctions: [] };
  }
  if (roles.has("propose") || roles.has("cast-vote")) {
    return { adapter: "generic-governance", matchedState: [], matchedFunctions: [] };
  }
  return { adapter: "none", matchedState: [], matchedFunctions: [] };
}

export function getGovernanceFrameworkAdapter(
  id: GovernanceFrameworkAdapterDefinition["id"],
): GovernanceFrameworkAdapterDefinition {
  const adapter = GOVERNANCE_FRAMEWORK_ADAPTERS.find((candidate) => candidate.id === id);
  if (!adapter) throw new Error(`Unknown governance framework adapter: ${id}`);
  return adapter;
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}
