import { getStakingFrameworkAdapter, matchStakingFrameworkAdapter } from "../adapters";
import type { StakingContractModel } from "../types";

function model(state: string[], functions: string[]): Pick<StakingContractModel, "stateVariables" | "transitions"> {
  return {
    stateVariables: state.map((name, index) => ({
      name,
      typeName: "uint256",
      role: "unknown",
      isMapping: false,
      location: { file: "adapter.sol", line: index + 1, column: 1 },
    })),
    transitions: functions.map((name, index) => ({
      name,
      role: name === "stake" ? "stake" : "unknown",
      visibility: "public",
      modifiers: [],
      parameters: [],
      reads: [],
      writes: [],
      calls: [],
      operations: [],
      location: { file: "adapter.sol", line: index + 20, column: 1 },
      source: `function ${name}() public {}`,
    })),
  };
}

describe("staking framework adapters", () => {
  it("requires structural Synthetix state and functions rather than a contract name", () => {
    const match = matchStakingFrameworkAdapter(model(
      ["rewardPerTokenStored", "userRewardPerTokenPaid", "periodFinish", "rewardRate"],
      ["rewardPerToken", "notifyRewardAmount"],
    ));
    expect(match.adapter).toBe("synthetix-staking-rewards");
    expect(match.matchedState).toHaveLength(4);
  });

  it("falls back to generic staking when a framework signature is incomplete", () => {
    expect(matchStakingFrameworkAdapter(model(["rewardRate"], ["stake"])).adapter)
      .toBe("generic-staking");
  });

  it("publishes guarantees and limitations for integrators", () => {
    const adapter = getStakingFrameworkAdapter("masterchef-accumulator");
    expect(adapter.guarantees.length).toBeGreaterThan(0);
    expect(adapter.limitations.length).toBeGreaterThan(0);
  });
});
