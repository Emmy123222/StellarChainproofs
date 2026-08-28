import * as path from "path";
import { scan } from "../../scanner";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/governance");

describe("governance scanner integration", () => {
  it("adds specialized findings exactly once per physical file", async () => {
    const result = await scan({
      targets: [path.join(FIXTURES, "VulnerableGovernor.sol")],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });
    const liveBalance = result.files[0].findings.filter((finding) => finding.id === "CP-GOV-001");
    expect(liveBalance).toHaveLength(1);
    expect(liveBalance[0].evidence?.length).toBeGreaterThan(0);
    expect(liveBalance[0].confidence).toBe("high");
  });

  it("does not add governance findings to an unrelated contract", async () => {
    const result = await scan({
      targets: [path.resolve(FIXTURES, "../UnrelatedRatioMath.sol")],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });
    expect(result.files.flatMap((file) => file.findings).some((finding) =>
      finding.id.startsWith("CP-GOV-"))).toBe(false);
  });
});
