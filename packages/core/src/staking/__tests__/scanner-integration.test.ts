import * as path from "path";
import { scan } from "../../scanner";

describe("staking scanner integration", () => {
  it("publishes CP-STK findings through the standard @chainproof/core scan API", async () => {
    const file = path.resolve(__dirname, "../../../../../examples/contracts/staking/VulnerableStakingAccounting.sol");
    const result = await scan({
      targets: [file],
      useSlither: false,
      useLLM: false,
      useMetrics: false,
    });
    const findings = result.files[0].findings.filter((finding) => finding.id.startsWith("CP-STK-"));
    expect(findings.length).toBeGreaterThanOrEqual(8);
    expect(findings[0].evidence?.length).toBeGreaterThan(0);
    expect(findings[0].confidence).toBeDefined();
  });
});
