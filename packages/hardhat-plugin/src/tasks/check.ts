import { task } from "hardhat/config";
import { runChainProofScan } from "../runner";

task("chainproof:check", "Fast CI security check — fails on critical/high findings")
  .setDescription("Run ChainProof and exit with an error when critical/high issues are found")
  .setAction(async (_taskArgs, hre) => {
    await runChainProofScan(hre, {
      minSeverity: "high",
      failOnCriticalHigh: true,
    });
  });
