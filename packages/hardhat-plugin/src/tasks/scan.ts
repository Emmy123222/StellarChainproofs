import { task } from "hardhat/config";
import { runChainProofScan } from "../runner";

task("chainproof", "Run a full ChainProof security audit")
  .setDescription("Scan configured targets and print findings to the Hardhat console")
  .setAction(async (_taskArgs, hre) => {
    await runChainProofScan(hre);
  });
