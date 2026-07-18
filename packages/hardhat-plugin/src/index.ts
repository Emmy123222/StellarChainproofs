import { extendConfig, extendEnvironment, task } from "hardhat/config";
import "./type-extensions";
import { resolveChainProofConfig } from "./config";
import { printTestFooterSummary } from "./console";
import { runChainProofScan } from "./runner";

import "./tasks/scan";
import "./tasks/check";
import "./tasks/report";

extendConfig((config, userConfig) => {
  config.chainproof = {
    targets: ["contracts/"],
    minSeverity: "high",
    useSlither: true,
    useLLM: false,
    runOnCompile: false,
    failOnCompile: false,
    ...userConfig.chainproof,
  };
});

extendEnvironment((hre) => {
  hre.chainproof = {
    lastResult: undefined,
  };
});

task("compile").setAction(async (args, hre, runSuper) => {
  await runSuper(args);

  const { runOnCompile, failOnCompile } = resolveChainProofConfig(hre);
  if (!runOnCompile) return;

  try {
    await runChainProofScan(hre, {
      failOnCriticalHigh: failOnCompile,
      quiet: false,
    });
  } catch (error) {
    if (failOnCompile) {
      throw error;
    }

    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[ChainProof] Compile-time scan warning: ${message}`);
  }
});

task("test").setAction(async (args, hre, runSuper) => {
  const result = await runSuper(args);

  if (hre.network.name === "hardhat") {
    try {
      const scanResult = await runChainProofScan(hre, { quiet: true });
      printTestFooterSummary(scanResult);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn(`[ChainProof] Test footer scan skipped: ${message}`);
    }
  }

  return result;
});

export { resolveChainProofConfig } from "./config";
export { printFindings, printTestFooterSummary } from "./console";
export { runChainProofScan, writeChainProofReport } from "./runner";
export type { ChainProofUserConfig } from "./type-extensions";
