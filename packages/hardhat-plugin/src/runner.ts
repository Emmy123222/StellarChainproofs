import {
  generateJSONReport,
  generateMarkdownReport,
  generateTableReport,
  scan,
} from "@chainproof/core";
import type { ScanResult } from "@chainproof/core";
import type { HardhatRuntimeEnvironment } from "hardhat/types";
import { HardhatPluginError } from "hardhat/plugins";
import * as fs from "fs";
import { resolveChainProofConfig, toScanConfig } from "./config";
import { printFindings } from "./console";

export interface RunChainProofOptions {
  minSeverity?: import("@chainproof/core").Severity;
  failOnCriticalHigh?: boolean;
  quiet?: boolean;
}

export async function runChainProofScan(
  hre: HardhatRuntimeEnvironment,
  options: RunChainProofOptions = {}
): Promise<ScanResult> {
  const resolved = resolveChainProofConfig(hre);
  const config = toScanConfig(resolved, {
    minSeverity: options.minSeverity ?? resolved.minSeverity,
  });

  const result = await scan(config);
  hre.chainproof.lastResult = result;

  if (!options.quiet) {
    printFindings(result);
  }

  if (
    options.failOnCriticalHigh &&
    (result.summary.critical > 0 || result.summary.high > 0)
  ) {
    throw new HardhatPluginError(
      "@chainproof/hardhat-plugin",
      `ChainProof found ${result.summary.critical} critical and ${result.summary.high} high severity issue(s).`
    );
  }

  return result;
}

export async function writeChainProofReport(
  hre: HardhatRuntimeEnvironment,
  format: "markdown" | "json" | "table",
  outputPath: string
): Promise<ScanResult> {
  const result = hre.chainproof.lastResult ?? (await runChainProofScan(hre, { quiet: true }));

  let report: string;
  switch (format) {
    case "json":
      report = generateJSONReport(result);
      break;
    case "table":
      report = generateTableReport(result);
      break;
    default:
      report = generateMarkdownReport(result);
  }

  fs.writeFileSync(outputPath, report, "utf-8");
  return result;
}
