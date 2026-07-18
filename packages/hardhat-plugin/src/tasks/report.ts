import * as path from "path";
import chalk from "chalk";
import { task } from "hardhat/config";
import { runChainProofScan, writeChainProofReport } from "../runner";

task("chainproof:report", "Generate a ChainProof audit report file")
  .addOptionalParam("format", "Report format: markdown, json, or table", "markdown")
  .addOptionalParam("output", "Output file path", "audit.md")
  .setAction(async (taskArgs, hre) => {
    const format = String(taskArgs.format) as "markdown" | "json" | "table";
    const output = path.isAbsolute(String(taskArgs.output))
      ? String(taskArgs.output)
      : path.join(hre.config.paths.root, String(taskArgs.output));

    await runChainProofScan(hre, { quiet: true });
    await writeChainProofReport(hre, format, output);

    console.log(chalk.green(`\n  ✅ ChainProof report written to ${output}\n`));
  });
