import { Command } from "commander";
import chalk from "chalk";
import * as fs from "fs";
import {
  analyzeGovernanceFiles,
  generateGovernanceMarkdown,
  GovernanceAnalysisCancelledError,
  GovernanceConfigError,
  loadGovernanceConfigFile,
  serializeGovernanceReport,
} from "@chainproof/core";
import type {
  GovernanceAnalysisLimits,
  GovernanceAnalysisOptions,
  GovernanceAnalysisReport,
  GovernanceRuleId,
} from "@chainproof/core";

type OutputFormat = "json" | "markdown";
type FailSeverity = "none" | "info" | "low" | "medium" | "high" | "critical";

interface GovernanceCliOptions {
  format: OutputFormat;
  output?: string;
  config?: string;
  includeModels?: boolean;
  includeRule: string[];
  excludeRule: string[];
  maxSourceBytes?: number;
  maxFiles?: number;
  maxContracts?: number;
  maxFunctions?: number;
  maxOperations?: number;
  maxFindings?: number;
  failOn: FailSeverity;
}

const RULE_PATTERN = /^CP-GOV-(?:00[1-9]|01[0-6])$/;
const SEVERITY_RANK: Record<FailSeverity, number> = {
  none: 99,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

export function registerGovernanceCommand(program: Command, printBanner: () => void): void {
  program
    .command("governance <targets...>")
    .description("Analyze governance, timelock, multisig, and proposal execution safety")
    .option("--format <format>", "Output format: json|markdown", "markdown")
    .option("--output <file>", "Write the report to a file")
    .option("--config <file>", "Load a versioned governance analysis configuration")
    .option("--include-models", "Include the normalized governance model in JSON output")
    .option("--include-rule <id>", "Only run a rule (repeatable)", collect, [])
    .option("--exclude-rule <id>", "Skip a rule (repeatable)", collect, [])
    .option("--max-source-bytes <n>", "Maximum bytes per Solidity source", positiveInteger)
    .option("--max-files <n>", "Maximum number of Solidity files", positiveInteger)
    .option("--max-contracts <n>", "Maximum contracts per Solidity file", positiveInteger)
    .option("--max-functions <n>", "Maximum functions per file and contract", positiveInteger)
    .option("--max-operations <n>", "Maximum modeled operations per function", positiveInteger)
    .option("--max-findings <n>", "Maximum findings in the report", positiveInteger)
    .option(
      "--fail-on <severity>",
      "Exit 1 when this severity or higher is present: none|info|low|medium|high|critical",
      "high",
    )
    .action((targets: string[], raw: GovernanceCliOptions) => {
      const json = raw.format === "json";
      if (!json && raw.format === "markdown") printBanner();
      try {
        validateFormat(raw.format);
        validateFailSeverity(raw.failOn);
        const configured = raw.config ? loadGovernanceConfigFile(raw.config) : undefined;
        const includeRules = raw.includeRule.length
          ? validateRules(raw.includeRule, "--include-rule")
          : configured?.config.includeRules;
        const excludeRules = raw.excludeRule.length
          ? validateRules(raw.excludeRule, "--exclude-rule")
          : configured?.config.excludeRules;
        rejectOverlap(includeRules, excludeRules);
        const limits: Partial<GovernanceAnalysisLimits> = {
          ...configured?.config.limits,
          ...(raw.maxSourceBytes ? { maxSourceBytes: raw.maxSourceBytes } : {}),
          ...(raw.maxFiles ? { maxFiles: raw.maxFiles } : {}),
          ...(raw.maxContracts ? { maxContracts: raw.maxContracts } : {}),
          ...(raw.maxFunctions ? {
            maxFunctionsPerFile: raw.maxFunctions,
            maxFunctionsPerContract: raw.maxFunctions,
          } : {}),
          ...(raw.maxOperations ? { maxOperationsPerFunction: raw.maxOperations } : {}),
          ...(raw.maxFindings ? { maxFindings: raw.maxFindings } : {}),
        };
        const options: GovernanceAnalysisOptions = {
          limits,
          includeModels: raw.includeModels ?? configured?.config.includeModels ?? false,
          ...(includeRules ? { includeRules } : {}),
          ...(excludeRules ? { excludeRules } : {}),
        };
        const report = analyzeGovernanceFiles(targets, options);
        const output = raw.format === "json"
          ? serializeGovernanceReport(report)
          : generateGovernanceMarkdown(report);
        if (raw.output) {
          writeReport(raw.output, output);
          if (!json) console.log(chalk.green(`\n  Governance report written to ${raw.output}`));
        } else {
          process.stdout.write(output);
        }
        process.exit(exitCode(report, raw.failOn));
      } catch (error) {
        const message = error instanceof GovernanceConfigError ||
          error instanceof GovernanceAnalysisCancelledError || error instanceof Error
          ? error.message
          : "Governance analysis failed";
        console.error(chalk.red(`Governance analysis error: ${sanitize(message)}`));
        process.exit(2);
      }
    });
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function positiveInteger(value: string): number {
  if (!/^\d+$/.test(value)) throw new GovernanceConfigError("analysis limits must be positive integers");
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result <= 0) {
    throw new GovernanceConfigError("analysis limits must be positive safe integers");
  }
  return result;
}

function validateRules(values: string[], option: string): GovernanceRuleId[] {
  const result = new Set<GovernanceRuleId>();
  for (const value of values) {
    if (!RULE_PATTERN.test(value)) throw new GovernanceConfigError(`${option} contains unknown rule ${value}`);
    result.add(value as GovernanceRuleId);
  }
  return [...result].sort();
}

function rejectOverlap(include: GovernanceRuleId[] | undefined, exclude: GovernanceRuleId[] | undefined): void {
  if (!include || !exclude) return;
  const overlap = include.filter((rule) => exclude.includes(rule));
  if (overlap.length) throw new GovernanceConfigError(`included and excluded rules overlap: ${overlap.join(", ")}`);
}

function validateFormat(value: string): asserts value is OutputFormat {
  if (value !== "json" && value !== "markdown") {
    throw new GovernanceConfigError("--format must be json or markdown");
  }
}

function validateFailSeverity(value: string): asserts value is FailSeverity {
  if (!(value in SEVERITY_RANK)) {
    throw new GovernanceConfigError("--fail-on must be none, info, low, medium, high, or critical");
  }
}

function exitCode(report: GovernanceAnalysisReport, threshold: FailSeverity): number {
  const rank = SEVERITY_RANK[threshold];
  return report.files.some((file) => file.findings.some((finding) =>
    SEVERITY_RANK[finding.severity] >= rank,
  )) ? 1 : 0;
}

function sanitize(message: string): string {
  return message.replace(/[\r\n]+/g, " ").slice(0, 500);
}

function writeReport(file: string, output: string): void {
  try {
    fs.writeFileSync(file, output, "utf8");
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    const safeCode = typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : "IO_ERROR";
    throw new GovernanceConfigError(`report file could not be written (${safeCode})`);
  }
}
