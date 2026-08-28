import * as fs from "fs";
import chalk from "chalk";
import type { Command } from "commander";
import {
  analyzeStakingProject,
  loadStakingConfigFile,
  serializeStakingReportJSON,
  serializeStakingReportMarkdown,
  StakingAnalysisCancelledError,
  StakingConfigError,
  type StakingAnalysisLimits,
  type StakingAnalysisOptions,
  type StakingRuleId,
} from "@chainproof/core";

interface StakingCommandOptions {
  format: "json" | "markdown";
  output?: string;
  config?: string;
  includeModels?: boolean;
  maxSourceBytes?: string;
  maxFiles?: string;
  maxFindings?: string;
  includeRule: string[];
  excludeRule: string[];
  failOn: "critical" | "high" | "medium" | "low" | "none";
}

const RULE_PATTERN = /^CP-STK-(?:00[1-9]|01[0-3])$/;

/** Register the deterministic staking/reward/vesting analysis CLI surface. */
export function registerStakingCommand(program: Command): void {
  program
    .command("staking <targets...>")
    .description("Analyze staking, reward distribution, and vesting accounting")
    .option("--format <format>", "Output format: json|markdown", "markdown")
    .option("--output <file>", "Write the versioned report to a file")
    .option("--config <file>", "Load a versioned staking analysis configuration")
    .option("--include-models", "Include normalized accounting models in JSON output")
    .option("--max-source-bytes <number>", "Maximum UTF-8 bytes analyzed per source")
    .option("--max-files <number>", "Maximum number of Solidity files analyzed")
    .option("--max-findings <number>", "Maximum findings returned by the analysis")
    .option(
      "--include-rule <id>",
      "Run only a CP-STK rule (repeatable)",
      collectOption,
      [],
    )
    .option(
      "--exclude-rule <id>",
      "Skip a CP-STK rule (repeatable)",
      collectOption,
      [],
    )
    .option(
      "--fail-on <severity>",
      "Exit 1 at or above: critical|high|medium|low|none",
      "high",
    )
    .action((targets: string[], rawOptions: StakingCommandOptions) => {
      try {
        const options = buildOptions(rawOptions);
        const report = analyzeStakingProject(targets, options);
        const output = rawOptions.format === "json"
          ? serializeStakingReportJSON(report)
          : serializeStakingReportMarkdown(report);

        if (rawOptions.output) {
          fs.writeFileSync(rawOptions.output, output, "utf8");
          console.log(chalk.green(`Staking accounting report written to ${rawOptions.output}`));
        } else {
          process.stdout.write(output);
        }

        if (exceedsThreshold(report.summary, rawOptions.failOn)) {
          process.exitCode = 1;
        }
      } catch (error) {
        const message = safeCliError(error);
        console.error(chalk.red(`Staking analysis failed: ${message}`));
        process.exitCode = 2;
      }
    });
}

function buildOptions(raw: StakingCommandOptions): StakingAnalysisOptions {
  if (raw.format !== "json" && raw.format !== "markdown") {
    throw new Error("--format must be json or markdown");
  }
  if (!new Set(["critical", "high", "medium", "low", "none"]).has(raw.failOn)) {
    throw new Error("--fail-on must be critical, high, medium, low, or none");
  }
  const fromFile = raw.config ? loadStakingConfigFile(raw.config).config : undefined;
  const limits: Partial<StakingAnalysisLimits> = { ...(fromFile?.limits ?? {}) };
  setIntegerLimit(limits, "maxSourceBytes", raw.maxSourceBytes);
  setIntegerLimit(limits, "maxFiles", raw.maxFiles);
  setIntegerLimit(limits, "maxFindings", raw.maxFindings);

  const cliIncludes = validateRuleIds(raw.includeRule, "--include-rule");
  const cliExcludes = validateRuleIds(raw.excludeRule, "--exclude-rule");
  const includeRules = cliIncludes.length > 0 ? cliIncludes : fromFile?.includeRules;
  const excludeRules = cliExcludes.length > 0 ? cliExcludes : fromFile?.excludeRules;
  if (includeRules && excludeRules) {
    const overlap = includeRules.filter((rule) => excludeRules.includes(rule));
    if (overlap.length > 0) throw new Error(`included and excluded rules overlap: ${overlap.join(", ")}`);
  }

  return {
    ...(Object.keys(limits).length > 0 ? { limits } : {}),
    includeModels: raw.includeModels ?? fromFile?.includeModels ?? false,
    ...(includeRules ? { includeRules } : {}),
    ...(excludeRules ? { excludeRules } : {}),
  };
}

function setIntegerLimit(
  limits: Partial<StakingAnalysisLimits>,
  key: keyof StakingAnalysisLimits,
  raw: string | undefined,
): void {
  if (raw === undefined) return;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`--${toKebabCase(key)} must be a positive integer`);
  }
  limits[key] = value;
}

function validateRuleIds(values: string[], option: string): StakingRuleId[] {
  const result = new Set<StakingRuleId>();
  for (const value of values) {
    if (!RULE_PATTERN.test(value)) throw new Error(`${option} contains unknown rule ${value}`);
    result.add(value as StakingRuleId);
  }
  return [...result].sort();
}

function collectOption(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function exceedsThreshold(
  summary: { critical: number; high: number; medium: number; low: number },
  threshold: StakingCommandOptions["failOn"],
): boolean {
  if (threshold === "none") return false;
  const rank = { critical: 4, high: 3, medium: 2, low: 1 } as const;
  const minimum = rank[threshold];
  return (Object.keys(rank) as Array<keyof typeof rank>)
    .some((severity) => rank[severity] >= minimum && summary[severity] > 0);
}

function toKebabCase(value: string): string {
  return value.replace(/[A-Z]/g, (character) => `-${character.toLowerCase()}`);
}

function safeCliError(error: unknown): string {
  if (error instanceof StakingConfigError || error instanceof StakingAnalysisCancelledError) {
    return error.message;
  }
  const code = (error as { code?: unknown } | null)?.code;
  if (typeof code === "string" && /^[A-Z0-9_]+$/.test(code)) {
    return `I/O operation failed (${code})`;
  }
  if (error instanceof Error && !/[\\/]/.test(error.message)) return error.message;
  return "analysis operation failed";
}
