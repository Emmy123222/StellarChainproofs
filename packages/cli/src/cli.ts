#!/usr/bin/env node
import "dotenv/config";
import { program } from "commander";
import chalk from "chalk";
import ora from "ora";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import {
  scan,
  generateMarkdownReport,
  generateJSONReport,
  generateTableReport,
  generateMarkdownDiffReport,
  generateJSONDiffReport,
  generateTableDiffReport,
  diffScans,
  clearCache,
  isSlitherAvailable,
  loadPlugins,
  loadConfigFile,
  mergePluginsFromConfig,
  generateThreatModel,
  generateMarkdownThreatModel,
  generateJSONThreatModel,
} from "@chainproof/core";
import type { ScanConfig, ScanResult } from "@chainproof/core";
import type { ServerOptions } from "@chainproof/server";
import { registerWatchCommand } from "./commands/watch";
import { registerInvariantsCommand } from "./commands/invariants";

// ─── ASCII Banner ─────────────────────────────────────────────────────────────

function printBanner() {
  console.log(
    chalk.cyan(`
  ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗██████╗ ██████╗  ██████╗  ██████╗ ███████╗
 ██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
 ██║     ███████║███████║██║██╔██╗ ██║██████╔╝██████╔╝██║   ██║██║   ██║█████╗
 ██║     ██╔══██║██╔══██║██║██║╚██╗██║██╔═══╝ ██╔══██╗██║   ██║██║   ██║██╔══╝
 ╚██████╗██║  ██║██║  ██║██║██║ ╚████║██║     ██║  ██║╚██████╔╝╚██████╔╝██║
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝
`),
  );
  console.log(
    chalk.gray(
      "  Smart Contract Audit Copilot — vulnerability scanner + gas advisor\n",
    ),
  );
}

// ─── scan command ─────────────────────────────────────────────────────────────

program
  .name("chainproof")
  .description("Smart contract security scanner and audit report generator")
  .version("0.1.0");

program
  .command("scan <targets...>")
  .description("Scan one or more .sol files or directories")
  .option("--no-slither", "Skip Slither analysis even if installed")
  .option("--no-llm", "Skip LLM enhancement of findings")
  .option("--no-metrics", "Skip complexity/maintainability metric computation")
  .option(
    "--api-key <key>",
    "Anthropic API key (or set ANTHROPIC_API_KEY env var)",
  )
  .option(
    "--llm-provider <provider>",
    "LLM provider identifier (e.g. anthropic, openai). Defaults to anthropic"
  )
  .option(
    "--llm-model <model>",
    "LLM model identifier (provider-specific)"
  )

  .option(
    "--diff <git-ref>",
    "Compare scan results against specified git reference"
  )
  .option(
    "--min-severity <level>",
    "Minimum severity to report: critical|high|medium|low|info",
    "low",
  )
  .option("--format <format>", "Output format: table|json|markdown", "table")
  .option("--output <file>", "Write report to file instead of stdout")
  .option(
    "--plugin <plugin>",
    "Load a custom plugin (can be used multiple times)",
    (value: string, previous: string[]) => [...(previous || []), value],
    [],
  )
  .action(
    async (
      targets: string[],
      opts: {
        slither: boolean;
        llm: boolean;
        metrics: boolean;
        apiKey?: string;
        llmProvider?: string;
        llmModel?: string;
        diff?: string;
        minSeverity: string;
        format: string;
        output?: string;
        plugin: string[];
      },
    ) => {

      printBanner();

      const apiKey = opts.apiKey ?? process.env.ANTHROPIC_API_KEY;
      const useLLM = opts.llm && !!apiKey;
      const useMetrics = opts.metrics;

      const llmProvider = opts.llmProvider ?? "anthropic";
      const llmModel = opts.llmModel;


      if (opts.llm && !apiKey) {
        console.warn(
          chalk.yellow(
            "  ⚠️  LLM enhancement disabled — no API key found.\n" +
              "     Set ANTHROPIC_API_KEY or pass --api-key <key>\n",
          ),
        );
      }

      const slitherAvailable = isSlitherAvailable();
      const useSlither = opts.slither && slitherAvailable;

      if (opts.slither && !slitherAvailable) {
        console.warn(
          chalk.yellow(
            "  ⚠️  Slither not found. Install with: pip install slither-analyzer\n",
          ),
        );
      }

      // Load plugins from CLI or config file
      let plugins = [];
      if (opts.plugin.length > 0) {
        plugins = loadPlugins(opts.plugin);
      } else {
        const configFile = loadConfigFile();
        const merged = mergePluginsFromConfig(
          {
            targets,
            useSlither,
            useLLM,
            useMetrics,
            apiKey,
            minSeverity: opts.minSeverity as ScanConfig["minSeverity"],
          },
          configFile,
        );
        plugins = merged.plugins || [];
      }

      console.log(
        chalk.gray(
          `  Targets  : ${targets.join(", ")}\n` +
            `  Slither  : ${useSlither ? chalk.green("enabled") : chalk.gray("disabled")}\n` +
            `  LLM      : ${useLLM ? chalk.green("enabled") : chalk.gray("disabled")}\n` +
            `  Plugins  : ${plugins.length > 0 ? chalk.green(`${plugins.length} loaded`) : chalk.gray("none")}\n` +
            `  Diff     : ${opts.diff ? chalk.cyan(opts.diff) : chalk.gray("none")}\n` +
            `  Severity : ${opts.minSeverity}+\n`,
        ),
      );

      const spinner = ora("Scanning contracts...").start();

      const config: ScanConfig = {
        targets,
        useSlither,
        useLLM,
        useMetrics,
        apiKey,
        minSeverity: opts.minSeverity as ScanConfig["minSeverity"],
        outputFormat: opts.format as ScanConfig["outputFormat"],
        plugins,
      };

      let result;
      try {
        result = await scan(config);
        spinner.succeed(`Scanned ${result.files.length} file(s)`);
      } catch (err) {
        spinner.fail("Scan failed");
        console.error(chalk.red(`\n  Error: ${err}`));
        process.exit(1);
      }

      // ── Handle diff against git ref if --diff is specified ─────────────────
      if (opts.diff) {
        const diffSpinner = ora(`Scanning base git ref (${opts.diff})...`).start();
        let oldResult: ScanResult;
        try {
          oldResult = await scanGitRef(opts.diff, config);
          diffSpinner.succeed(`Scanned base git ref (${opts.diff})`);
        } catch (err) {
          diffSpinner.fail(`Failed to scan git ref (${opts.diff})`);
          console.error(chalk.red(`\n  Error: ${err}`));
          process.exit(1);
        }

        const diff = diffScans(oldResult, result);
        let diffReport: string;
        switch (opts.format) {
          case "json":
            diffReport = generateJSONDiffReport(diff);
            break;
          case "markdown":
            diffReport = generateMarkdownDiffReport(diff);
            break;
          default:
            diffReport = generateTableDiffReport(diff);
        }

        if (opts.output) {
          fs.writeFileSync(opts.output, diffReport, "utf-8");
          console.log(chalk.green(`\n  ✅ Diff report written to ${opts.output}`));
        } else {
          console.log(diffReport);
        }

        if (diff.summary.newCritical > 0 || diff.summary.newHigh > 0) {
          console.log(
            chalk.red(
              `\n  ❌ ${diff.summary.newCritical} new critical, ${diff.summary.newHigh} new high severity issues introduced.\n`
            )
          );
          process.exit(1);
        } else {
          process.exit(0);
        }
      }

      // ── Generate report ────────────────────────────────────────────────────
      let report: string;
      switch (opts.format) {
        case "json":
          report = generateJSONReport(result);
          break;
        case "markdown":
          report = generateMarkdownReport(result);
          break;
        default:
          report = generateTableReport(result);
      }

      if (opts.output) {
        fs.writeFileSync(opts.output, report, "utf-8");
        console.log(chalk.green(`\n  ✅ Report written to ${opts.output}`));
      } else {
        console.log(report);
      }

      // ── Markdown also auto-saved when piped to file ───────────────────────
      if (!opts.output && opts.format === "table") {
        const mdPath = path.join(process.cwd(), "chainproof-report.md");
        fs.writeFileSync(mdPath, generateMarkdownReport(result), "utf-8");
        console.log(chalk.gray(`\n  💾 Full report saved to ${mdPath}`));
      }

      // ── Exit code: non-zero if critical/high found ─────────────────────────
      const { critical, high } = result.summary;
      if (critical > 0 || high > 0) {
        console.log(
          chalk.red(
            `\n  ❌ ${critical} critical, ${high} high severity issues found.\n` +
              "     Resolve these before deploying to mainnet.\n",
          ),
        );
        process.exit(1);
      } else if (result.summary.total > 0) {
        console.log(
          chalk.yellow(
            `\n  ⚠️  ${result.summary.total} findings. Review before deploying.\n`,
          ),
        );
      } else {
        console.log(
          chalk.green("\n  ✅ No issues detected. Stay safe out there.\n"),
        );
      }
    },
  );

// ─── scanGitRef helper ────────────────────────────────────────────────────────

async function scanGitRef(gitRef: string, config: ScanConfig): Promise<ScanResult> {
  const isDirty = execSync("git status --porcelain", { encoding: "utf-8" }).trim().length > 0;
  let currentRef = "";
  try {
    currentRef = execSync("git symbolic-ref --short -q HEAD", { encoding: "utf-8" }).trim();
    if (!currentRef) {
      currentRef = execSync("git rev-parse HEAD", { encoding: "utf-8" }).trim();
    }
  } catch {
    currentRef = execSync("git rev-parse HEAD", { encoding: "utf-8" }).trim();
  }

  let stashed = false;
  if (isDirty) {
    execSync("git stash push -m 'chainproof-diff-tmp'", { stdio: "ignore" });
    stashed = true;
  }

  try {
    execSync(`git checkout ${gitRef}`, { stdio: "ignore" });
    clearCache();
    return await scan(config);
  } finally {
    execSync(`git checkout ${currentRef}`, { stdio: "ignore" });
    if (stashed) {
      execSync("git stash pop", { stdio: "ignore" });
    }
    clearCache();
  }
}

// ─── diff command ─────────────────────────────────────────────────────────────

program
  .command("diff <oldJson> <newJson>")
  .description("Compare two JSON scan reports and surface vulnerability regressions")
  .option("--format <format>", "Output format: table|json|markdown", "table")
  .option("--output <file>", "Write diff report to file instead of stdout")
  .option(
    "--min-severity <level>",
    "Minimum severity of introduced findings to fail CI: critical|high|medium|low",
    "high"
  )
  .action((oldJsonPath: string, newJsonPath: string, opts: { format: string; output?: string; minSeverity: string }) => {
    printBanner();

    if (!fs.existsSync(oldJsonPath)) {
      console.error(chalk.red(`  ❌ File not found: ${oldJsonPath}`));
      process.exit(1);
    }
    if (!fs.existsSync(newJsonPath)) {
      console.error(chalk.red(`  ❌ File not found: ${newJsonPath}`));
      process.exit(1);
    }

    try {
      const oldResult: ScanResult = JSON.parse(fs.readFileSync(oldJsonPath, "utf-8"));
      const newResult: ScanResult = JSON.parse(fs.readFileSync(newJsonPath, "utf-8"));

      const diff = diffScans(oldResult, newResult);

      let report: string;
      switch (opts.format) {
        case "json":
          report = generateJSONDiffReport(diff);
          break;
        case "markdown":
          report = generateMarkdownDiffReport(diff);
          break;
        default:
          report = generateTableDiffReport(diff);
      }

      if (opts.output) {
        fs.writeFileSync(opts.output, report, "utf-8");
        console.log(chalk.green(`\n  ✅ Diff report written to ${opts.output}`));
      } else {
        console.log(report);
      }

      const RANK: Record<string, number> = {
        critical: 5, high: 4, medium: 3, low: 2, info: 1,
      };
      const minRank = RANK[opts.minSeverity] ?? 4;
      const introducedFailures = diff.introduced.filter((f) => (RANK[f.severity] ?? 0) >= minRank);

      if (introducedFailures.length > 0) {
        console.log(
          chalk.red(
            `\n  ❌ ${introducedFailures.length} newly introduced ${opts.minSeverity}+ finding(s) detected.\n`
          )
        );
        process.exit(1);
      } else {
        console.log(chalk.green("\n  ✅ No new regressions detected.\n"));
        process.exit(0);
      }
    } catch (err) {
      console.error(chalk.red(`  ❌ Failed to parse or diff scan reports: ${err}`));
      process.exit(1);
    }
  });

// ─── check command (fast pass/fail for CI) ────────────────────────────────────

program
  .command("check <targets...>")
  .description("Fast pass/fail check — exits 1 if critical/high issues found")
  .option("--no-slither", "Skip Slither")
  .option("--no-metrics", "Skip complexity/maintainability metric computation")
  .option("--api-key <key>", "Anthropic API key")
  .action(
    async (targets: string[], opts: { slither: boolean; metrics?: boolean; apiKey?: string }) => {
      const spinner = ora("Running security check...").start();

      const config: ScanConfig = {
        targets,
        useSlither: opts.slither && isSlitherAvailable(),
        useLLM: false,
        useMetrics: opts.metrics ?? true,
        minSeverity: "high",
      };

      try {
        const result = await scan(config);
        const { critical, high } = result.summary;

        if (critical > 0 || high > 0) {
          spinner.fail(
            `FAIL — ${critical} critical, ${high} high severity issues found`,
          );
          result.files.forEach((f) => {
            f.findings.forEach((finding) => {
              if (
                finding.severity === "critical" ||
                finding.severity === "high"
              ) {
                console.error(
                  chalk.red(
                    `  [${finding.severity.toUpperCase()}] ${f.file}:${finding.line} — ${finding.title}`,
                  ),
                );
              }
            });
          });
          process.exit(1);
        } else {
          spinner.succeed(
            `PASS — ${result.files.length} file(s) checked, no critical/high issues`,
          );
          process.exit(0);
        }
      } catch (err) {
        spinner.fail(`Check failed: ${err}`);
        process.exit(1);
      }
    },
  );

// ─── init command — generate .chainproofrc config ────────────────────────────

program
  .command("init")
  .description(
    "Create a .chainproofrc.json config file in the current directory",
  )
  .action(() => {
    const config = {
      targets: ["contracts/"],
      useSlither: true,
      useLLM: true,
      minSeverity: "low",
      outputFormat: "markdown",
      output: "audit-report.md",
      plugins: [],
    };
    const configPath = path.join(process.cwd(), ".chainproofrc.json");
    if (fs.existsSync(configPath)) {
      console.log(chalk.yellow("  ⚠️  .chainproofrc.json already exists"));
      process.exit(0);
    }
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf-8");
    console.log(chalk.green("  ✅ Created .chainproofrc.json"));
    console.log(chalk.gray("  Edit it to configure your targets and options."));
  });

// ─── serve command — start the REST API server ───────────────────────────────

program
  .command("serve")
  .description("Start the ChainProof REST API server")
  .option("--port <number>", "Port to listen on", "4243")
  .option("--host <host>", "Host/IP to bind", "127.0.0.1")
  .option("--token <token>", "Bearer token for authentication (optional)")
  .option("--allow-fs", "Allow POST /scan/file to scan server-side file paths")
  .option(
    "--max-requests <number>",
    "Max scan requests per minute (rate limit)",
    "10"
  )
  .option(
    "--body-limit <size>",
    "Max request body size (e.g. 5mb)",
    "5mb"
  )
  .action(
    async (opts: {
      port: string;
      host: string;
      token?: string;
      allowFs?: boolean;
      maxRequests: string;
      bodyLimit: string;
    }) => {
      printBanner();

      const port = parseInt(opts.port, 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        console.error(chalk.red("  ❌ Invalid port number"));
        process.exit(1);
      }

      const maxRequests = parseInt(opts.maxRequests, 10);
      if (isNaN(maxRequests) || maxRequests < 1) {
        console.error(chalk.red("  ❌ --max-requests must be a positive integer"));
        process.exit(1);
      }

      const serverOpts: ServerOptions = {
        port,
        host: opts.host,
        token: opts.token,
        allowFs: opts.allowFs ?? false,
        maxRequests,
        bodySizeLimit: opts.bodyLimit,
      };

      if (opts.token) {
        console.log(chalk.green("  🔐 Bearer token auth enabled"));
      } else {
        console.log(
          chalk.yellow(
            "  ⚠️  No bearer token set — server is open. " +
            "Use --token <secret> for non-localhost bindings."
          )
        );
      }

      try {
        // Dynamically import to avoid loading Express unless `serve` is used
        const { startServer } = await import("@chainproof/server");
        await startServer(serverOpts);
      } catch (err) {
        console.error(chalk.red(`\n  ❌ Failed to start server: ${err}`));
        process.exit(1);
      }
    }
  );

// ─── threat-model command ───────────────────────────────────────────────────

program
  .command("threat-model <targets...>")
  .description("Generate a comprehensive threat model for the target smart contracts")
  .option(
    "--assumptions <file>",
    "Path to a JSON file containing user-provided assumptions/overrides"
  )
  .option(
    "--min-severity <level>",
    "Minimum severity of threats to prioritize: critical|high|medium|low",
    "low"
  )
  .option(
    "--format <format>",
    "Output format: markdown|json",
    "markdown"
  )
  .option(
    "--output <file>",
    "Write threat model report to file instead of stdout"
  )
  .action(
    async (
      targets: string[],
      opts: {
        assumptions?: string;
        minSeverity: string;
        format: "markdown" | "json";
        output?: string;
      }
    ) => {
      const isJson = opts.format === "json";
      if (!isJson) {
        printBanner();
      }

      const spinner = isJson ? null : ora("Generating threat model...").start();

      try {
        const model = await generateThreatModel({
          targets,
          assumptionsPath: opts.assumptions,
          minSeverity: opts.minSeverity as any,
        });

        if (spinner) {
          spinner.succeed(`Threat model generated successfully with ${model.threats.length} threat(s)`);
        }

        let reportStr: string;
        if (isJson) {
          reportStr = generateJSONThreatModel(model);
        } else {
          reportStr = generateMarkdownThreatModel(model);
        }

        if (opts.output) {
          fs.writeFileSync(opts.output, reportStr, "utf-8");
          console.log(chalk.green(`\n  ✅ Threat model written to ${opts.output}`));
        } else {
          console.log(reportStr);
        }
      } catch (err) {
        if (spinner) {
          spinner.fail("Threat model generation failed");
        }
        console.error(chalk.red(`\n  Error: ${err}`));
        process.exit(1);
      }
    }
  );

registerWatchCommand(program, printBanner);
registerInvariantsCommand(program, printBanner);

program.parse();
