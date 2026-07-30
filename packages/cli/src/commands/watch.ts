import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import chokidar from "chokidar";
import * as fs from "fs";
import * as path from "path";
import {
  scan,
  createWatchScanState,
  scanIncremental,
  generateTableReport,
  isSlitherAvailable,
  loadPlugins,
  loadConfigFile,
  mergePluginsFromConfig,
} from "@chainproof/core";
import type {
  ASTCacheStats,
  ScanConfig,
  ScanResult,
  WatchScanState,
} from "@chainproof/core";

export interface WatchOptions {
  slither: boolean;
  llm: boolean;
  metrics: boolean;
  apiKey?: string;
  llmProvider?: string;
  llmModel?: string;
  minSeverity: string;
  plugin: string[];
  debounce: number;
  verbose: boolean;
  once: boolean;
}

export interface Debouncer {
  schedule: (...args: unknown[]) => void;
  flush: () => void;
  cancel: () => void;
  pendingCount: () => number;
}

/** Collapse rapid successive calls into a single invocation after `delayMs`. */
export function createDebouncer(
  delayMs: number,
  fn: (...args: unknown[]) => void | Promise<void>
): Debouncer {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let pendingArgs: unknown[] | undefined;
  let scheduled = 0;

  const run = () => {
    timer = undefined;
    scheduled = 0;
    const args = pendingArgs ?? [];
    pendingArgs = undefined;
    void fn(...args);
  };

  return {
    schedule: (...args: unknown[]) => {
      pendingArgs = args;
      scheduled++;
      if (timer) clearTimeout(timer);
      timer = setTimeout(run, delayMs);
    },
    flush: () => {
      if (timer) {
        clearTimeout(timer);
        run();
      }
    },
    cancel: () => {
      if (timer) clearTimeout(timer);
      timer = undefined;
      pendingArgs = undefined;
      scheduled = 0;
    },
    pendingCount: () => scheduled,
  };
}

function resolveWatchPaths(targets: string[]): string[] {
  const paths: string[] = [];
  for (const target of targets) {
    if (!fs.existsSync(target)) continue;
    const stat = fs.statSync(target);
    if (stat.isDirectory() || target.endsWith(".sol")) {
      paths.push(path.resolve(target));
    }
  }
  return paths;
}

function buildScanConfig(
  targets: string[],
  opts: WatchOptions
): ScanConfig {
  const apiKey = opts.apiKey ?? process.env.ANTHROPIC_API_KEY;
  const useLLM = opts.llm && !!apiKey;
  const useSlither = opts.slither && isSlitherAvailable();

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
        useMetrics: opts.metrics,
        apiKey,
        minSeverity: opts.minSeverity as ScanConfig["minSeverity"],
      },
      configFile
    );
    plugins = merged.plugins || [];
  }

  return {
    targets,
    useSlither,
    useLLM,
    useMetrics: opts.metrics,
    apiKey,
    llmProvider: opts.llmProvider ?? "anthropic",
    llmModel: opts.llmModel,
    minSeverity: opts.minSeverity as ScanConfig["minSeverity"],
    outputFormat: "table",
    plugins,
  };
}

function computeExitCode(result: ScanResult): number {
  const { critical, high } = result.summary;
  return critical > 0 || high > 0 ? 1 : 0;
}

function collectRecentFindings(result: ScanResult, limit = 8) {
  const severityRank: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
    gas: 0,
  };

  return result.files
    .flatMap((file) =>
      file.findings.map((finding) => ({
        ...finding,
        file: file.file,
      }))
    )
    .sort(
      (a, b) =>
        (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0)
    )
    .slice(0, limit);
}

export function formatWatchSummary(
  result: ScanResult,
  meta: {
    rescannedFiles?: string[];
    cacheStats?: ASTCacheStats;
    targets?: string[];
  } = {}
): string {
  const lines: string[] = [];
  const { summary } = result;

  lines.push(chalk.cyan.bold("  ChainProof Watch"));
  lines.push("");
  lines.push(
    chalk.gray(
      `  Targets  : ${(meta.targets ?? []).join(", ") || "(none)"}\n` +
        `  Files    : ${result.files.length}\n` +
        `  Updated  : ${result.timestamp}`
    )
  );
  lines.push("");
  lines.push(
    `  ${chalk.red("Critical")}: ${summary.critical}` +
      `  ${chalk.yellow("High")}: ${summary.high}` +
      `  ${chalk.hex("#FFA500")("Medium")}: ${summary.medium}` +
      `  Low: ${summary.low}` +
      `  Info: ${summary.info}` +
      `  Gas: ${summary.gas}`
  );
  lines.push(`  Total findings: ${summary.total}`);

  if (meta.cacheStats) {
    lines.push(
      chalk.gray(
        `  AST cache: ${meta.cacheStats.hits} hit(s), ${meta.cacheStats.misses} miss(es)`
      )
    );
  }

  if (meta.rescannedFiles && meta.rescannedFiles.length > 0) {
    lines.push(
      chalk.gray(
        `  Re-scanned: ${meta.rescannedFiles.map((f) => path.basename(f)).join(", ")}`
      )
    );
  }

  lines.push("");
  lines.push(chalk.gray("  Recent findings:"));

  const recent = collectRecentFindings(result);
  if (recent.length === 0) {
    lines.push(chalk.green("    (none)"));
  } else {
    for (const finding of recent) {
      const color =
        finding.severity === "critical" || finding.severity === "high"
          ? chalk.red
          : finding.severity === "medium"
            ? chalk.yellow
            : chalk.gray;
      lines.push(
        color(
          `    [${finding.severity.toUpperCase()}] ${path.basename(finding.file)}:${finding.line} — ${finding.title}`
        )
      );
    }
  }

  lines.push("");
  lines.push(chalk.gray("  Press Ctrl+C to exit"));
  return lines.join("\n");
}

export function renderWatchOutput(
  content: string,
  opts: { isTty: boolean; verbose: boolean }
): void {
  if (!opts.isTty || opts.verbose) {
    console.log(content);
    return;
  }

  process.stdout.write("\x1b[H\x1b[J" + content);
}

async function runOnceScan(
  targets: string[],
  opts: WatchOptions,
  printBanner: () => void
): Promise<number> {
  printBanner();

  const config = buildScanConfig(targets, opts);
  const spinner = ora("Scanning contracts...").start();

  try {
    const result = await scan(config);
    spinner.succeed(`Scanned ${result.files.length} file(s)`);
    console.log(generateTableReport(result));

    const exitCode = computeExitCode(result);
    const { critical, high, total } = result.summary;
    if (exitCode === 1) {
      console.log(
        chalk.red(
          `\n  ❌ ${critical} critical, ${high} high severity issues found.\n`
        )
      );
    } else if (total > 0) {
      console.log(
        chalk.yellow(`\n  ⚠️  ${total} findings. Review before deploying.\n`)
      );
    } else {
      console.log(chalk.green("\n  ✅ No issues detected.\n"));
    }

    return exitCode;
  } catch (err) {
    spinner.fail("Scan failed");
    console.error(chalk.red(`\n  Error: ${err}`));
    return 1;
  }
}

async function runWatchLoop(
  targets: string[],
  opts: WatchOptions,
  printBanner: () => void
): Promise<number> {
  printBanner();

  const config = buildScanConfig(targets, opts);
  const isTty = process.stdout.isTTY === true;
  let state: WatchScanState;
  let lastExitCode = 0;

  const initialSpinner = ora("Initial scan...").start();
  try {
    state = await createWatchScanState(config);
    initialSpinner.succeed(`Watching ${state.allFiles.length} file(s)`);
  } catch (err) {
    initialSpinner.fail("Initial scan failed");
    console.error(chalk.red(`\n  Error: ${err}`));
    return 1;
  }

  const render = (
    result: ScanResult,
    meta: {
      rescannedFiles?: string[];
      cacheStats?: ASTCacheStats;
    } = {}
  ) => {
    lastExitCode = computeExitCode(result);
    renderWatchOutput(
      formatWatchSummary(result, { ...meta, targets }),
      { isTty, verbose: opts.verbose }
    );
  };

  render(state.result);

  const watchPaths = resolveWatchPaths(targets);
  if (watchPaths.length === 0) {
    console.error(chalk.red("  ❌ No valid watch targets found"));
    return 1;
  }

  let rescanInFlight = false;
  const pendingChanges = new Set<string>();

  const debouncer = createDebouncer(opts.debounce, async () => {
    if (rescanInFlight) return;
    rescanInFlight = true;

    const changedFiles = [...pendingChanges];
    pendingChanges.clear();
    if (changedFiles.length === 0) {
      rescanInFlight = false;
      return;
    }

    try {
      const outcome = await scanIncremental(config, state, changedFiles);
      state = outcome.state;
      render(state.result, {
        rescannedFiles: outcome.rescannedFiles,
        cacheStats: outcome.cacheStats,
      });
    } catch (err) {
      if (opts.verbose || !isTty) {
        console.error(chalk.red(`\n  Re-scan failed: ${err}`));
      }
    } finally {
      rescanInFlight = false;
    }
  });

  const watcher = chokidar.watch(watchPaths, {
    ignoreInitial: true,
    awaitWriteFinish: {
      stabilityThreshold: 100,
      pollInterval: 50,
    },
  });

  const onSolEvent = (filePath: string) => {
    if (!filePath.endsWith(".sol")) return;
    pendingChanges.add(path.resolve(filePath));
    debouncer.schedule(filePath);
  };

  watcher.on("change", onSolEvent);
  watcher.on("add", onSolEvent);

  await new Promise<void>((resolve) => {
    const shutdown = () => {
      debouncer.cancel();
      void watcher.close().finally(() => {
        if (isTty && !opts.verbose) {
          process.stdout.write("\n");
        }
        resolve();
      });
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  });

  return lastExitCode;
}

export function registerWatchCommand(
  program: Command,
  printBanner: () => void
): void {
  program
    .command("watch <targets...>")
    .description(
      "Watch .sol files and re-scan incrementally on save (sub-second feedback loop)"
    )
    .option("--no-slither", "Skip Slither analysis even if installed")
    .option("--no-llm", "Skip LLM enhancement of findings")
    .option("--no-metrics", "Skip complexity/maintainability metric computation")
    .option(
      "--api-key <key>",
      "Anthropic API key (or set ANTHROPIC_API_KEY env var)"
    )
    .option(
      "--llm-provider <provider>",
      "LLM provider identifier (e.g. anthropic, openai). Defaults to anthropic"
    )
    .option("--llm-model <model>", "LLM model identifier (provider-specific)")
    .option(
      "--min-severity <level>",
      "Minimum severity to report: critical|high|medium|low|info",
      "low"
    )
    .option(
      "--plugin <plugin>",
      "Load a custom plugin (can be used multiple times)",
      (value: string, previous: string[]) => [...(previous || []), value],
      []
    )
    .option(
      "--debounce <ms>",
      "Debounce window for file-change events (milliseconds)",
      "300"
    )
    .option(
      "--verbose",
      "Append full scan output on each re-scan instead of live in-place UI"
    )
    .option(
      "--once",
      "Run a single scan and exit (same output/exit codes as scan)"
    )
    .action(async (targets: string[], opts: WatchOptions & { debounce: string }) => {
      const watchOpts: WatchOptions = {
        ...opts,
        debounce: parseInt(String(opts.debounce), 10) || 300,
      };

      if (watchOpts.llm && !(watchOpts.apiKey ?? process.env.ANTHROPIC_API_KEY)) {
        console.warn(
          chalk.yellow(
            "  ⚠️  LLM enhancement disabled — no API key found.\n" +
              "     Set ANTHROPIC_API_KEY or pass --api-key <key>\n"
          )
        );
      }

      if (watchOpts.slither && !isSlitherAvailable()) {
        console.warn(
          chalk.yellow(
            "  ⚠️  Slither not found. Install with: pip install slither-analyzer\n"
          )
        );
      }

      const exitCode = watchOpts.once
        ? await runOnceScan(targets, watchOpts, printBanner)
        : await runWatchLoop(targets, watchOpts, printBanner);

      process.exit(exitCode);
    });
}
