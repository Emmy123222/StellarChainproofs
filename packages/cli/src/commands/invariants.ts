import { Command } from "commander";
import chalk from "chalk";
import * as fs from "fs";
import * as path from "path";
import {
  parseInvariantSpecFile,
  validateInvariantSpecFile,
  checkInvariantsFromFile,
  explainInvariant,
  migrateInvariantSpecFile,
  scaffoldInvariantSpec,
  serializeReport,
  formatRange,
  CURRENT_SPEC_SCHEMA_VERSION,
  SpecValidationError,
} from "@chainproof/core";
import type { Diagnostic, InvariantCheckReport, InvariantResult, InvariantStatus } from "@chainproof/core";

function severityColor(severity: string): (s: string) => string {
  switch (severity) {
    case "critical":
    case "high":
      return chalk.red;
    case "medium":
      return chalk.yellow;
    default:
      return chalk.gray;
  }
}

function statusColor(status: InvariantStatus): (s: string) => string {
  switch (status) {
    case "pass":
      return chalk.green;
    case "fail":
      return chalk.red;
    case "error":
    case "timeout":
      return chalk.yellow;
    default:
      return chalk.gray;
  }
}

function printDiagnostics(diagnostics: Diagnostic[]): void {
  for (const d of diagnostics) {
    const color = d.severity === "error" ? chalk.red : d.severity === "warning" ? chalk.yellow : chalk.gray;
    const location = d.range ? ` (${formatRange(d.range)})` : "";
    console.log(color(`  [${d.code}] ${d.severity.toUpperCase()}${location}: ${d.message}`));
  }
}

function formatResultsTable(report: InvariantCheckReport): string {
  const lines: string[] = [];
  lines.push(chalk.cyan.bold(`\n  Invariant check: ${report.specName} (schema ${report.specSchemaVersion})`));
  lines.push(chalk.gray(`  Targets: ${report.targets.join(", ")}\n`));

  for (const r of report.results) {
    const sColor = statusColor(r.status);
    const sevColor = severityColor(r.severity);
    lines.push(
      `  ${sColor(r.status.toUpperCase().padEnd(7))} ${sevColor(`[${r.severity}]`)} ${r.id} — ${r.title}`,
    );
    lines.push(chalk.gray(`          ${r.contract}${r.function ? `.${r.function}` : ""}: ${r.message}`));
    if (r.counterexample && r.counterexample.locations.length > 0) {
      for (const loc of r.counterexample.locations.slice(0, 2)) {
        lines.push(chalk.gray(`          counterexample: ${loc.file}:${loc.line}`));
      }
    }
  }

  lines.push("");
  const { pass, fail, error, timeout, skipped, total } = report.summary;
  lines.push(
    `  ${chalk.green(`${pass} pass`)}, ${chalk.red(`${fail} fail`)}, ${chalk.yellow(`${error} error`)}, ` +
      `${chalk.yellow(`${timeout} timeout`)}, ${chalk.gray(`${skipped} skipped`)} (${total} total)`,
  );
  if (report.bounded.timeExceeded) {
    lines.push(chalk.yellow("  ⚠️  Evaluation stopped early: total time budget exceeded"));
  }
  if (report.diagnostics.length > 0) {
    lines.push(chalk.cyan("\n  Diagnostics:"));
    for (const d of report.diagnostics) {
      const color = d.severity === "error" ? chalk.red : d.severity === "warning" ? chalk.yellow : chalk.gray;
      const location = d.range ? ` (${formatRange(d.range)})` : "";
      lines.push(color(`  [${d.code}] ${d.severity.toUpperCase()}${location}: ${d.message}`));
    }
  }

  return lines.join("\n");
}

function reportExitCode(report: InvariantCheckReport): number {
  return report.summary.fail > 0 || report.summary.error > 0 ? 1 : 0;
}

export function registerInvariantsCommand(program: Command, printBanner: () => void): void {
  const invariants = program
    .command("invariants")
    .description("Deterministic security invariant specification and checking DSL");

  invariants
    .command("init <specFile>")
    .description("Scaffold a new invariant spec file")
    .option("--contract <name>", "Contract name used in the scaffolded invariant", "MyContract")
    .option("--force", "Overwrite an existing file")
    .action((specFile: string, opts: { contract: string; force?: boolean }) => {
      if (fs.existsSync(specFile) && !opts.force) {
        console.error(chalk.red(`  ❌ ${specFile} already exists. Pass --force to overwrite.`));
        process.exit(1);
      }
      const name = path.basename(specFile).replace(/\.(cpinv\.)?json$/, "");
      const scaffold = scaffoldInvariantSpec(name, opts.contract);
      fs.writeFileSync(specFile, JSON.stringify(scaffold, null, 2) + "\n", "utf-8");
      console.log(chalk.green(`  ✅ Wrote ${specFile} (schemaVersion ${CURRENT_SPEC_SCHEMA_VERSION})`));
      console.log(chalk.gray(`     Edit its 'invariants' array, then run 'chainproof invariants validate ${specFile}'`));
    });

  invariants
    .command("validate <specFile>")
    .description("Parse and validate a spec file without checking it against any contract")
    .option("--format <format>", "Output format: table|json", "table")
    .action((specFile: string, opts: { format: "table" | "json" }) => {
      const { valid, diagnostics } = validateInvariantSpecFile(specFile);

      if (opts.format === "json") {
        console.log(JSON.stringify({ valid, diagnostics }, null, 2));
      } else {
        if (valid) {
          console.log(chalk.green(`  ✅ ${specFile} is valid`));
        } else {
          console.log(chalk.red(`  ❌ ${specFile} failed validation`));
        }
        if (diagnostics.length > 0) {
          console.log("");
          printDiagnostics(diagnostics);
        }
      }
      process.exit(valid ? 0 : 1);
    });

  invariants
    .command("check <specFile> <targets...>")
    .description("Check an invariant spec against one or more Solidity targets")
    .option("--format <format>", "Output format: table|json", "table")
    .option("--output <file>", "Write the report to a file instead of stdout")
    .option("--max-steps <n>", "Per-invariant evaluation step budget", (v) => parseInt(v, 10))
    .option("--max-time-ms <n>", "Total evaluation time budget in milliseconds", (v) => parseInt(v, 10))
    .action(
      async (
        specFile: string,
        targets: string[],
        opts: { format: "table" | "json"; output?: string; maxSteps?: number; maxTimeMs?: number },
      ) => {
        const isJson = opts.format === "json";
        if (!isJson) printBanner();

        try {
          const report = await checkInvariantsFromFile(specFile, {
            targets,
            budget: {
              ...(opts.maxSteps ? { maxStepsPerInvariant: opts.maxSteps } : {}),
              ...(opts.maxTimeMs ? { maxTotalTimeMs: opts.maxTimeMs } : {}),
            },
          });

          const output = isJson ? serializeReport(report) : formatResultsTable(report);
          if (opts.output) {
            fs.writeFileSync(opts.output, output, "utf-8");
            if (!isJson) console.log(chalk.green(`\n  ✅ Report written to ${opts.output}`));
          } else {
            console.log(output);
          }

          process.exit(reportExitCode(report));
        } catch (err) {
          if (err instanceof SpecValidationError) {
            console.error(chalk.red(`\n  ❌ ${err.message}`));
            printDiagnostics(err.diagnostics);
          } else {
            console.error(chalk.red(`\n  Error: ${err instanceof Error ? err.message : String(err)}`));
          }
          process.exit(1);
        }
      },
    );

  invariants
    .command("explain <specFile> <invariantId>")
    .description("Print a human-readable explanation of one invariant, including its expanded condition")
    .action((specFile: string, invariantId: string) => {
      const { spec, diagnostics } = parseInvariantSpecFile(specFile);
      if (!spec) {
        console.error(chalk.red(`  ❌ ${specFile} failed to parse:`));
        printDiagnostics(diagnostics);
        process.exit(1);
      }
      console.log(explainInvariant(spec, invariantId));
    });

  invariants
    .command("migrate <specFile>")
    .description("Migrate a spec file to the current schema version")
    .option("--write", "Overwrite the input file with the migrated spec instead of printing it")
    .option("--output <file>", "Write the migrated spec to a different file")
    .action((specFile: string, opts: { write?: boolean; output?: string }) => {
      try {
        const result = migrateInvariantSpecFile(specFile);
        const text = JSON.stringify(result.spec, null, 2) + "\n";

        if (result.fromVersion === result.toVersion) {
          console.log(chalk.green(`  ✅ ${specFile} is already on schema ${result.toVersion} — nothing to migrate`));
          return;
        }

        console.log(chalk.cyan(`  Migrating ${specFile}: ${result.fromVersion} -> ${result.toVersion}`));
        for (const change of result.changes) {
          console.log(chalk.gray(`    - ${change}`));
        }

        const target = opts.output ?? (opts.write ? specFile : undefined);
        if (target) {
          fs.writeFileSync(target, text, "utf-8");
          console.log(chalk.green(`  ✅ Wrote migrated spec to ${target}`));
        } else {
          console.log("");
          console.log(text);
        }
      } catch (err) {
        console.error(chalk.red(`  ❌ Migration failed: ${err instanceof Error ? err.message : String(err)}`));
        process.exit(1);
      }
    });
}

export type { InvariantResult };
