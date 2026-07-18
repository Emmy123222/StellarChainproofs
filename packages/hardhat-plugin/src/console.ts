import chalk from "chalk";
import type { Finding, ScanResult, Severity } from "@chainproof/core";

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.green,
  info: chalk.blue,
  gas: chalk.cyan,
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
  gas: "GAS",
};

export function printChainProofHeader(): void {
  console.log("");
  console.log(chalk.cyan.bold("  ChainProof Security Scan"));
  console.log(chalk.gray("  ─────────────────────────────────────────"));
}

export function printFindings(result: ScanResult, options?: { compact?: boolean }): void {
  printChainProofHeader();

  console.log(
    chalk.gray(
      `  Files scanned : ${result.files.length}\n` +
        `  Critical      : ${colorCount("critical", result.summary.critical)}\n` +
        `  High          : ${colorCount("high", result.summary.high)}\n` +
        `  Medium        : ${result.summary.medium}\n` +
        `  Total         : ${result.summary.total}\n`
    )
  );

  if (result.summary.total === 0) {
    console.log(chalk.green("  ✅ No security issues detected.\n"));
    return;
  }

  console.log(chalk.white.bold("  Findings"));
  console.log(chalk.gray("  ─────────────────────────────────────────"));

  for (const file of result.files) {
    if (file.findings.length === 0) continue;

    console.log("");
    console.log(chalk.white(`  ${file.file}`));

    for (const finding of sortFindings(file.findings)) {
      printFinding(finding, options?.compact);
    }
  }

  console.log("");
}

export function printTestFooterSummary(result: ScanResult): void {
  console.log("");
  console.log(chalk.gray("  ── ChainProof Test Footer ─────────────────"));
  console.log(
    chalk.gray(
      `  Security summary: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.total} total findings`
    )
  );

  if (result.summary.critical > 0 || result.summary.high > 0) {
    console.log(
      chalk.red(
        "  ⚠ Review critical/high findings before deploying to mainnet."
      )
    );
  } else if (result.summary.total > 0) {
    console.log(chalk.yellow("  ⚠ Non-blocking findings detected — review recommended."));
  } else {
    console.log(chalk.green("  ✅ No ChainProof findings for configured targets."));
  }

  console.log(chalk.gray("  ───────────────────────────────────────────\n"));
}

function printFinding(finding: Finding, compact?: boolean): void {
  const color = SEVERITY_COLOR[finding.severity];
  const label = SEVERITY_LABEL[finding.severity].padEnd(8);
  const location = `L${finding.line}`;

  console.log(
    color(
      `    [${label}] ${location}  ${finding.id} — ${finding.title}`
    )
  );

  if (finding.definedIn && finding.inheritedBy) {
    console.log(
      chalk.gray(
        `             inherited from ${shortPath(finding.definedIn)} → ${shortPath(finding.inheritedBy)}`
      )
    );
  }

  if (!compact) {
    console.log(chalk.gray(`             ${finding.description.split(".")[0]}.`));
  }
}

function sortFindings(findings: Finding[]): Finding[] {
  const order: Severity[] = ["critical", "high", "medium", "low", "info", "gas"];
  return [...findings].sort(
    (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)
  );
}

function colorCount(severity: Severity, count: number): string {
  if (count === 0) return String(count);
  return SEVERITY_COLOR[severity](String(count));
}

function shortPath(filePath: string): string {
  const parts = filePath.split(/[/\\]/);
  return parts.slice(-2).join("/");
}
