import type { ScanResult, Finding, GasHint, Severity, ContractMetrics, ScanDiff } from "../types";
import chalk from "chalk";

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: "🔴",
  high:     "🟠",
  medium:   "🟡",
  low:      "🟢",
  info:     "🔵",
  gas:      "⛽",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "gas"];

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
}

// ─── Markdown Report ──────────────────────────────────────────────────────────

/**
 * Generates a full Markdown audit report from a scan result.
 *
 * Includes an executive summary table, per-file vulnerability findings,
 * gas optimization hints, and (when available) contract complexity metrics.
 *
 * @param result - The {@link ScanResult} returned by {@link scan}
 * @returns A Markdown string ready to write to a `.md` file or post as a PR comment
 *
 * @example
 * ```typescript
 * import { scan, generateMarkdownReport } from '@chainproof/core';
 * import { writeFileSync } from 'fs';
 *
 * const result = await scan({ targets: ['contracts/'], useSlither: false, useLLM: false, useMetrics: false });
 * writeFileSync('audit-report.md', generateMarkdownReport(result));
 * ```
 */
export function generateMarkdownReport(result: ScanResult): string {
  const lines: string[] = [];
  const { summary } = result;

  lines.push("# ChainProof Security Audit Report");
  lines.push("");
  lines.push(`**Generated:** ${result.timestamp}`);
  lines.push(`**ChainProof version:** ${result.version}`);
  lines.push(`**Files scanned:** ${result.files.length}`);
  lines.push("");

  // Executive Summary
  lines.push("## Executive Summary");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  lines.push(`| ${SEVERITY_EMOJI.critical} Critical | ${summary.critical} |`);
  lines.push(`| ${SEVERITY_EMOJI.high} High     | ${summary.high} |`);
  lines.push(`| ${SEVERITY_EMOJI.medium} Medium   | ${summary.medium} |`);
  lines.push(`| ${SEVERITY_EMOJI.low} Low      | ${summary.low} |`);
  lines.push(`| ${SEVERITY_EMOJI.info} Info     | ${summary.info} |`);
  lines.push(`| ${SEVERITY_EMOJI.gas} Gas      | ${summary.gas} |`);
  lines.push(`| **Total** | **${summary.total}** |`);
  lines.push("");

  if (summary.critical > 0 || summary.high > 0) {
    lines.push(
      "> ⚠️ **This contract has critical or high severity findings. " +
      "Do not deploy to mainnet without addressing these issues.**"
    );
    lines.push("");
  }

  // ── Risk Score Header ──────────────────────────────────────────────────────
  if (result.metrics && result.metrics.length > 0) {
    const topRisk = result.metrics
      .slice()
      .sort((a, b) => b.riskScore - a.riskScore)[0];
    lines.push(`> 📊 **Top Risk Contract:** \`${topRisk.contract}\` — Risk Score: **${topRisk.riskScore}/100**`);
    lines.push("");
  }

  // ── Complexity Metrics Section ─────────────────────────────────────────────
  if (result.metrics && result.metrics.length > 0) {
    lines.push("## Complexity Metrics");
    lines.push("");
    lines.push(
      "The following metrics assess code complexity and maintainability. " +
      "High-complexity contracts are harder to audit and carry elevated risk."
    );
    lines.push("");
    lines.push(
      "_Composite risk score formula: weighted sum of normalized metrics " +
      "(LOC: 25%, Inheritance Depth: 15%, Cyclomatic Complexity: 25%, " +
      "Public/External Ratio: 15%, State Variables: 10%, External Calls: 10%)._"
    );
    lines.push("");

    lines.push("| Contract | File | LOC | Functions | Inheritance Depth | Avg CC | High CC Functions | Risk Score |");
    lines.push("|----------|------|-----|-----------|-------------------|--------|-------------------|------------|");

    for (const m of result.metrics) {
      const highCCList = m.highComplexityFunctions
        .map((f) => `${f.name}(${f.cc})`)
        .join(", ") || "—";
      const riskColor = m.riskScore >= 70 ? "🔴" : m.riskScore >= 40 ? "🟡" : "🟢";
      lines.push(
        `| ${m.contract} | ${m.file} | ${m.linesOfCode} | ${m.functionCount} | ${m.inheritanceDepth} | ${m.avgCyclomaticComplexity} | ${highCCList} | ${riskColor} ${m.riskScore}/100 |`
      );
    }
    lines.push("");

    // High complexity function details
    const allHighCC = result.metrics.flatMap((m) =>
      m.highComplexityFunctions.map((f) => ({ ...f, contract: m.contract, file: m.file }))
    );
    if (allHighCC.length > 0) {
      lines.push("### ⚠️ High-Complexity Functions (CC > 10)");
      lines.push("");
      for (const f of allHighCC) {
        lines.push(`- **${f.contract}::${f.name}** — CC: ${f.cc} (\`${f.file}\`) — _Consider refactoring_`);
      }
      lines.push("");
    }

    // Top 3 highest risk contracts
    const top3 = result.metrics
      .slice()
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 3);
    if (top3.length > 0) {
      lines.push("### 🔥 Top 3 Highest-Risk Contracts");
      lines.push("");
      for (let i = 0; i < top3.length; i++) {
        const m = top3[i];
        const badge = i === 0 ? "🥇" : i === 1 ? "🥈" : "🥉";
        lines.push(
          `${badge} **${m.contract}** — Risk Score: **${m.riskScore}/100** ` +
          `(\`${m.file}\`, ${m.linesOfCode} LOC, ${m.functionCount} functions, ` +
          `inheritance depth: ${m.inheritanceDepth})`
        );
      }
      lines.push("");
    }
  }

  // Findings per file
  for (const file of result.files) {
    if (file.parseError) {
      lines.push(`## ${file.file}`);
      lines.push("");
      lines.push(`> ❌ Parse error: ${file.parseError}`);
      lines.push("");
      continue;
    }

    const allFindings = sortFindings(file.findings);
    if (allFindings.length === 0 && file.gasHints.length === 0) continue;

    lines.push(`## ${file.file}`);
    lines.push("");
    if (file.slitherRan) {
      lines.push("_Scanned with ChainProof AST engine + Slither_");
    } else {
      lines.push("_Scanned with ChainProof AST engine (Slither not available)_");
    }
    lines.push("");

    // Vulnerability findings
    if (allFindings.length > 0) {
      lines.push("### Vulnerability Findings");
      lines.push("");

      allFindings.forEach((f, idx) => {
        lines.push(
          `#### ${idx + 1}. ${SEVERITY_EMOJI[f.severity]} [${f.severity.toUpperCase()}] ${f.title}`
        );
        lines.push("");
        lines.push(`- **ID:** \`${f.id}\`${f.swcId ? ` ([${f.swcId}](https://swcregistry.io/docs/${f.swcId}))` : ""}`);
        lines.push(`- **Location:** Line ${f.line}`);
        if (f.confidence) lines.push(`- **Confidence:** ${f.confidence}`);
        if (f.callPath && f.callPath.length > 0) {
          lines.push(`- **Call path:** ${f.callPath.join(" → ")}`);
        }
        if (f.llmEnhanced) lines.push("- **Enhanced by:** AI analysis ✨");
        lines.push("");
        lines.push("**Description**");
        lines.push("");
        lines.push(f.description);
        lines.push("");
        lines.push("**Recommendation**");
        lines.push("");
        lines.push(f.recommendation);
        lines.push("");

        if (f.snippet) {
          lines.push("**Affected Code**");
          lines.push("");
          lines.push("```solidity");
          lines.push(f.snippet);
          lines.push("```");
          lines.push("");
        }

        if (f.evidence && f.evidence.length > 0) {
          lines.push("**Evidence**");
          lines.push("");
          for (const e of f.evidence) {
            lines.push(`- ${e.description}${e.line ? ` (line ${e.line})` : ""}`);
          }
          lines.push("");
        }

        if (f.assumptions && f.assumptions.length > 0) {
          lines.push("**Assumptions**");
          lines.push("");
          for (const a of f.assumptions) {
            lines.push(`- ${a}`);
          }
          lines.push("");
        }

        lines.push("---");
        lines.push("");
      });
    }

    // Gas hints
    if (file.gasHints.length > 0) {
      lines.push("### Gas Optimization Hints");
      lines.push("");
      file.gasHints.forEach((h: GasHint, idx: number) => {
        lines.push(`#### ${idx + 1}. ⛽ Line ${h.line} — ${h.description.split(".")[0]}`);
        lines.push("");
        lines.push(h.description);
        lines.push("");
        lines.push(`**Estimated saving:** ${h.estimatedSaving}`);
        lines.push("");
        if (h.snippet) {
          lines.push("```solidity");
          lines.push(h.snippet);
          lines.push("```");
          lines.push("");
        }
      });
    }
  }

  lines.push("---");
  lines.push("");
  lines.push(
    "_This report was generated by [ChainProof](https://github.com/your-org/chainproof). " +
    "It is not a substitute for a manual security audit by a qualified professional._"
  );

  return lines.join("\n");
}

// ─── JSON Report ──────────────────────────────────────────────────────────────

/**
 * Serializes a scan result to a pretty-printed JSON string.
 *
 * The JSON shape matches the {@link ScanResult} interface exactly, making it
 * suitable for machine consumption, CI artifact storage, or API responses.
 *
 * @param result - The {@link ScanResult} returned by {@link scan}
 * @returns A JSON string (2-space indented)
 *
 * @example
 * ```typescript
 * const result = await scan({ targets: ['contracts/'], useSlither: false, useLLM: false, useMetrics: false });
 * process.stdout.write(generateJSONReport(result));
 * ```
 */
export function generateJSONReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

// ─── Table (terminal) ─────────────────────────────────────────────────────────

/**
 * Generates a human-readable, ANSI-coloured table report for terminal output.
 *
 * Uses colour coding (red/yellow/green) based on severity. Suitable for
 * piping to a terminal or CI log output.
 *
 * @param result - The {@link ScanResult} returned by {@link scan}
 * @returns A multi-line string with box-drawing characters and ANSI colours
 *
 * @example
 * ```typescript
 * const result = await scan({ targets: ['contracts/'], useSlither: false, useLLM: false, useMetrics: false });
 * console.log(generateTableReport(result));
 * ```
 */
export function generateTableReport(result: ScanResult): string {
  const lines: string[] = [];
  const { summary } = result;

  lines.push("\n╔═══════════════════════════════════════════════════════════╗");
  lines.push("║              CHAINPROOF AUDIT REPORT                     ║");
  lines.push("╚═══════════════════════════════════════════════════════════╝\n");

  lines.push(`  Files scanned : ${result.files.length}`);
  lines.push(`  Timestamp     : ${result.timestamp}\n`);

  lines.push("  FINDINGS SUMMARY");
  lines.push("  ─────────────────────────────────────────");
  lines.push(`  ${SEVERITY_EMOJI.critical} Critical : ${summary.critical}`);
  lines.push(`  ${SEVERITY_EMOJI.high} High     : ${summary.high}`);
  lines.push(`  ${SEVERITY_EMOJI.medium} Medium   : ${summary.medium}`);
  lines.push(`  ${SEVERITY_EMOJI.low} Low      : ${summary.low}`);
  lines.push(`  ${SEVERITY_EMOJI.info} Info     : ${summary.info}`);
  lines.push(`  ${SEVERITY_EMOJI.gas} Gas      : ${summary.gas}`);
  lines.push(`  ─────────────────────────────────────────`);
  lines.push(`  Total    : ${summary.total}\n`);

  // ── Contract Risk Table ────────────────────────────────────────────────────
  if (result.metrics && result.metrics.length > 0) {
    lines.push("  CONTRACT RISK METRICS");
    lines.push("  ─────────────────────────────────────────────────────────────────");
    lines.push(
      `  ${"Contract".padEnd(24)} ${"LOC".padStart(5)} ${"Functions".padStart(9)} ${"Inh.Depth".padStart(10)} ${"Avg CC".padStart(7)} ${"Risk".padStart(10)}`
    );
    for (const m of result.metrics) {
      const riskColor =
        m.riskScore >= 70
          ? chalk.red(`${m.riskScore}/100`)
          : m.riskScore >= 40
            ? chalk.yellow(`${m.riskScore}/100`)
            : chalk.green(`${m.riskScore}/100`);
      lines.push(
        `  ${m.contract.padEnd(24)} ${String(m.linesOfCode).padStart(5)} ${String(m.functionCount).padStart(9)} ${String(m.inheritanceDepth).padStart(10)} ${String(m.avgCyclomaticComplexity).padStart(7)} ${riskColor.padStart(10)}`
      );
    }
    lines.push("");
  }

  for (const file of result.files) {
    if (file.findings.length === 0 && file.gasHints.length === 0) continue;
    lines.push(`  FILE: ${file.file}`);
    sortFindings(file.findings).forEach((f) => {
      lines.push(
        `    ${SEVERITY_EMOJI[f.severity]} [${f.severity.padEnd(8)}] Line ${String(f.line).padEnd(4)} ${f.title}`
      );
    });
    file.gasHints.forEach((h) => {
      lines.push(`    ⛽ [gas     ] Line ${String(h.line).padEnd(4)} ${h.description.split(".")[0]}`);
    });
    lines.push("");
  }

  return lines.join("\n");
}

// ─── Diff Reports ─────────────────────────────────────────────────────────────

function capitalizeSeverity(sev: Severity): string {
  return sev.charAt(0).toUpperCase() + sev.slice(1);
}

/**
 * Generates a Markdown diff report comparing findings between two scans.
 */
export function generateMarkdownDiffReport(diff: ScanDiff): string {
  const lines: string[] = [];

  lines.push("## ChainProof Diff Report");
  lines.push("");

  lines.push(`### Newly Introduced (${diff.introduced.length})`);
  if (diff.introduced.length > 0) {
    lines.push("| Rule   | File                | Line | Severity |");
    lines.push("|--------|---------------------|------|----------|");
    sortFindings(diff.introduced).forEach((f) => {
      lines.push(`| ${f.id} | ${f.file} | ${f.line} | ${capitalizeSeverity(f.severity)} |`);
    });
  } else {
    lines.push("");
    lines.push("No newly introduced findings.");
  }
  lines.push("");

  lines.push(`### Resolved Since Last Scan (${diff.resolved.length})`);
  if (diff.resolved.length > 0) {
    lines.push("| Rule   | File                | Line | Severity |");
    lines.push("|--------|---------------------|------|----------|");
    sortFindings(diff.resolved).forEach((f) => {
      lines.push(`| ${f.id} | ${f.file} | ${f.line} | ${capitalizeSeverity(f.severity)} |`);
    });
  } else {
    lines.push("");
    lines.push("No resolved findings.");
  }

  return lines.join("\n");
}

/**
 * Serializes a ScanDiff result to JSON.
 */
export function generateJSONDiffReport(diff: ScanDiff): string {
  return JSON.stringify(diff, null, 2);
}

/**
 * Generates an ANSI-formatted terminal table report for a scan diff.
 */
export function generateTableDiffReport(diff: ScanDiff): string {
  const lines: string[] = [];

  lines.push("\n╔═══════════════════════════════════════════════════════════╗");
  lines.push("║           CHAINPROOF SCAN DIFF REPORT                     ║");
  lines.push("╚═══════════════════════════════════════════════════════════╝\n");

  lines.push(`  Newly Introduced : ${diff.summary.newCritical} critical, ${diff.summary.newHigh} high (${diff.introduced.length} total)`);
  lines.push(`  Resolved Total   : ${diff.summary.resolvedTotal}`);
  lines.push(`  Persisted Total  : ${diff.persisted.length}\n`);

  if (diff.introduced.length > 0) {
    lines.push("  NEWLY INTRODUCED FINDINGS");
    lines.push("  ─────────────────────────────────────────");
    sortFindings(diff.introduced).forEach((f) => {
      lines.push(
        `  ${SEVERITY_EMOJI[f.severity]} [${f.severity.padEnd(8)}] ${f.file}:${f.line} — [${f.id}] ${f.title}`
      );
    });
    lines.push("");
  }

  if (diff.resolved.length > 0) {
    lines.push("  RESOLVED FINDINGS");
    lines.push("  ─────────────────────────────────────────");
    sortFindings(diff.resolved).forEach((f) => {
      lines.push(
        `  ✅ [${f.severity.padEnd(8)}] ${f.file}:${f.line} — [${f.id}] ${f.title}`
      );
    });
    lines.push("");
  }

  return lines.join("\n");
}
