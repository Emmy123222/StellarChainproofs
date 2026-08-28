import type { GovernanceAnalysisReport, GovernanceFinding } from "./types";

/** Deterministic, recursively key-sorted JSON suitable for versioned CI artifacts. */
export function serializeGovernanceReport(report: GovernanceAnalysisReport): string {
  return JSON.stringify(sortValue(report), null, 2) + "\n";
}

/** Human-readable governance report with evidence and explicit scope limitations. */
export function generateGovernanceMarkdown(report: GovernanceAnalysisReport): string {
  const lines = [
    "# Governance Safety Analysis",
    "",
    `Schema: \`${report.schemaVersion}\`  `,
    `Engine: \`${report.engineVersion}\``,
    "",
    "## Summary",
    "",
    `- Solidity files analyzed: ${report.summary.files}`,
    `- Governance contracts modeled: ${report.summary.contracts}`,
    `- Findings: ${report.summary.total} (${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium, ${report.summary.low} low, ${report.summary.info} info)`,
    `- Output truncated by a configured limit: ${report.summary.truncated ? "yes" : "no"}`,
    "",
  ];
  for (const file of report.files) {
    lines.push(`## ${escapeMarkdown(file.file)}`, "");
    for (const diagnostic of file.diagnostics) {
      lines.push(`> ${diagnostic.severity.toUpperCase()} ${diagnostic.code}: ${escapeMarkdown(diagnostic.message)}`, "");
    }
    if (!file.findings.length) lines.push("No structural governance findings.", "");
    for (const finding of file.findings) appendFinding(lines, finding);
  }
  lines.push(
    "## Scope",
    "",
    "This report evaluates structural implementation safety: state transitions, authorization, replay protection, ordering, and data flow. It does not rate political legitimacy, voter preferences, or proposal outcomes.",
    "",
  );
  return lines.join("\n");
}

function appendFinding(lines: string[], finding: GovernanceFinding): void {
  lines.push(
    `### ${finding.ruleId}: ${escapeMarkdown(finding.title)}`,
    "",
    `**Severity:** ${finding.severity}  `,
    `**Confidence:** ${finding.confidence}  `,
    `**Contract:** \`${escapeMarkdown(finding.contract)}\`  `,
    `**Location:** \`${escapeMarkdown(finding.location.file)}:${finding.location.line}:${finding.location.column}\``,
    "",
    finding.description,
    "",
    `**Recommendation:** ${finding.recommendation}`,
    "",
    "**Evidence:**",
  );
  for (const evidence of finding.evidence) {
    lines.push(`- ${escapeMarkdown(evidence.description)} (${evidence.location.line}:${evidence.location.column})`);
  }
  if (finding.assumptions.length) {
    lines.push("", "**Assumptions:**");
    for (const assumption of finding.assumptions) lines.push(`- ${escapeMarkdown(assumption)}`);
  }
  lines.push("");
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, sortValue(child)]));
  }
  return value;
}

function escapeMarkdown(value: string): string {
  return value.replace(/[|]/g, "\\|").replace(/[\r\n]+/g, " ");
}
