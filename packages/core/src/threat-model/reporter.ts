import * as path from "path";
import type { ThreatModel } from "./types";
import { generateMermaidDiagram, generateASCIIDiagram } from "./visualizer";

/**
 * Formats a threat model into a comprehensive Markdown document.
 */
export function generateMarkdownThreatModel(model: ThreatModel): string {
  let md = "";
  md += `# ChainProof Smart Contract Threat Model\n\n`;
  md += `**Generated on:** ${model.timestamp}  \n`;
  md += `**Engine Version:** ${model.version}  \n`;
  md += `**Targets:** ${model.targets.join(", ")}\n\n`;

  md += `## Executive Summary\n\n`;
  md += `This threat model highlights the key assets, actors, trust boundaries, and potential attack vectors found in the target smart contracts. It is structured around the **STRIDE** methodology and tailored for **DeFi-specific** risk vectors.\n\n`;

  md += `### Risk Statistics\n\n`;
  md += `| Metric | Count |\n`;
  md += `| --- | --- |\n`;
  md += `| **Total Identified Threats** | ${model.summary.totalThreats} |\n`;
  md += `| 🔴 Critical Severity | ${model.summary.bySeverity.critical} |\n`;
  md += `| 🟠 High Severity | ${model.summary.bySeverity.high} |\n`;
  md += `| 🟡 Medium Severity | ${model.summary.bySeverity.medium} |\n`;
  md += `| 🔵 Low Severity | ${model.summary.bySeverity.low} |\n`;
  md += `| 🛡️ Mitigated | ${model.summary.mitigatedCount} |\n`;
  md += `| ⚠️ Unmitigated / Pending | ${model.summary.unmitigatedCount} |\n\n`;

  md += `## 1. Asset Identification\n\n`;
  md += `The following high-value assets and attack targets were identified in the source code:\n\n`;
  md += `| ID | Name | Type | Value / Criticality | Defined In | Description |\n`;
  md += `| --- | --- | --- | --- | --- | --- |\n`;
  for (const asset of model.assets) {
    const valueEmoji = asset.value === "high" ? "🔴 High" : asset.value === "medium" ? "🟡 Medium" : "🔵 Low";
    md += `| \`${asset.id}\` | ${asset.name} | \`${asset.type}\` | ${valueEmoji} | ${asset.definedIn} | ${asset.description} |\n`;
  }
  md += `\n`;

  md += `## 2. Threat Agent Modeling\n\n`;
  md += `The system considers the following potential threat actors and their capabilities:\n\n`;
  for (const agent of model.agents) {
    md += `### 👤 ${agent.name} (\`${agent.id}\`)\n`;
    md += `- **Motivation:** ${agent.motivation}\n`;
    md += `- **Capabilities:** ${agent.capabilities.map((c) => `\`${c}\``).join(", ")}\n`;
    md += `- **Description:** ${agent.description}\n\n`;
  }

  md += `## 3. Attack Surface & Trust Boundaries\n\n`;
  md += `### Trust Boundaries\n`;
  for (const tb of model.attackSurface.trustBoundaries) {
    md += `- **${tb.name} (\`${tb.id}\`):** ${tb.description}\n`;
  }
  md += `\n`;

  md += `### Public / External Entry Points\n`;
  md += `| Signature | Visibility | Payable | Modifiers | Contract |\n`;
  md += `| --- | --- | --- | --- | --- |\n`;
  for (const ep of model.attackSurface.entryPoints) {
    md += `| \`${ep.signature}\` | \`${ep.visibility}\` | ${ep.isPayable ? "Yes ✅" : "No"} | ${ep.modifiers.map((m) => `\`${m}\``).join(", ") || "_None_"} | ${ep.contract} |\n`;
  }
  md += `\n`;

  md += `## 4. Visual Threat Model Diagram\n\n`;
  md += `### Architecture & Threat Flow (Mermaid)\n\n`;
  md += `\`\`\`mermaid\n`;
  md += generateMermaidDiagram(model);
  md += `\n\`\`\`\n\n`;

  md += `### Terminal Trust Boundary Mapping\n\n`;
  md += `\`\`\`text\n`;
  md += generateASCIIDiagram(model);
  md += `\n\`\`\`\n\n`;

  md += `## 5. Prioritized Threat Matrix\n\n`;
  md += `The threats below are prioritized by composite risk scores (combining likelihood, impact, and category multipliers):\n\n`;

  for (const t of model.threats) {
    const sevEmoji = t.severity === "critical" ? "🔴" : t.severity === "high" ? "🟠" : t.severity === "medium" ? "🟡" : "🔵";
    const statusLabel = t.status === "mitigated" ? "✅ Mitigated" : t.status === "partially_mitigated" ? "⚠️ Partially Mitigated" : "❌ Unmitigated";

    md += `### ${sevEmoji} [${t.severity.toUpperCase()}] ${t.title} (\`${t.id}\`)\n`;
    md += `- **STRIDE Category:** \`${t.strideCategory}\` | **DeFi Category:** \`${t.defiCategory}\`\n`;
    md += `- **Risk Score:** \`${t.riskScore}/100\` (Likelihood: \`${t.likelihood.toUpperCase()}\`, Impact: \`${t.impact.toUpperCase()}\`)\n`;
    md += `- **Target Asset:** \`${t.targetAssetId}\` | **Primary Threat Agent:** \`${t.agentId}\`\n`;
    md += `- **Status:** **${statusLabel}**\n`;
    md += `- **Attack Vector:** ${t.attackVector}\n`;
    if (t.location) {
      md += `- **Location:** [${path.basename(t.location.file)}:L${t.location.line}](file:///${t.location.file}#L${t.location.line})\n`;
    }
    md += `- **Description:** ${t.description}\n`;
    md += `- **Recommended Mitigations:**\n`;
    for (const mit of t.mitigations) {
      md += `  - [ ] ${mit}\n`;
    }
    md += `\n---\n\n`;
  }

  md += `## 6. Team Collaboration & Assumptions\n\n`;
  md += `To customize this threat model, define custom assets, or track mitigation statuses, create a JSON assumptions file and pass it to the scanner:\n\n`;
  md += `\`\`\`json\n`;
  md += `{\n`;
  md += `  "threatStatuses": {\n`;
  if (model.threats.length > 0) {
    md += `    "${model.threats[0].id}": "mitigated"\n`;
  } else {
    md += `    "thr-reentrancy-mycontract": "mitigated"\n`;
  }
  md += `  },\n`;
  md += `  "mitigations": {\n`;
  if (model.threats.length > 0) {
    md += `    "${model.threats[0].id}": [\n`;
    md += `      "Implemented Gnosis Safe multi-sig with 3/5 quorum."\n`;
    md += `    ]\n`;
  } else {
    md += `    "thr-reentrancy-mycontract": [\n`;
    md += `      "Added ReentrancyGuard to all deposit/withdraw methods."\n`;
    md += `    ]\n`;
  }
  md += `  }\n`;
  md += `}\n`;
  md += `\`\`\`\n`;

  return md;
}

/**
 * Formats a threat model into a structured JSON string.
 */
export function generateJSONThreatModel(model: ThreatModel): string {
  return JSON.stringify(model, null, 2);
}
