import type { ThreatModel } from "./types";

/**
 * Generates a Mermaid.js diagram string visualizing the threat model flow.
 */
export function generateMermaidDiagram(model: ThreatModel): string {
  const lines: string[] = ["flowchart TB"];

  // 1. Add Threat Agents
  lines.push("    subgraph agents [Threat Agents]");
  for (const agent of model.agents) {
    const safeId = agent.id.replace(/-/g, "_");
    lines.push(`        ${safeId}["${agent.name}"]`);
  }
  lines.push("    end");

  // 2. Add Trust Boundaries and components
  for (const tb of model.attackSurface.trustBoundaries) {
    const safeTbId = tb.id.replace(/-/g, "_");
    lines.push(`    subgraph ${safeTbId} ["${tb.name}"]`);
    for (const comp of tb.components) {
      const compId = comp.replace(/[\.\-]/g, "_");
      lines.push(`        ${compId}["${comp}"]`);
    }
    lines.push("    end");
  }

  // 3. Add Assets
  lines.push("    subgraph assets [Discovered Assets]");
  for (const asset of model.assets) {
    const safeAssetId = asset.id.replace(/-/g, "_");
    lines.push(`        ${safeAssetId}["${asset.name} (${asset.type.toUpperCase()})"]`);
  }
  lines.push("    end");

  // 4. Connect Agents to EntryPoints/Components and then to Assets based on Threats
  const connected = new Set<string>();
  for (const threat of model.threats) {
    const safeAgentId = threat.agentId.replace(/-/g, "_");
    const safeAssetId = threat.targetAssetId.replace(/-/g, "_");

    // Connect agent to target asset via threat label
    const connectionKey = `${safeAgentId}->${safeAssetId}`;
    if (!connected.has(connectionKey)) {
      lines.push(`    ${safeAgentId} -.->|"${threat.title}"| ${safeAssetId}`);
      connected.add(connectionKey);
    }
  }

  return lines.join("\n");
}

/**
 * Generates a clear ASCII representation of the threat boundaries and entry points for terminal display.
 */
export function generateASCIIDiagram(model: ThreatModel): string {
  let ascii = "\n";
  ascii += "=== Threat Model Architecture Map ===\n\n";

  // Draw external boundary
  ascii += " [ UNTRUSTED WORLD ]\n";
  ascii += "         │\n";
  ascii += "         ▼\n";
  ascii += " ────────────────────────────────────────────────────────── (Trust Boundary: External User)\n";

  // List entrypoints
  const entryPoints = model.attackSurface.entryPoints;
  if (entryPoints.length > 0) {
    ascii += "   Public/External Entrypoints:\n";
    entryPoints.slice(0, 8).forEach((ep) => {
      ascii += `     ┌─▶ [${ep.contract}.${ep.name}] (${ep.isPayable ? "payable" : "non-payable"})\n`;
    });
    if (entryPoints.length > 8) {
      ascii += `     └─▶ ... and ${entryPoints.length - 8} more functions\n`;
    }
  }

  // Draw privileged boundary if exists
  const privBoundary = model.attackSurface.trustBoundaries.find((b) => b.id === "tb-privileged-boundary");
  if (privBoundary) {
    ascii += "         │\n";
    ascii += "         ▼\n";
    ascii += " ────────────────────────────────────────────────────────── (Trust Boundary: Privileged Admin)\n";
    ascii += "   Restricted Admin Functions:\n";
    privBoundary.components.slice(0, 5).forEach((comp) => {
      ascii += `     🔒 [${comp}]\n`;
    });
    if (privBoundary.components.length > 5) {
      ascii += `     🔒 ... and ${privBoundary.components.length - 5} more restricted functions\n`;
    }
  }

  // Draw Asset layer
  ascii += "         │\n";
  ascii += "         ▼\n";
  ascii += " ────────────────────────────────────────────────────────── (Data & Storage Layer)\n";
  ascii += "   Discovered Key Assets:\n";
  model.assets.forEach((asset) => {
    ascii += `     💰 [${asset.name}] (${asset.type.toUpperCase()} - Value: ${asset.value.toUpperCase()})\n`;
  });

  return ascii;
}
