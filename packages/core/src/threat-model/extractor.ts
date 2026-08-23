import * as fs from "fs";
import * as path from "path";
import { parseSolidity, visit } from "../ast/parser";
import type { ASTNode, Finding } from "../types";
import type {
  Asset,
  AssetType,
  AssetValue,
  ThreatAgent,
  TrustBoundary,
  EntryPoint,
  AttackSurface,
  Threat,
  STRIDECategory,
  DeFiCategory,
  LocationInfo,
  SeverityLevel,
} from "./types";

/**
 * Standard Threat Agents database
 */
export const DEFAULT_AGENTS: ThreatAgent[] = [
  {
    id: "agent-external-attacker",
    name: "Anonymous External Attacker",
    description: "An unprivileged actor attempting to exploit vulnerabilities from outside the network trust boundary.",
    capabilities: ["Arbitrary transaction calling", "Flash loan sourcing", "Mempool monitoring", "Reentrancy invocation"],
    motivation: "Financial theft, token drain, or protocol disruption.",
  },
  {
    id: "agent-compromised-admin",
    name: "Compromised/Malicious Administrator",
    description: "An actor possessing administrative credentials or keys who either acts maliciously or whose keys have been stolen.",
    capabilities: ["Calling owner/admin functions", "Upgrading contract implementation logic", "Pausing/Unpausing protocol", "Modifying access control configurations"],
    motivation: "Asset extraction, privilege abuse, or complete protocol hijacking.",
  },
  {
    id: "agent-oracle-manipulator",
    name: "Oracle Price Manipulator",
    description: "A well-funded actor capable of executing large trades to manipulate external liquidity pools or AMM spot prices referenced by the contract.",
    capabilities: ["Flash loans", "Slippage exploitation", "Block-level sandwiching"],
    motivation: "Arbitrage profits at the expense of the contract's lending or swap rates.",
  },
  {
    id: "agent-mev-searcher",
    name: "MEV Searcher / Frontrunner",
    description: "An actor monitoring the blockchain mempool to insert, reorder, or sandwich transactions for economic profit.",
    capabilities: ["Gas fee bidding (PGA)", "Direct builder relationships (Flashbots)", "Transaction frontrunning/backrunning"],
    motivation: "Extracting arbitrage, liquidation, or user trade slippage value.",
  },
  {
    id: "agent-governance-attacker",
    name: "Hostile Governance Participant",
    description: "An actor acquiring a significant share of voting tokens or proposing malicious proposals to pass governance checks.",
    capabilities: ["Flash loan governance voting", "Token accumulation", "Social engineering"],
    motivation: "Forcing malicious upgrades or draining treasury funds via governance proposals.",
  },
];

/**
 * Helper to get variable type string from AST node
 */
function getVariableTypeString(node: ASTNode): string {
  if (!node || !node.typeName) return "unknown";
  const type = node.typeName;
  if (type.type === "ElementaryTypeName") {
    return type.name;
  }
  if (type.type === "UserDefinedTypeName") {
    return type.namePath;
  }
  if (type.type === "Mapping") {
    const key = type.keyType.type === "ElementaryTypeName" ? type.keyType.name : "mapping_key";
    const val = getVariableTypeString({ typeName: type.valueType });
    return `mapping(${key} => ${val})`;
  }
  if (type.type === "ArrayTypeName") {
    const base = getVariableTypeString({ typeName: type.baseTypeName });
    return `${base}[]`;
  }
  return "unknown";
}

/**
 * Extracts assets, attack surfaces, trust boundaries, and initial threat models from contract source code.
 */
export function extractThreatModel(
  filePaths: string[],
  findings: Finding[] = []
): {
  assets: Asset[];
  agents: ThreatAgent[];
  attackSurface: AttackSurface;
  threats: Threat[];
} {
  const assets: Asset[] = [];
  const entryPoints: EntryPoint[] = [];
  const trustBoundaries: TrustBoundary[] = [];
  const threats: Threat[] = [];

  // Track discovered contract names and their features
  const contractsInfo = new Map<
    string,
    {
      isToken: boolean;
      isVault: boolean;
      hasOwner: boolean;
      hasOracle: boolean;
      hasPause: boolean;
    }
  >();

  // 1. Process each file
  for (const filePath of filePaths) {
    if (!fs.existsSync(filePath)) continue;
    let source = "";
    try {
      source = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    const { ast } = parseSolidity(source, filePath);
    if (!ast) continue;

    visit(ast, {
      ContractDefinition(node: ASTNode) {
        const contractName = node.name;
        let isToken = false;
        let isVault = false;
        let hasOwner = false;
        let hasOracle = false;
        let hasPause = false;

        const nameLower = contractName.toLowerCase();
        if (nameLower.includes("token") || nameLower.includes("erc20") || nameLower.includes("coin")) isToken = true;
        if (nameLower.includes("vault") || nameLower.includes("pool") || nameLower.includes("defi")) isVault = true;

        // Check inheritance
        if (node.baseContracts) {
          for (const base of node.baseContracts) {
            const name = base.baseName.namePath.toLowerCase();
            if (name.includes("erc20") || name.includes("token")) isToken = true;
            if (name.includes("vault") || name.includes("pool")) isVault = true;
            if (name.includes("ownable") || name.includes("access")) hasOwner = true;
            if (name.includes("pausable")) hasPause = true;
          }
        }

        // Analyze state variables
        const stateVariables = node.subNodes.filter(
          (n: ASTNode) => n.type === "StateVariableDeclaration"
        );

        for (const stateDecl of stateVariables) {
          for (const variable of stateDecl.variables) {
            const varName = variable.name;
            const varType = getVariableTypeString(variable);
            const varNameLower = varName.toLowerCase();
            const varTypeLower = varType.toLowerCase();

            // Look for specific indicators
            if (varNameLower.includes("owner") || varNameLower.includes("admin") || varNameLower.includes("governor")) {
              hasOwner = true;
            }
            if (varNameLower.includes("oracle") || varNameLower.includes("pricefeed") || varNameLower.includes("feed")) {
              hasOracle = true;
            }
            if (varNameLower.includes("paused")) {
              hasPause = true;
            }

            // Asset discovery logic
            let asset: Asset | null = null;
            const location: LocationInfo = {
              line: variable.loc?.start?.line ?? 1,
              file: filePath,
            };

            if (
              varNameLower.includes("balance") ||
              varNameLower.includes("balances") ||
              varNameLower.includes("allowance") ||
              varNameLower.includes("allowances")
            ) {
              asset = {
                id: `asset-token-${contractName.toLowerCase()}-${varNameLower}`,
                name: `${contractName} ${varName} Ledger`,
                type: "token",
                description: `Stores user address balances or allowances in the ${contractName} token system.`,
                value: "high",
                definedIn: contractName,
                location,
              };
            } else if (
              varNameLower.includes("owner") ||
              varNameLower.includes("admin") ||
              varNameLower.includes("role") ||
              varNameLower.includes("authority")
            ) {
              asset = {
                id: `asset-access-${contractName.toLowerCase()}-${varNameLower}`,
                name: `${contractName} Privileged Role Variable`,
                type: "access_control",
                description: `Represents administrative permission settings (${varName}) that authorize critical protocol operations.`,
                value: "high",
                definedIn: contractName,
                location,
              };
            } else if (
              varNameLower.includes("oracle") ||
              varNameLower.includes("feed") ||
              varNameLower.includes("price")
            ) {
              asset = {
                id: `asset-oracle-${contractName.toLowerCase()}-${varNameLower}`,
                name: `${contractName} External Oracle Feed`,
                type: "oracle",
                description: `Reference to external oracle or pricing contract (${varName}) used for asset valuation.`,
                value: "high",
                definedIn: contractName,
                location,
              };
            } else if (
              varTypeLower.includes("mapping") &&
              (varNameLower.includes("shares") ||
                varNameLower.includes("stake") ||
                varNameLower.includes("deposit"))
            ) {
              isVault = true;
              asset = {
                id: `asset-vault-${contractName.toLowerCase()}-${varNameLower}`,
                name: `${contractName} ${varName} Ledger`,
                type: "vault",
                description: `Maintains records of vault user shares, deposits, or staked balances.`,
                value: "high",
                definedIn: contractName,
                location,
              };
            } else if (
              varNameLower.includes("totalsupply") ||
              varNameLower.includes("totalassets") ||
              varNameLower.includes("totalshares")
            ) {
              asset = {
                id: `asset-supply-${contractName.toLowerCase()}-${varNameLower}`,
                name: `${contractName} Supply Variables`,
                type: "token",
                description: `Global total supply or aggregate asset tracking variables (${varName}).`,
                value: "medium",
                definedIn: contractName,
                location,
              };
            }

            if (asset) {
              // Deduplicate
              if (!assets.some((a) => a.id === asset!.id)) {
                assets.push(asset);
              }
            }
          }
        }

        // Check functions for features
        const functions = node.subNodes.filter(
          (n: ASTNode) => n.type === "FunctionDefinition"
        );

        for (const fn of functions) {
          const fnName = fn.name || "fallback";
          const fnNameLower = fnName.toLowerCase();

          // Infer features
          if (fnNameLower.includes("oracle") || fnNameLower.includes("price")) hasOracle = true;
          if (fnNameLower.includes("pause") || fnNameLower.includes("unpause")) hasPause = true;

          // Track entry points (only public / external)
          const visibility = fn.visibility || "public";
          if (visibility === "public" || visibility === "external") {
            const isPayable = fn.stateMutability === "payable";
            const modifiers = fn.modifiers ? fn.modifiers.map((m: ASTNode) => m.name) : [];
            const signature = `${fnName}(${
              fn.parameters
                ? fn.parameters.map((p: ASTNode) => getVariableTypeString({ typeName: p.typeName })).join(",")
                : ""
            })`;

            if (modifiers.some((m: string) => m.toLowerCase().includes("owner") || m.toLowerCase().includes("admin"))) {
              hasOwner = true;
            }

            entryPoints.push({
              name: fnName,
              signature,
              visibility,
              isPayable,
              modifiers,
              contract: contractName,
              line: fn.loc?.start?.line ?? 1,
            });
          }
        }

        contractsInfo.set(contractName, {
          isToken,
          isVault,
          hasOwner,
          hasOracle,
          hasPause,
        });

        // Add overall contract logic as an asset
        assets.push({
          id: `asset-logic-${contractName.toLowerCase()}`,
          name: `${contractName} Smart Contract Logic`,
          type: "logic",
          description: `The compiled code and execution logic of the ${contractName} contract.`,
          value: "high",
          definedIn: contractName,
          location: { line: node.loc?.start?.line ?? 1, file: filePath },
        });
      },
    });
  }

  // 2. Setup trust boundaries
  // Boundary 1: User to Public Interface
  trustBoundaries.push({
    id: "tb-external-boundary",
    name: "External Untrusted Boundary",
    description: "Separates external untrusted clients (e.g., anonymous wallets) from the public/external interface of the smart contracts.",
    components: entryPoints.map((ep) => `${ep.contract}.${ep.name}`),
  });

  // Boundary 2: Privileged Boundary
  const privilegedComponents = entryPoints
    .filter((ep) =>
      ep.modifiers.some((m) =>
        ["owner", "onlyowner", "admin", "onlyadmin", "onlygovernor", "onlyrole"].some((role) =>
          m.toLowerCase().includes(role)
        )
      )
    )
    .map((ep) => `${ep.contract}.${ep.name}`);

  if (privilegedComponents.length > 0) {
    trustBoundaries.push({
      id: "tb-privileged-boundary",
      name: "Privileged Admin Boundary",
      description: "Separates normal callers from restricted functions requiring special roles or ownership rights.",
      components: privilegedComponents,
    });
  }

  // Boundary 3: Oracle boundary if applicable
  const oracleContracts = Array.from(contractsInfo.entries())
    .filter(([_, info]) => info.hasOracle)
    .map(([name, _]) => name);

  if (oracleContracts.length > 0) {
    trustBoundaries.push({
      id: "tb-oracle-boundary",
      name: "External Oracle Feed Boundary",
      description: "Separates the contract state and calculations from price feeds or other data streams retrieved from external oracle providers.",
      components: oracleContracts.map((c) => `${c}.oracle`),
    });
  }

  // 3. Generate threats dynamically based on discovered assets, attack surface, and findings
  const assetsMap = new Map(assets.map((a) => [a.type, a]));

  // Generate generic threats based on architecture
  for (const [contractName, info] of contractsInfo.entries()) {
    const logicAsset = assets.find((a) => a.id === `asset-logic-${contractName.toLowerCase()}`);
    if (!logicAsset) continue;

    // A. Reentrancy threat
    if (info.isVault || info.isToken) {
      threats.push({
        id: `thr-reentrancy-${contractName.toLowerCase()}`,
        title: `Reentrancy Exploitation on ${contractName}`,
        strideCategory: "Tampering",
        defiCategory: "Reentrancy",
        description: `An external attacker exploits state updates occurring after external calls to perform reentrant calls, draining assets from the contract.`,
        targetAssetId: logicAsset.id,
        agentId: "agent-external-attacker",
        attackVector: `Triggering a withdrawal or transfer that makes an external call to an untrusted contract, which re-enters ${contractName} before state reconciliation.`,
        likelihood: "medium",
        impact: "high",
        riskScore: 60,
        severity: "high",
        mitigations: [
          "Apply the checks-effects-interactions pattern strictly.",
          "Use a ReentrancyGuard and attach nonReentrant modifier to all state-mutating external methods."
        ],
        status: "unmitigated",
        location: logicAsset.location,
      });
    }

    // B. Privileged Admin Abuse
    if (info.hasOwner) {
      const accessAsset = assets.find(
        (a) => a.type === "access_control" && a.definedIn === contractName
      );
      threats.push({
        id: `thr-admin-compromise-${contractName.toLowerCase()}`,
        title: `Privileged Command Abuse or Key Compromise on ${contractName}`,
        strideCategory: "ElevationOfPrivilege",
        defiCategory: "AccessControl",
        description: `An administrative key is compromised, or a developer rogue action triggers unauthorized state transitions or upgrades, resulting in complete protocol freeze or asset drain.`,
        targetAssetId: accessAsset ? accessAsset.id : logicAsset.id,
        agentId: "agent-compromised-admin",
        attackVector: `Direct invocation of owner/governance functions via compromised keys.`,
        likelihood: "low",
        impact: "high",
        riskScore: 50,
        severity: "medium",
        mitigations: [
          "Use a multi-signature wallet (e.g. Gnosis Safe) for ownership keys.",
          "Implement a timelock for administrative or upgrade actions to allow users to exit before changes take effect."
        ],
        status: "unmitigated",
        location: accessAsset?.location ?? logicAsset.location,
      });
    }

    // C. Oracle Manipulation
    if (info.hasOracle) {
      const oracleAsset = assets.find(
        (a) => a.type === "oracle" && a.definedIn === contractName
      );
      threats.push({
        id: `thr-oracle-manipulation-${contractName.toLowerCase()}`,
        title: `Price Oracle Manipulation on ${contractName}`,
        strideCategory: "InformationDisclosure",
        defiCategory: "OracleManipulation",
        description: `An attacker manipulates the spot price of an asset in an AMM pool referenced by the contract's oracle, leading to incorrect calculations and potential arbitrage/liquidation exploits.`,
        targetAssetId: oracleAsset ? oracleAsset.id : logicAsset.id,
        agentId: "agent-oracle-manipulator",
        attackVector: `Use of flash loans to temporarily inflate/deflate reserves in the spot pool, skewing the reported oracle price during a transaction.`,
        likelihood: "medium",
        impact: "high",
        riskScore: 70,
        severity: "high",
        mitigations: [
          "Use Chainlink or similar decentralized/aggregate price feeds instead of a single spot pool.",
          "Implement a Time-Weighted Average Price (TWAP) oracle with sufficient window size."
        ],
        status: "unmitigated",
        location: oracleAsset?.location ?? logicAsset.location,
      });
    }

    // D. Frontrunning
    const contractEntryPoints = entryPoints.filter((ep) => ep.contract === contractName);
    const hasSlippageFunctions = contractEntryPoints.some(
      (ep) =>
        ep.name.toLowerCase().includes("swap") ||
        ep.name.toLowerCase().includes("trade") ||
        ep.name.toLowerCase().includes("liquidate")
    );
    if (hasSlippageFunctions) {
      threats.push({
        id: `thr-frontrunning-${contractName.toLowerCase()}`,
        title: `Transaction Sandwiching / MEV on ${contractName}`,
        strideCategory: "InformationDisclosure",
        defiCategory: "Frontrunning",
        description: `A searcher detects a pending swap/trade transaction in the mempool and inserts transactions before and after to profit from the user's slippage.`,
        targetAssetId: logicAsset.id,
        agentId: "agent-mev-searcher",
        attackVector: `Exploiting mempool visibility and offering high gas fees to sandwich trade transactions.`,
        likelihood: "high",
        impact: "medium",
        riskScore: 55,
        severity: "medium",
        mitigations: [
          "Implement strict minimum output amount parameters (slippage bounds) passed from users.",
          "Use private transaction routes (e.g. Flashbots Protect)."
        ],
        status: "unmitigated",
        location: logicAsset.location,
      });
    }
  }

  // 4. Map existing ChainProof findings to specific threat instances
  findings.forEach((finding, idx) => {
    // Map Finding properties to Threat
    let strideCat: STRIDECategory = "Tampering";
    let defiCat: DeFiCategory = "Other";
    let likelihood: AssetValue = "medium";
    let impact: AssetValue = "high";
    let risk = 60;

    const lowerId = finding.id.toLowerCase();
    const lowerTitle = finding.title.toLowerCase();

    if (lowerId.includes("107") || lowerTitle.includes("reentrancy")) {
      strideCat = "Tampering";
      defiCat = "Reentrancy";
      likelihood = "medium";
      impact = "high";
      risk = 75;
    } else if (lowerId.includes("115") || lowerTitle.includes("origin")) {
      strideCat = "Spoofing";
      defiCat = "AccessControl";
      likelihood = "high";
      impact = "high";
      risk = 80;
    } else if (lowerId.includes("101") || lowerTitle.includes("overflow") || lowerTitle.includes("underflow")) {
      strideCat = "Tampering";
      defiCat = "Other";
      likelihood = "low";
      impact = "medium";
      risk = 30;
    } else if (lowerId.includes("116") || lowerTitle.includes("upgrade")) {
      strideCat = "ElevationOfPrivilege";
      defiCat = "AccessControl";
      likelihood = "medium";
      impact = "high";
      risk = 85;
    } else if (lowerId.includes("122") || lowerTitle.includes("inflation") || lowerTitle.includes("vault")) {
      strideCat = "Tampering";
      defiCat = "FlashloanAttack";
      likelihood = "medium";
      impact = "high";
      risk = 70;
    } else if (lowerId.includes("119") || lowerTitle.includes("frontrunning") || lowerTitle.includes("sandwich")) {
      strideCat = "InformationDisclosure";
      defiCat = "Frontrunning";
      likelihood = "high";
      impact = "medium";
      risk = 60;
    }

    const severity: SeverityLevel =
      risk >= 75 ? "critical" : risk >= 55 ? "high" : risk >= 35 ? "medium" : "low";

    // Deduce target asset
    const contract = finding.file ? path.basename(finding.file, ".sol") : "contract";
    const targetAssetId = `asset-logic-${contract.toLowerCase()}`;

    // Add unique finding-derived threat
    threats.push({
      id: `thr-finding-${finding.id.toLowerCase()}-${idx}`,
      title: `Vulnerability: ${finding.title}`,
      strideCategory: strideCat,
      defiCategory: defiCat,
      description: `ChainProof scan discovered: ${finding.description}`,
      targetAssetId,
      agentId: "agent-external-attacker",
      attackVector: `Exploiting the vulnerable code on line ${finding.line} in ${finding.file}.`,
      likelihood,
      impact,
      riskScore: risk,
      severity,
      mitigations: [finding.recommendation || "Refactor code to resolve this finding."],
      status: "unmitigated",
      location: { line: finding.line, file: finding.file },
    });
  });

  return {
    assets,
    agents: DEFAULT_AGENTS,
    attackSurface: { entryPoints, trustBoundaries },
    threats,
  };
}
