import type { ASTNode } from "../types";
import { visit } from "../ast/parser";

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Compute cyclomatic complexity for a single function.
 *
 * CC = 1 + number of decision points.
 * Decision points: if, for, while, require, ternary (?), &&, ||
 *
 * A function with CC > 10 is considered high-complexity.
 */
export function computeFunctionComplexity(fnNode: ASTNode): number {
  let cc = 1; // base complexity

  visit(fnNode, {
    IfStatement() {
      cc += 1;
    },
    ForStatement() {
      cc += 1;
    },
    WhileStatement() {
      cc += 1;
    },
    FunctionCall(node: ASTNode) {
      const callNode = node as { expression?: { name?: string } };
      if (callNode.expression?.name === "require") {
        cc += 1;
      }
    },
    ConditionalExpression() {
      cc += 1;
    },
    BinaryOperation(node: ASTNode) {
      const binOp = node as { operator?: string };
      if (binOp.operator === "&&" || binOp.operator === "||") {
        cc += 1;
      }
    },
  });

  return cc;
}

/**
 * Compute the logical lines of code (LOC) for a contract.
 * Excludes blank lines and single-line comments.
 */
export function computeLinesOfCode(source: string, contractStart: number, contractEnd: number): number {
  const lines = source.split("\n");
  const start = Math.max(0, contractStart - 1);
  const end = Math.min(lines.length, contractEnd);
  let logicalLines = 0;

  for (let i = start; i < end; i++) {
    const trimmed = lines[i].trim();
    if (trimmed === "" || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
      continue;
    }
    logicalLines++;
  }

  return logicalLines;
}

/**
 * Compute inheritance depth for a contract.
 * A contract with no `is` clause has depth 0.
 * Otherwise, depth = 1 + max inheritance depth of all parent contracts.
 */
export function computeInheritanceDepth(
  contractName: string,
  source: string
): number {
  // Find all contract/abstract/library declarations and their inheritance
  const contractRegex =
    /(contract|abstract|library)\s+(\w+)(?:\s+is\s+([^{}]+?))?\s*\{/g;
  const inheritanceMap = new Map<string, string[]>();

  let match: RegExpExecArray | null;
  while ((match = contractRegex.exec(source)) !== null) {
    const name = match[2];
    const basesStr = match[3];
    if (basesStr) {
      const bases = basesStr
        .split(",")
        .map((b) => b.trim().replace(/\s*\(.*?\)\s*$/, ""))
        .filter(Boolean);
      inheritanceMap.set(name, bases);
    } else {
      inheritanceMap.set(name, []);
    }
  }

  // Recursively compute depth
  function depth(name: string, visited: Set<string>): number {
    if (visited.has(name)) return 0; // circular inheritance guard
    visited.add(name);
    const bases = inheritanceMap.get(name);
    if (!bases || bases.length === 0) return 0;
    return 1 + Math.max(...bases.map((b) => depth(b, new Set(visited))));
  }

  return depth(contractName, new Set());
}

/**
 * Count external calls in a function body.
 * Detects: .call, .delegatecall, .staticcall, .transfer, .send
 */
function countExternalCalls(fnBody: ASTNode): number {
  let count = 0;

  visit(fnBody, {
    MemberAccess(maNode: ASTNode) {
      const ma = maNode as { memberName?: string };
      if (
        ma.memberName === "call" ||
        ma.memberName === "delegatecall" ||
        ma.memberName === "staticcall" ||
        ma.memberName === "transfer" ||
        ma.memberName === "send"
      ) {
        count += 1;
      }
    },
  });

  return count;
}

// ─── Analyze Full Contract ────────────────────────────────────────────────────

export interface FunctionMetric {
  name: string;
  cyclomaticComplexity: number;
  externalCallCount: number;
  visibility: string;
}

export interface ContractMetricAnalysis {
  contractName: string;
  filePath: string;
  linesOfCode: number;
  inheritanceDepth: number;
  totalFunctions: number;
  visibilityDistribution: Record<string, number>;
  stateVariableCount: number;
  functionMetrics: FunctionMetric[];
  highComplexityFunctions: Array<{ name: string; cc: number }>;
  externalCallsPerFunction: Record<string, number>;
  riskScore: number; // 0-100 composite
}

export function analyzeContract(
  ast: ASTNode,
  source: string,
  filePath: string
): ContractMetricAnalysis[] {
  const results: ContractMetricAnalysis[] = [];

  // Collect all contract-level info
  const contracts: Array<{
    name: string;
    bodyNode: ASTNode;
    loc: { start: { line: number }; end: { line: number } };
  }> = [];

  visit(ast, {
    ContractDefinition(node: ASTNode) {
      const contract = node as {
        name: string;
        kind: string;
        baseContracts?: ASTNode[];
        subNodes?: ASTNode[];
        loc?: { start: { line: number }; end: { line: number } };
      };
      if (contract.name && contract.loc) {
        contracts.push({
          name: contract.name,
          bodyNode: node,
          loc: contract.loc,
        });
      }
    },
  });

  for (const contract of contracts) {
    // ── Lines of Code ────────────────────────────────────────────────────
    const loc = computeLinesOfCode(
      source,
      contract.loc.start.line,
      contract.loc.end.line
    );

    // ── Inheritance Depth ────────────────────────────────────────────────
    const inheritanceDepth = computeInheritanceDepth(contract.name, source);

    // ── Function-level metrics ───────────────────────────────────────────
    const functionMetrics: FunctionMetric[] = [];
    let stateVariableCount = 0;

    visit(contract.bodyNode, {
      FunctionDefinition(node: ASTNode) {
        const fn = node as {
          name?: string;
          visibility?: string;
          isConstructor?: boolean;
          loc?: { start: { line: number }; end: { line: number } };
          body?: ASTNode;
        };

        const fnName = fn.isConstructor
          ? "constructor"
          : fn.name ?? "fallback";
        const cc = computeFunctionComplexity(node);
        const externalCallCount = fn.body ? countExternalCalls(fn.body) : 0;

        functionMetrics.push({
          name: fnName,
          cyclomaticComplexity: cc,
          externalCallCount,
          visibility: fn.visibility ?? "public",
        });
      },
      StateVariableDeclaration(node: ASTNode) {
        const decl = node as {
          variables?: Array<{ name?: string }>;
        };
        stateVariableCount += decl.variables?.length ?? 0;
      },
    });

    // ── Visibility Distribution ──────────────────────────────────────────
    const visibilityDistribution: Record<string, number> = {
      external: 0,
      public: 0,
      internal: 0,
      private: 0,
    };
    for (const fm of functionMetrics) {
      if (fm.visibility in visibilityDistribution) {
        visibilityDistribution[fm.visibility]++;
      } else {
        visibilityDistribution[fm.visibility] =
          (visibilityDistribution[fm.visibility] ?? 0) + 1;
      }
    }

    // ── High Complexity Functions ────────────────────────────────────────
    const highComplexityFunctions = functionMetrics
      .filter((fm) => fm.cyclomaticComplexity > 10)
      .map((fm) => ({ name: fm.name, cc: fm.cyclomaticComplexity }));

    // ── External Calls Per Function ──────────────────────────────────────
    const externalCallsPerFunction: Record<string, number> = {};
    for (const fm of functionMetrics) {
      externalCallsPerFunction[fm.name] = fm.externalCallCount;
    }

    // ── Composite Risk Score (0-100) ─────────────────────────────────────
    const riskScore = computeRiskScore({
      linesOfCode: loc,
      inheritanceDepth,
      highComplexityFunctions,
      visibilityDistribution,
      stateVariableCount,
      externalCallsPerFunction,
      totalFunctions: functionMetrics.length,
    });

    results.push({
      contractName: contract.name,
      filePath,
      linesOfCode: loc,
      inheritanceDepth,
      totalFunctions: functionMetrics.length,
      visibilityDistribution,
      stateVariableCount,
      functionMetrics,
      highComplexityFunctions,
      externalCallsPerFunction,
      riskScore,
    });
  }

  return results;
}

// ─── Composite Risk Score ───────────────────────────────────────────────────

/**
 * Weighted composite risk score (0-100).
 *
 * Formula:
 *   riskScore = clamp(0, 100,
 *     25 * norm(linesOfCode, 500) +
 *     15 * norm(inheritanceDepth, 4) +
 *     25 * norm(maxCyclomaticComplexity, 10) +
 *     15 * norm(publicExternalRatio, 0.7) +
 *     10 * norm(stateVariableCount, 20) +
 *     10 * norm(maxExternalCallsPerFunction, 3)
 *   )
 *
 * Where norm(value, threshold) = min(value / threshold, 1.0)
 */
interface RiskInputs {
  linesOfCode: number;
  inheritanceDepth: number;
  highComplexityFunctions: Array<{ cc: number }>;
  visibilityDistribution: Record<string, number>;
  stateVariableCount: number;
  externalCallsPerFunction: Record<string, number>;
  totalFunctions: number;
}

function computeRiskScore(inputs: RiskInputs): number {
  const norm = (val: number, threshold: number) =>
    Math.min(val / threshold, 1.0);

  // 25% weight: LOC > 500
  const locScore = norm(inputs.linesOfCode, 500);

  // 15% weight: inheritance depth > 4
  const inheritanceScore = norm(inputs.inheritanceDepth, 4);

  // 25% weight: max cyclomatic complexity > 10
  const maxCC =
    inputs.highComplexityFunctions.length > 0
      ? Math.max(...inputs.highComplexityFunctions.map((f) => f.cc))
      : inputs.totalFunctions > 0
        ? 5 // default moderate complexity
        : 0;
  const ccScore = norm(maxCC, 10);

  // 15% weight: public+external ratio > 0.7
  const pubExt =
    (inputs.visibilityDistribution.public ?? 0) +
    (inputs.visibilityDistribution.external ?? 0);
  const totalVis = Object.values(inputs.visibilityDistribution).reduce(
    (a, b) => a + b,
    0
  );
  const pubExtRatio = totalVis > 0 ? pubExt / totalVis : 0;
  const visibilityScore = norm(pubExtRatio, 0.7);

  // 10% weight: state variables > 20
  const stateVarScore = norm(inputs.stateVariableCount, 20);

  // 10% weight: max external calls per function > 3
  const maxExtCalls =
    inputs.totalFunctions > 0
      ? Math.max(
          ...Object.values(inputs.externalCallsPerFunction),
          0
        )
      : 0;
  const extCallScore = norm(maxExtCalls, 3);

  const raw =
    25 * locScore +
    15 * inheritanceScore +
    25 * ccScore +
    15 * visibilityScore +
    10 * stateVarScore +
    10 * extCallScore;

  return Math.min(100, Math.max(0, Math.round(raw)));
}
