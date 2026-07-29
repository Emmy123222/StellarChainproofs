import { getSnippet, visit } from "../ast/parser";
import type { MergedMember } from "../ast/import-graph";
import type { ASTNode, Finding } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";

/**
 * CP-122: ERC-4626 / vault share-price inflation.
 *
 * This detector intentionally requires several independent vault signals before
 * reporting a finding:
 *
 *  1. deposit/mint and withdraw/redeem entry points;
 *  2. a share-minting operation;
 *  3. assets * totalSupply / totalAssets-style conversion math; and
 *  4. total-assets accounting backed by the asset token's live balance.
 *
 * The finding is suppressed when dead/locked shares, virtual assets and shares,
 * a decimals offset, or an explicit minimum-liquidity initialization is found.
 * Requiring the full conjunction avoids treating unrelated proportional math as
 * vulnerable vault accounting.
 */

interface FunctionInfo {
  name: string;
  node: ASTNode;
  source: string;
  member?: MergedMember;
}

interface ContractAnalysis {
  name: string;
  functions: FunctionInfo[];
  stateVariableNames: string[];
}

interface RatioMatch {
  node: ASTNode;
  fn: FunctionInfo;
  hasTwoSidedOffset: boolean;
}

const ENTRY_FUNCTIONS = new Set(["deposit", "mint"]);
const EXIT_FUNCTIONS = new Set(["withdraw", "redeem"]);
const CONVERSION_FUNCTION = /^(previewdeposit|previewmint|converttoshares|_converttoshares|deposit|mint)$/;
const PROTECTION_NAME =
  /(virtual|decimalsoffset|minimum(deposit|liquidity)|deadshares?|lockedshares?|seedshares?|initialshares?)/;

export function detectVaultInflation(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions,
): Finding[] {
  const analyses = options?.contractView
    ? [analysisFromView(options.contractView.name, options.contractView.members)]
    : analysesFromAst(ast, source);

  const findings: Finding[] = [];
  for (const analysis of analyses) {
    const finding = analyzeContract(analysis, filePath, options);
    if (finding) findings.push(finding);
  }
  return findings;
}

function analysesFromAst(ast: ASTNode, source: string): ContractAnalysis[] {
  const contracts: ContractAnalysis[] = [];

  visit(ast, {
    ContractDefinition(node: ASTNode) {
      const contract = node as { name?: string };
      const functions: FunctionInfo[] = [];
      const stateVariableNames: string[] = [];

      visit(node, {
        FunctionDefinition(fnNode: ASTNode) {
          const fn = fnNode as { name?: string; isConstructor?: boolean };
          if (!fn.isConstructor && fn.name) {
            functions.push({ name: fn.name, node: fnNode, source });
          }
        },
        StateVariableDeclaration(declarationNode: ASTNode) {
          const declaration = declarationNode as {
            variables?: Array<{ name?: string }>;
          };
          for (const variable of declaration.variables ?? []) {
            if (variable.name) stateVariableNames.push(variable.name);
          }
        },
      });

      contracts.push({
        name: contract.name ?? "vault",
        functions,
        stateVariableNames,
      });
    },
  });

  return contracts;
}

function analysisFromView(
  contractName: string,
  members: MergedMember[],
): ContractAnalysis {
  return {
    name: contractName,
    functions: members
      .filter((member) => member.kind === "function")
      .map((member) => ({
        name: member.name,
        node: member.node,
        source: member.source,
        member,
      })),
    stateVariableNames: members
      .filter((member) => member.kind === "stateVariable")
      .map((member) => member.name),
  };
}

function analyzeContract(
  contract: ContractAnalysis,
  filePath: string,
  options?: RuleOptions,
): Finding | null {
  const functionNames = new Set(contract.functions.map((fn) => fn.name.toLowerCase()));
  const hasEntry = [...ENTRY_FUNCTIONS].some((name) => functionNames.has(name));
  const hasExit = [...EXIT_FUNCTIONS].some((name) => functionNames.has(name));
  if (!hasEntry || !hasExit || !mintsShares(contract.functions)) return null;

  const ratio = findNaiveShareRatio(contract.functions);
  if (!ratio) return null;

  const usesLiveAssetBalance =
    expressionUsesLiveBalance(ratio.node) ||
    contract.functions.some(
      (fn) =>
        normalizeName(fn.name) === "totalassets" &&
        nodeUsesLiveBalance(fn.node),
    );
  if (!usesLiveAssetBalance || hasInflationProtection(contract, ratio)) {
    return null;
  }

  const line =
    (ratio.node as { loc?: { start?: { line?: number } } }).loc?.start?.line ??
    1;

  return applyFindingContext(
    {
      id: "CP-122",
      title: `Vault share-price inflation risk in ${contract.name}`,
      description:
        `"${contract.name}" mints shares using a total-supply/total-assets ratio while ` +
        "total assets come from the token's live balance. An attacker can mint the first " +
        "shares with a minimal deposit, donate tokens directly to the vault, and cause a " +
        "later depositor's share amount to round down to zero or a negligible value.",
      recommendation:
        `Protect ${contract.name}'s ${ratio.fn.name} share conversion by adding virtual ` +
        "assets and virtual shares (with a decimals offset), or lock a fixed minimum " +
        "number of dead shares during first-deposit initialization. For stronger donation " +
        "resistance, track managed assets in an internal accounting variable instead of " +
        "using the token's live balanceOf(address(this)).",
      severity: "high",
      file: filePath,
      line,
      snippet: getSnippet(ratio.fn.source, ratio.node),
    },
    ratio.fn.member,
    options?.contractView,
  );
}

function mintsShares(functions: FunctionInfo[]): boolean {
  return functions.some((fn) => {
    let found = false;
    visit(fn.node, {
      FunctionCall(node: ASTNode) {
        const expression = (node as { expression?: ASTNode }).expression;
        const calledName = getCalledName(expression);
        if (calledName === "_mint" || calledName === "mint") found = true;
      },
    });
    return found;
  });
}

function findNaiveShareRatio(functions: FunctionInfo[]): RatioMatch | null {
  for (const fn of functions) {
    if (!CONVERSION_FUNCTION.test(normalizeName(fn.name))) continue;

    let match: RatioMatch | null = null;
    const parameterNames = new Set(
      (
        fn.node as {
          parameters?: Array<{ name?: string }>;
        }
      ).parameters
        ?.map((parameter) => parameter.name?.toLowerCase())
        .filter((name): name is string => Boolean(name)) ?? [],
    );

    visit(fn.node, {
      BinaryOperation(node: ASTNode) {
        if (match) return;
        const operation = node as {
          operator?: string;
          left?: ASTNode;
          right?: ASTNode;
        };
        if (operation.operator !== "/" || !operation.left || !operation.right) {
          return;
        }

        const numeratorNames = collectNames(operation.left);
        const denominatorNames = collectNames(operation.right);
        const numeratorHasProduct = containsOperator(operation.left, "*");
        const usesAssetInput = [...numeratorNames].some(
          (name) =>
            parameterNames.has(name) &&
            /(asset|amount|deposit|value)/.test(name),
        );
        const usesSupply = [...numeratorNames].some((name) =>
          /totalsupply|sharesupply/.test(name),
        );
        const usesAssets = [...denominatorNames].some((name) =>
          /totalassets|assetbalance|balanceof/.test(name),
        );

        if (numeratorHasProduct && usesAssetInput && usesSupply && usesAssets) {
          match = {
            node,
            fn,
            hasTwoSidedOffset:
              containsOperator(operation.left, "+") &&
              containsOperator(operation.right, "+"),
          };
        }
      },
    });

    if (match) return match;
  }
  return null;
}

function hasInflationProtection(
  contract: ContractAnalysis,
  ratio: RatioMatch,
): boolean {
  if (ratio.hasTwoSidedOffset) return true;

  const names = [
    ...contract.stateVariableNames,
    ...contract.functions.map((fn) => fn.name),
  ];
  if (names.some((name) => PROTECTION_NAME.test(normalizeName(name)))) {
    return true;
  }

  return contract.functions.some((fn) => {
    const compact = getSnippet(fn.source, fn.node)
      .toLowerCase()
      .replace(/\s+/g, "");
    return (
      /_?mint\(address\((0|0x0+|0xdead)\),/.test(compact) ||
      /_?mint\(0x0+,/.test(compact)
    );
  });
}

function nodeUsesLiveBalance(node: ASTNode): boolean {
  let usesBalanceOf = false;
  let usesThisAddress = false;

  visit(node, {
    MemberAccess(child: ASTNode) {
      const access = child as { memberName?: string };
      if (access.memberName?.toLowerCase() === "balanceof") {
        usesBalanceOf = true;
      }
    },
    Identifier(child: ASTNode) {
      const identifier = child as { name?: string };
      if (identifier.name?.toLowerCase() === "this") usesThisAddress = true;
    },
  });

  // Some parser versions represent `this` as a primary expression rather than
  // an Identifier, so retain a source-independent structural balanceOf signal.
  return usesBalanceOf && (usesThisAddress || containsAddressThisCall(node));
}

function expressionUsesLiveBalance(node: ASTNode): boolean {
  return nodeUsesLiveBalance(node);
}

function containsAddressThisCall(node: ASTNode): boolean {
  let found = false;
  visit(node, {
    FunctionCall(child: ASTNode) {
      const call = child as { expression?: ASTNode; arguments?: ASTNode[] };
      if (
        getCalledName(call.expression)?.toLowerCase() === "address" &&
        (call.arguments ?? []).some((argument) =>
          collectNames(argument).has("this"),
        )
      ) {
        found = true;
      }
    },
  });
  return found;
}

function collectNames(node: ASTNode): Set<string> {
  const names = new Set<string>();
  visit(node, {
    Identifier(child: ASTNode) {
      const identifier = child as { name?: string };
      if (identifier.name) names.add(identifier.name.toLowerCase());
    },
    MemberAccess(child: ASTNode) {
      const access = child as { memberName?: string };
      if (access.memberName) names.add(access.memberName.toLowerCase());
    },
  });
  return names;
}

function containsOperator(node: ASTNode, operator: string): boolean {
  let found = false;
  visit(node, {
    BinaryOperation(child: ASTNode) {
      if ((child as { operator?: string }).operator === operator) found = true;
    },
  });
  return found;
}

function getCalledName(expression?: ASTNode): string | undefined {
  if (!expression) return undefined;
  const value = expression as { name?: string; memberName?: string };
  return value.name ?? value.memberName;
}

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/_/g, "");
}
