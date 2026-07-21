import { visit, getSnippet } from "../ast/parser";
import type { MergedMember } from "../ast/import-graph";
import type { Finding, ASTNode } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";

type FunctionNode = ASTNode & {
  name?: string;
  body?: ASTNode;
  loc?: { start?: { line?: number } };
};

type ContractNode = ASTNode & {
  name?: string;
  subNodes?: ASTNode[];
};

type FunctionCallNode = ASTNode & {
  expression?: { name?: string; memberName?: string };
  arguments?: ASTNode[];
  loc?: { start?: { line?: number } };
};

interface FunctionAnalysisContext {
  hasAllowanceAlternative: boolean;
  hasCommitReveal: boolean;
  member?: MergedMember;
  contractView?: RuleOptions["contractView"];
}

/**
 * CP-119: Front-running and MEV attack surface detection.
 *
 * Surfaces common transaction-ordering risks: miner-controlled randomness,
 * zero-slippage AMM swaps, ERC-20 approve races, and public bidding flows
 * that reveal bids without a commit-reveal phase.
 */
export function detectFrontRunningMev(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions
): Finding[] {
  const findings: Finding[] = [];
  const emitted = new Set<string>();

  const pushFinding = (finding: Finding, member?: MergedMember) => {
    const contextual = applyFindingContext(
      finding,
      member,
      options?.contractView
    );
    const key = `${contextual.id}:${contextual.title}:${contextual.file}:${contextual.line}`;
    if (emitted.has(key)) return;
    emitted.add(key);
    findings.push(contextual);
  };

  const memberFunctions =
    options?.contractView?.members.filter((m) => m.kind === "function") ?? [];

  if (memberFunctions.length > 0) {
    const functionNames = memberFunctions.map((m) => m.name);
    const context: FunctionAnalysisContext = {
      hasAllowanceAlternative: hasAllowanceAlternative(functionNames),
      hasCommitReveal: hasCommitReveal(functionNames),
      contractView: options?.contractView,
    };

    for (const member of memberFunctions) {
      analyzeFunction(
        member.node as FunctionNode,
        member.source,
        filePath,
        { ...context, member },
        pushFinding
      );
    }

    return findings;
  }

  analyzeFunctionCalls(
    ast,
    source,
    filePath,
    { hasAllowanceAlternative: false, hasCommitReveal: false },
    pushFinding
  );

  visit(ast, {
    ContractDefinition(node: ASTNode) {
      const contract = node as ContractNode;
      const functions = getContractFunctions(contract);
      const functionNames = functions.map((fn) => fn.name ?? "");
      const context: FunctionAnalysisContext = {
        hasAllowanceAlternative: hasAllowanceAlternative(functionNames),
        hasCommitReveal: hasCommitReveal(functionNames),
      };

      for (const fn of functions) {
        analyzeApproveFunction(fn, source, filePath, context, pushFinding);
        analyzeAuctionFunction(fn, source, filePath, context, pushFinding);
      }
    },
  });

  return findings;
}

function analyzeFunction(
  fn: FunctionNode,
  source: string,
  filePath: string,
  context: FunctionAnalysisContext,
  pushFinding: (finding: Finding, member?: MergedMember) => void
): void {
  analyzeFunctionCalls(fn, source, filePath, context, pushFinding);
  analyzeApproveFunction(fn, source, filePath, context, pushFinding);
  analyzeAuctionFunction(fn, source, filePath, context, pushFinding);
}

function analyzeFunctionCalls(
  root: ASTNode,
  source: string,
  filePath: string,
  context: FunctionAnalysisContext,
  pushFinding: (finding: Finding, member?: MergedMember) => void
): void {
  visit(root, {
    FunctionCall(node: ASTNode) {
      const call = node as FunctionCallNode;

      if (isKeccakWithBlockEntropy(call)) {
        pushFinding(
          {
            id: "CP-119",
            swcId: "SWC-120",
            title: "Miner-controlled value used for randomness",
            description:
              "A keccak256 hash includes block.timestamp, block.difficulty, block.number, " +
              "or block.prevrandao. Validators can influence these values within protocol " +
              "limits, allowing transaction-ordering or randomness manipulation.",
            recommendation:
              "Use a commit-reveal scheme or a verifiable randomness source. Do not derive " +
              "winner selection, pricing, or privileged execution from block metadata alone.",
            severity: "high",
            file: filePath,
            line: call.loc?.start?.line ?? 0,
            snippet: getSnippet(source, call),
          },
          context.member
        );
      }

      if (isAmmSwapWithZeroSlippage(call)) {
        pushFinding(
          {
            id: "CP-119",
            title: "AMM swap accepts zero minimum output",
            description:
              "This AMM swap passes 0 as the minimum output amount. A transaction that " +
              "accepts any output can be sandwiched or reordered so the caller receives " +
              "substantially less than expected.",
            recommendation:
              "Calculate a non-zero amountOutMin from an oracle, quote, or user-provided " +
              "slippage tolerance and reject swaps that fall below it.",
            severity: "high",
            file: filePath,
            line: call.loc?.start?.line ?? 0,
            snippet: getSnippet(source, call),
          },
          context.member
        );
      }
    },
  });
}

function analyzeApproveFunction(
  fn: FunctionNode,
  source: string,
  filePath: string,
  context: FunctionAnalysisContext,
  pushFinding: (finding: Finding, member?: MergedMember) => void
): void {
  if (fn.name !== "approve" || context.hasAllowanceAlternative) return;

  const body = JSON.stringify(fn.body ?? fn);
  if (!body.includes('"name":"allowance"') && !body.includes('"name":"_approve"')) {
    return;
  }

  pushFinding(
    {
      id: "CP-119",
      title: "ERC-20 approve race condition",
      description:
        "The standard approve flow can be front-run when an allowance changes from one " +
        "non-zero value to another. A spender can consume the old allowance before the " +
        "new approval is mined, effectively using both allowances.",
      recommendation:
        "Add increaseAllowance/decreaseAllowance helpers or require callers to set the " +
        "allowance to zero before setting a new non-zero value.",
      severity: "medium",
      file: filePath,
      line: fn.loc?.start?.line ?? 0,
      snippet: getSnippet(source, fn),
    },
    context.member
  );
}

function analyzeAuctionFunction(
  fn: FunctionNode,
  source: string,
  filePath: string,
  context: FunctionAnalysisContext,
  pushFinding: (finding: Finding, member?: MergedMember) => void
): void {
  if (context.hasCommitReveal || !isAuctionBidFunction(fn)) return;

  pushFinding(
    {
      id: "CP-119",
      title: "Public bidding without commit-reveal",
      description:
        "This bidding function appears to compare and update the highest bid directly. " +
        "Visible bids can be copied or outbid from the mempool before inclusion.",
      recommendation:
        "Use a commit-reveal auction flow where bidders first submit a hash commitment " +
        "and only reveal bid amounts after the commit phase closes.",
      severity: "medium",
      file: filePath,
      line: fn.loc?.start?.line ?? 0,
      snippet: getSnippet(source, fn),
    },
    context.member
  );
}

function getContractFunctions(contract: ContractNode): FunctionNode[] {
  return (contract.subNodes ?? []).filter(
    (node: ASTNode) => (node as { type?: string }).type === "FunctionDefinition"
  ) as FunctionNode[];
}

function hasAllowanceAlternative(functionNames: string[]): boolean {
  return functionNames.some((name) =>
    /^(increase|decrease)(Allowance|Approval)$/i.test(name)
  );
}

function hasCommitReveal(functionNames: string[]): boolean {
  const normalized = functionNames.map((name) => name.toLowerCase());
  return (
    normalized.some((name) => name.includes("commit")) &&
    normalized.some((name) => name.includes("reveal"))
  );
}

function isKeccakWithBlockEntropy(call: FunctionCallNode): boolean {
  if (call.expression?.name !== "keccak256") return false;

  const json = JSON.stringify(call);
  return (
    json.includes('"name":"block"') &&
    (json.includes('"memberName":"timestamp"') ||
      json.includes('"memberName":"difficulty"') ||
      json.includes('"memberName":"number"') ||
      json.includes('"memberName":"prevrandao"'))
  );
}

function isAmmSwapWithZeroSlippage(call: FunctionCallNode): boolean {
  const memberName = call.expression?.memberName ?? "";
  if (!memberName.startsWith("swapExact")) return false;

  const args = call.arguments ?? [];
  const amountOutMinIndex = memberName.includes("ETHForTokens") ? 0 : 1;
  return isZeroLiteral(args[amountOutMinIndex]);
}

function isZeroLiteral(node: ASTNode | undefined): boolean {
  if (!node) return false;

  const literal = node as {
    type?: string;
    number?: string;
    value?: string | number;
  };

  if (literal.type !== "NumberLiteral") return false;
  return String(literal.number ?? literal.value ?? "") === "0";
}

function isAuctionBidFunction(fn: FunctionNode): boolean {
  const name = (fn.name ?? "").toLowerCase();
  if (!name.includes("bid") && !name.includes("auction")) return false;

  const body = JSON.stringify(fn.body ?? fn);
  return (
    (body.includes('"name":"highestBid"') ||
      body.includes('"name":"highestBidder"')) &&
    (body.includes('"operator":">"') || body.includes('"operator":">="')) &&
    body.includes('"memberName":"sender"')
  );
}
