import { parseSolidity } from "../ast/parser";
import type { ASTNode } from "../types";
import { StakingAnalysisCancelledError } from "./config";
import { matchStakingFrameworkAdapter } from "./adapters";
import type {
  AccountingFunctionRole,
  AccountingOperation,
  AccountingStateVariable,
  AccountingTransition,
  AccountingVariableRole,
  StakingAnalysisLimits,
  StakingCancellationSignal,
  StakingContractModel,
  StakingDiagnostic,
  StakingSourceLocation,
} from "./types";

interface NodeRecord {
  type?: string;
  name?: string;
  namePath?: string;
  memberName?: string;
  operator?: string;
  visibility?: string;
  isConstructor?: boolean;
  range?: [number, number];
  loc?: {
    start?: { line?: number; column?: number };
    end?: { line?: number; column?: number };
  };
  children?: ASTNode[];
  subNodes?: ASTNode[];
  variables?: ASTNode[];
  parameters?: ASTNode[];
  modifiers?: ASTNode[];
  expression?: ASTNode;
  left?: ASTNode;
  right?: ASTNode;
  condition?: ASTNode;
  typeName?: ASTNode;
  baseTypeName?: ASTNode;
  keyType?: ASTNode;
  valueType?: ASTNode;
  arguments?: ASTNode[];
  [key: string]: unknown;
}

export interface BuildModelsResult {
  models: StakingContractModel[];
  diagnostics: StakingDiagnostic[];
}

/** Build bounded state-transition models from a parsed Solidity compilation unit. */
export function buildStakingModels(
  source: string,
  file: string,
  limits: StakingAnalysisLimits,
  signal?: StakingCancellationSignal,
): BuildModelsResult {
  checkCancelled(signal);
  const byteLength = Buffer.byteLength(source, "utf8");
  if (byteLength > limits.maxSourceBytes) {
    return {
      models: [],
      diagnostics: [
        {
          code: "STK_SOURCE_LIMIT",
          severity: "warning",
          message: `Source exceeds the ${limits.maxSourceBytes}-byte analysis limit`,
          location: startLocation(file),
        },
      ],
    };
  }

  const preflight = preflightSourceShape(source);
  if (preflight.contracts > limits.maxContracts) {
    return {
      models: [],
      diagnostics: [{
        code: "STK_CONTRACT_LIMIT",
        severity: "warning",
        message: `Source declares more than ${limits.maxContracts} contracts or interfaces`,
        location: startLocation(file),
      }],
    };
  }
  if (preflight.functions > limits.maxFunctionsPerFile) {
    return {
      models: [],
      diagnostics: [{
        code: "STK_FUNCTION_LIMIT",
        severity: "warning",
        message: `Source declares more than ${limits.maxFunctionsPerFile} functions`,
        location: startLocation(file),
      }],
    };
  }

  const parsed = parseSolidity(source, "<staking-source>");
  if (!parsed.ast) {
    return {
      models: [],
      diagnostics: [
        {
          code: "STK_PARSE_ERROR",
          severity: "error",
          message: sanitizeParseError(parsed.error),
          location: startLocation(file),
        },
      ],
    };
  }

  const tolerantErrors = (parsed.ast as { errors?: Array<{ message?: string; line?: number; column?: number }> }).errors;
  if (tolerantErrors && tolerantErrors.length > 0) {
    const first = tolerantErrors[0];
    return {
      models: [],
      diagnostics: [{
        code: "STK_PARSE_ERROR",
        severity: "error",
        message: `Solidity source could not be parsed: ${sanitizeParserMessage(first.message)}`,
        location: {
          file,
          line: first.line ?? 1,
          column: (first.column ?? 0) + 1,
        },
      }],
    };
  }

  const contractNodes = collectNodesByType(parsed.ast, "ContractDefinition", signal);
  const diagnostics: StakingDiagnostic[] = [];
  if (contractNodes.length > limits.maxContracts) {
    diagnostics.push({
      code: "STK_CONTRACT_LIMIT",
      severity: "warning",
      message: `Only the first ${limits.maxContracts} contracts were analyzed`,
      location: startLocation(file),
    });
  }

  const models: StakingContractModel[] = [];
  for (const contractNode of contractNodes.slice(0, limits.maxContracts)) {
    checkCancelled(signal);
    const built = buildContractModel(source, file, contractNode, limits, signal);
    diagnostics.push(...built.diagnostics);
    if (isRelevantAccountingContract(built.model)) {
      models.push(built.model);
    }
  }

  return { models, diagnostics };
}

function buildContractModel(
  source: string,
  file: string,
  contractNode: ASTNode,
  limits: StakingAnalysisLimits,
  signal?: StakingCancellationSignal,
): { model: StakingContractModel; diagnostics: StakingDiagnostic[] } {
  const contract = contractNode as NodeRecord;
  const members = contract.subNodes ?? [];
  const stateVariables: AccountingStateVariable[] = [];
  const functionNodes: ASTNode[] = [];
  const diagnostics: StakingDiagnostic[] = [];

  for (const member of members) {
    const record = member as NodeRecord;
    if (record.type === "StateVariableDeclaration") {
      for (const variable of record.variables ?? []) {
        const item = variable as NodeRecord;
        if (!item.name) continue;
        const typeName = stringifyType(item.typeName);
        stateVariables.push({
          name: item.name,
          typeName,
          role: classifyVariable(item.name, typeName),
          isMapping: typeName.startsWith("mapping("),
          location: nodeLocation(item, file),
        });
      }
    } else if (record.type === "FunctionDefinition" && !record.isConstructor) {
      functionNodes.push(member);
    }
  }

  if (functionNodes.length > limits.maxFunctionsPerContract) {
    diagnostics.push({
      code: "STK_FUNCTION_LIMIT",
      severity: "warning",
      message:
        `Contract ${contract.name ?? "<anonymous>"} has more than ` +
        `${limits.maxFunctionsPerContract} functions; the remainder were skipped`,
      location: nodeLocation(contract, file),
    });
  }

  const stateNames = new Set(stateVariables.map((variable) => variable.name));
  const transitions: AccountingTransition[] = [];
  for (const fnNode of functionNodes.slice(0, limits.maxFunctionsPerContract)) {
    checkCancelled(signal);
    const transition = buildTransition(source, file, fnNode, stateNames, limits);
    transitions.push(transition.value);
    if (transition.truncated) {
      diagnostics.push({
        code: "STK_OPERATION_LIMIT",
        severity: "warning",
        message:
          `Function ${transition.value.name} exceeded the ` +
          `${limits.maxOperationsPerFunction}-operation limit`,
        location: transition.value.location,
      });
    }
  }

  const baseModel: StakingContractModel = {
    name: contract.name ?? "<anonymous>",
    file,
    adapter: "none",
    stateVariables: stateVariables.sort(byLocationThenName),
    transitions: transitions.sort(byLocationThenName),
    precisionScalars: inferPrecisionScalars(source, stateVariables),
    rewardTokens: stateVariables
      .filter((variable) => variable.role === "reward-asset")
      .map((variable) => variable.name)
      .sort(),
    stakeTokens: stateVariables
      .filter((variable) => variable.role === "stake-asset")
      .map((variable) => variable.name)
      .sort(),
    assumptions: [],
    location: nodeLocation(contract, file),
  };

  baseModel.adapter = matchStakingFrameworkAdapter(baseModel).adapter;
  baseModel.assumptions = inferAssumptions(baseModel);
  return { model: baseModel, diagnostics };
}

function buildTransition(
  source: string,
  file: string,
  functionNode: ASTNode,
  stateNames: Set<string>,
  limits: StakingAnalysisLimits,
): { value: AccountingTransition; truncated: boolean } {
  const fn = functionNode as NodeRecord;
  const operations: AccountingOperation[] = [];
  const writeNames = new Set<string>();
  const readNames = new Set<string>();
  const callNames = new Set<string>();
  let truncated = false;

  walkNode(functionNode, (node) => {
    if (operations.length >= limits.maxOperationsPerFunction) {
      truncated = true;
      return false;
    }

    const record = node as NodeRecord;
    if (record.type === "Assignment" ||
      (record.type === "BinaryOperation" && isAssignmentOperator(record.operator))) {
      const targets = collectExpressionNames(record.left);
      for (const target of targets) {
        if (stateNames.has(target)) writeNames.add(target);
      }
      addOperation(operations, "write", [...targets].join(",") || "assignment", node, source, file);
    } else if (record.type === "UnaryOperation" && ["++", "--", "delete"].includes(record.operator ?? "")) {
      const targets = collectExpressionNames(record.expression);
      for (const target of targets) {
        if (stateNames.has(target)) writeNames.add(target);
      }
      addOperation(operations, "write", [...targets].join(",") || "unary", node, source, file);
    } else if (record.type === "FunctionCall") {
      const callName = calledName(record.expression);
      if (callName) {
        callNames.add(callName);
        const kind = callName === "require" || callName === "assert" ? "guard" : "call";
        addOperation(operations, kind, callName, node, source, file);
      }
    } else if (record.type === "IfStatement" && record.condition) {
      addOperation(operations, "guard", "if", record.condition, source, file);
    } else if (record.type === "BinaryOperation") {
      addOperation(operations, "arithmetic", record.operator ?? "binary", node, source, file);
    } else if (record.type === "Identifier" && record.name && stateNames.has(record.name)) {
      readNames.add(record.name);
    } else if (record.type === "MemberAccess" && record.memberName && stateNames.has(record.memberName)) {
      readNames.add(record.memberName);
    }
    return true;
  });

  operations.sort((left, right) =>
    left.order - right.order || left.kind.localeCompare(right.kind) || left.name.localeCompare(right.name),
  );

  const modifiers = (fn.modifiers ?? [])
    .map((modifier) => modifierName(modifier))
    .filter((name): name is string => Boolean(name));
  const parameters = (fn.parameters ?? [])
    .map((parameter) => (parameter as NodeRecord).name)
    .filter((name): name is string => Boolean(name));
  const name = fn.name || (fn.isConstructor ? "constructor" : "<fallback>");

  return {
    value: {
      name,
      role: classifyFunction(name),
      visibility: fn.visibility ?? "default",
      modifiers: [...new Set(modifiers)].sort(),
      parameters,
      reads: [...readNames].sort(),
      writes: [...writeNames].sort(),
      calls: [...callNames].sort(),
      operations,
      location: nodeLocation(fn, file),
      source: nodeSnippet(source, fn),
    },
    truncated,
  };
}

function addOperation(
  operations: AccountingOperation[],
  kind: AccountingOperation["kind"],
  name: string,
  node: ASTNode,
  source: string,
  file: string,
): void {
  const record = node as NodeRecord;
  operations.push({
    order: record.range?.[0] ?? operations.length,
    kind,
    name,
    expression: compactSnippet(nodeSnippet(source, record)),
    location: nodeLocation(record, file),
  });
}

function isRelevantAccountingContract(model: StakingContractModel): boolean {
  const meaningfulVariables = model.stateVariables.filter((variable) => variable.role !== "unknown");
  const meaningfulFunctions = model.transitions.filter((transition) => transition.role !== "unknown");
  const roles = new Set(meaningfulFunctions.map((transition) => transition.role));
  const hasStakingPair = roles.has("stake") && (roles.has("withdraw") || roles.has("exit"));
  const hasRewardAccounting = model.stateVariables.some((variable) =>
    ["reward-rate", "reward-index", "user-index", "accrued-reward"].includes(variable.role),
  );
  const hasVesting = model.stateVariables.some((variable) => variable.role.startsWith("vesting-")) ||
    roles.has("claim-vested") || roles.has("vest");
  return hasStakingPair || hasRewardAccounting || hasVesting || meaningfulVariables.length >= 3;
}

function classifyVariable(name: string, typeName: string): AccountingVariableRole {
  const normalized = normalize(name);
  if (/^(stakingtoken|staketoken|stakingasset|depositasset|lpToken)$/i.test(name)) return "stake-asset";
  if (/(rewardtoken|rewardasset|rewardtokens|rewardsToken)/i.test(name)) return "reward-asset";
  if (/(totalsupply|totalstaked|stakedtotal|poolshares|totalshares)/.test(normalized)) return "total-supply";
  if (/(balances|stakedbalance|stakes|usershares|amountstaked)/.test(normalized) && typeName.startsWith("mapping(")) return "user-balance";
  if (/(rewardrate|rewardspersecond|rewardpersecond|emissionrate|tokenspersecond|rewardperepoch)/.test(normalized)) return "reward-rate";
  if (/(rewardpertokenstored|rewardpershare|accrewardpershare|accumulatedrewardper|rewardindex|globalindex)/.test(normalized)) return "reward-index";
  if (/(userrewardpertokenpaid|rewarddebt|userindex|indexpaid|usersnapshot)/.test(normalized)) return "user-index";
  if (/(rewards|accruedreward|pendingreward|claimablereward)/.test(normalized) && typeName.startsWith("mapping(")) return "accrued-reward";
  if (/(rewardsduration|rewardduration|epochduration|distributionduration)/.test(normalized)) return "duration";
  if (/(periodfinish|rewardend|epochend|distributionend)/.test(normalized)) return "period-finish";
  if (/(lastupdatetime|lastrewardtime|lastupdate|updatedat)/.test(normalized)) return "last-update";
  if (/(queuedrewards?|undistributedrewards?|rewardremainder|carryover)/.test(normalized)) return "queued-reward";
  if (/(currentepoch|epochindex|epochnumber)/.test(normalized)) return "epoch";
  if (/(vestingstart|starttime|vestingbegin)/.test(normalized)) return "vesting-start";
  if (/(vestingduration|vestingperiod|releaseduration)/.test(normalized)) return "vesting-duration";
  if (/(cliff|cliffduration|clifftime)/.test(normalized)) return "vesting-cliff";
  if (/(vestedamount|totalallocation|vestingamount)/.test(normalized)) return "vested-amount";
  if (/(released|claimed|claimedamount|totalclaimed)/.test(normalized)) return "claimed-amount";
  if (/(penalty|withdrawalfee|earlyexitfee)/.test(normalized)) return "penalty";
  if (/(paused|ispaused|pauseflag)/.test(normalized)) return "pause-state";
  if (/(owner|admin|governance|operator|rewarddistributor)/.test(normalized)) return "administrator";
  return "unknown";
}

function classifyFunction(name: string): AccountingFunctionRole {
  const normalized = normalize(name);
  if (/^(stake|deposit|stakefor|depositfor|enter|restake|compound)$/.test(normalized)) return "stake";
  if (/^(withdraw|unstake|withdrawfor|leave)$/.test(normalized)) return "withdraw";
  if (/^(getreward|claimreward|harvest|claimrewards|collectreward)$/.test(normalized)) return "claim-reward";
  if (/^(exit|withdrawall|unstakeall)$/.test(normalized)) return "exit";
  if (/^(updatereward|checkpoint|accrue|updatepool|massupdatepools)$/.test(normalized)) return "checkpoint";
  if (/^(rewardpertoken|pendingreward|earned|updaterewardindex)$/.test(normalized)) return "reward-index";
  if (/^(notifyrewardamount|notifyreward|fundrewards|addrewards)$/.test(normalized)) return "notify-reward";
  if (/^(setrewardrate|setemissionrate|setrewardpersecond|setrewardsduration)$/.test(normalized)) return "set-reward-rate";
  if (/^(emergencywithdraw|emergencyunstake|emergencyexit)$/.test(normalized)) return "emergency-withdraw";
  if (/^(recovererc20|recovertoken|rescuetokens|sweeptoken|recoverasset)$/.test(normalized)) return "recover-token";
  if (/^(pause|pausestaking)$/.test(normalized)) return "pause";
  if (/^(unpause|resumestaking)$/.test(normalized)) return "unpause";
  if (/^(vest|createvesting|addvesting|grantvesting)$/.test(normalized)) return "vest";
  if (/^(release|claimvested|claimvesting|claimtokens)$/.test(normalized)) return "claim-vested";
  if (/^(revoke|revokevesting|cancelvesting)$/.test(normalized)) return "revoke-vesting";
  if (/^(rollepoch|startepoch|nextepoch|updateepoch)$/.test(normalized)) return "epoch-rollover";
  return "unknown";
}

function inferAssumptions(model: StakingContractModel): string[] {
  const assumptions: string[] = [];
  if (model.stakeTokens.length > 0) {
    assumptions.push("The configured stake asset can be transferred by staking entry points");
  }
  if (model.rewardTokens.length > 0) {
    assumptions.push("Reward asset balances are intended to cover accounted user rewards");
  }
  if (model.rewardTokens.length > 1) {
    assumptions.push("Each reward asset requires an independent index and user checkpoint");
  }
  if (model.stateVariables.some((variable) => variable.role === "vesting-cliff")) {
    assumptions.push("The stored cliff is intended to restrict beneficiary claims");
  }
  return assumptions;
}

function inferPrecisionScalars(
  source: string,
  variables: AccountingStateVariable[],
): string[] {
  const scalars = new Set<string>();
  for (const variable of variables) {
    if (/(precision|scale|one|wad|ray)/i.test(variable.name)) scalars.add(variable.name);
  }
  for (const match of source.matchAll(/\b(?:1e\d+|10\s*\*\*\s*\d+)\b/g)) {
    scalars.add(match[0].replace(/\s+/g, ""));
  }
  return [...scalars].sort();
}

function stringifyType(typeNode: ASTNode | undefined): string {
  if (!typeNode) return "unknown";
  const type = typeNode as NodeRecord;
  if (type.type === "Mapping") {
    return `mapping(${stringifyType(type.keyType)}=>${stringifyType(type.valueType)})`;
  }
  if (type.type === "ArrayTypeName") {
    return `${stringifyType(type.baseTypeName)}[]`;
  }
  return type.name ?? type.namePath ?? type.type ?? "unknown";
}

function modifierName(modifier: ASTNode): string | undefined {
  const record = modifier as NodeRecord;
  const name = record.name ?? record.namePath;
  if (name) return name;
  const nested = record.name as unknown;
  return typeof nested === "string" ? nested : undefined;
}

function calledName(expression: ASTNode | undefined): string | undefined {
  const record = expression as NodeRecord | undefined;
  return record?.name ?? record?.memberName ?? record?.namePath;
}

function collectExpressionNames(root: ASTNode | undefined): Set<string> {
  const names = new Set<string>();
  if (!root) return names;
  walkNode(root, (node) => {
    const record = node as NodeRecord;
    if (record.type === "Identifier" && record.name) names.add(record.name);
    if (record.type === "MemberAccess" && record.memberName) names.add(record.memberName);
    return true;
  });
  return names;
}

function collectNodesByType(
  root: ASTNode,
  type: string,
  signal?: StakingCancellationSignal,
): ASTNode[] {
  const nodes: ASTNode[] = [];
  walkNode(root, (node) => {
    checkCancelled(signal);
    if ((node as NodeRecord).type === type) nodes.push(node);
    return true;
  });
  return nodes;
}

function walkNode(root: unknown, visitor: (node: ASTNode) => boolean): void {
  const stack: unknown[] = [root];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const value = stack.pop();
    if (!value || typeof value !== "object") continue;
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index--) stack.push(value[index]);
      continue;
    }
    if (seen.has(value)) continue;
    seen.add(value);
    if (!visitor(value as ASTNode)) continue;
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).filter((key) => key !== "loc" && key !== "range").sort().reverse();
    for (const key of keys) stack.push(record[key]);
  }
}

function nodeLocation(node: NodeRecord, file: string): StakingSourceLocation {
  return {
    file,
    line: node.loc?.start?.line ?? 1,
    column: (node.loc?.start?.column ?? 0) + 1,
    ...(node.loc?.end?.line ? { lineEnd: node.loc.end.line } : {}),
    ...(node.loc?.end?.column !== undefined ? { columnEnd: node.loc.end.column + 1 } : {}),
  };
}

function nodeSnippet(source: string, node: NodeRecord): string {
  if (node.range) return source.slice(node.range[0], node.range[1] + 1);
  const start = node.loc?.start?.line;
  const end = node.loc?.end?.line;
  if (!start || !end) return "";
  return source.split("\n").slice(start - 1, end).join("\n");
}

function compactSnippet(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  return compact.length > 240 ? `${compact.slice(0, 237)}...` : compact;
}

function sanitizeParseError(error: string | undefined): string {
  if (!error) return "Solidity source could not be parsed";
  const detail = error.replace(/^Parse error in <staking-source>:\s*/, "").replace(/\s+/g, " ").trim();
  return `Solidity source could not be parsed${detail ? `: ${detail}` : ""}`;
}

function sanitizeParserMessage(message: string | undefined): string {
  if (!message) return "syntax error";
  return message.replace(/[\r\n]+/g, " ").slice(0, 300);
}

function preflightSourceShape(source: string): { contracts: number; functions: number } {
  const code = source.replace(
    /\/\*[\s\S]*?\*\/|\/\/[^\n\r]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g,
    " ",
  );
  return {
    contracts: countMatches(code, /\b(?:contract|interface|library)\s+[A-Za-z_$][\w$]*/g),
    functions: countMatches(code, /\bfunction\b/g),
  };
}

function countMatches(value: string, expression: RegExp): number {
  let count = 0;
  while (expression.exec(value)) count += 1;
  return count;
}

function isAssignmentOperator(operator: string | undefined): boolean {
  return operator !== undefined && new Set([
    "=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>=",
  ]).has(operator);
}

function startLocation(file: string): StakingSourceLocation {
  return { file, line: 1, column: 1 };
}

function checkCancelled(signal?: StakingCancellationSignal): void {
  if (signal?.aborted) throw new StakingAnalysisCancelledError();
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function byLocationThenName<T extends { location: StakingSourceLocation; name: string }>(
  left: T,
  right: T,
): number {
  return left.location.line - right.location.line ||
    left.location.column - right.location.column ||
    left.name.localeCompare(right.name);
}
