import { parseSolidity } from "../ast/parser";
import type { ASTNode } from "../types";
import { matchGovernanceFramework } from "./adapters";
import { GovernanceAnalysisCancelledError } from "./config";
import type {
  GovernanceAnalysisLimits,
  GovernanceCancellationSignal,
  GovernanceContractModel,
  GovernanceDiagnostic,
  GovernanceFunctionRole,
  GovernanceOperation,
  GovernanceSourceLocation,
  GovernanceStateVariable,
  GovernanceTransition,
  GovernanceVariableRole,
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
  subNodes?: ASTNode[];
  variables?: ASTNode[];
  parameters?: ASTNode[];
  modifiers?: ASTNode[];
  expression?: ASTNode;
  left?: ASTNode;
  condition?: ASTNode;
  typeName?: ASTNode;
  baseTypeName?: ASTNode;
  keyType?: ASTNode;
  valueType?: ASTNode;
  [key: string]: unknown;
}

export interface BuildGovernanceModelsResult {
  models: GovernanceContractModel[];
  diagnostics: GovernanceDiagnostic[];
}

export function buildGovernanceModels(
  source: string,
  file: string,
  limits: GovernanceAnalysisLimits,
  signal?: GovernanceCancellationSignal,
): BuildGovernanceModelsResult {
  checkCancelled(signal);
  if (Buffer.byteLength(source, "utf8") > limits.maxSourceBytes) {
    return limited("GOV_SOURCE_LIMIT", `Source exceeds the ${limits.maxSourceBytes}-byte limit`, file);
  }
  const shape = preflightSourceShape(source);
  if (shape.contracts > limits.maxContracts) {
    return limited("GOV_CONTRACT_LIMIT", `Source declares more than ${limits.maxContracts} contracts`, file);
  }
  if (shape.functions > limits.maxFunctionsPerFile) {
    return limited("GOV_FUNCTION_LIMIT", `Source declares more than ${limits.maxFunctionsPerFile} functions`, file);
  }

  const parsed = parseSolidity(source, "<governance-source>");
  if (!parsed.ast) {
    return parseFailure(file, sanitizeParseError(parsed.error));
  }
  const tolerantErrors = (parsed.ast as {
    errors?: Array<{ message?: string; line?: number; column?: number }>;
  }).errors;
  if (tolerantErrors?.length) {
    const first = tolerantErrors[0];
    return {
      models: [],
      diagnostics: [{
        code: "GOV_PARSE_ERROR",
        severity: "error",
        message: `Solidity source could not be parsed: ${sanitizeParserMessage(first.message)}`,
        location: { file, line: first.line ?? 1, column: (first.column ?? 0) + 1 },
      }],
    };
  }

  const contracts = collectNodes(parsed.ast, "ContractDefinition", signal);
  const diagnostics: GovernanceDiagnostic[] = [];
  if (contracts.length > limits.maxContracts) {
    diagnostics.push({
      code: "GOV_CONTRACT_LIMIT",
      severity: "warning",
      message: `Only the first ${limits.maxContracts} contracts were analyzed`,
      location: startLocation(file),
    });
  }
  const models: GovernanceContractModel[] = [];
  for (const contract of contracts.slice(0, limits.maxContracts)) {
    checkCancelled(signal);
    const built = buildContract(source, file, contract, limits);
    diagnostics.push(...built.diagnostics);
    if (isRelevant(built.model)) models.push(built.model);
  }
  return { models, diagnostics };
}

function buildContract(
  source: string,
  file: string,
  contractNode: ASTNode,
  limits: GovernanceAnalysisLimits,
): { model: GovernanceContractModel; diagnostics: GovernanceDiagnostic[] } {
  const contract = contractNode as NodeRecord;
  const stateVariables: GovernanceStateVariable[] = [];
  const functions: ASTNode[] = [];
  const diagnostics: GovernanceDiagnostic[] = [];
  for (const member of contract.subNodes ?? []) {
    const item = member as NodeRecord;
    if (item.type === "StateVariableDeclaration") {
      for (const rawVariable of item.variables ?? []) {
        const variable = rawVariable as NodeRecord;
        if (!variable.name) continue;
        const typeName = stringifyType(variable.typeName);
        stateVariables.push({
          name: variable.name,
          typeName,
          role: classifyVariable(variable.name, typeName),
          isMapping: typeName.startsWith("mapping("),
          location: nodeLocation(variable, file),
        });
      }
    } else if (item.type === "FunctionDefinition" && !item.isConstructor) {
      functions.push(member);
    }
  }

  if (functions.length > limits.maxFunctionsPerContract) {
    diagnostics.push({
      code: "GOV_FUNCTION_LIMIT",
      severity: "warning",
      message: `Contract ${contract.name ?? "<anonymous>"} exceeds the function limit`,
      location: nodeLocation(contract, file),
    });
  }
  const stateNames = new Set(stateVariables.map((variable) => variable.name));
  const transitions: GovernanceTransition[] = [];
  for (const fn of functions.slice(0, limits.maxFunctionsPerContract)) {
    const built = buildTransition(source, file, fn, stateNames, limits);
    transitions.push(built.transition);
    if (built.truncated) {
      diagnostics.push({
        code: "GOV_OPERATION_LIMIT",
        severity: "warning",
        message: `Function ${built.transition.name} exceeded the operation limit`,
        location: built.transition.location,
      });
    }
  }

  const base: GovernanceContractModel = {
    name: contract.name ?? "<anonymous>",
    file,
    adapter: "none",
    stateVariables: stateVariables.sort(byLocationThenName),
    transitions: transitions.sort(byLocationThenName),
    privilegedCalls: [],
    proposalControlledCalls: [],
    assumptions: [],
    location: nodeLocation(contract, file),
  };
  base.privilegedCalls = transitions.flatMap((transition) =>
    transition.operations.filter((operation) =>
      operation.kind === "call" && isPrivilegedCall(operation.name, operation.expression),
    ),
  ).sort(byOperation);
  base.proposalControlledCalls = base.privilegedCalls.filter((operation) =>
    operation.parameterSources.length > 0,
  );
  base.adapter = matchGovernanceFramework(base).adapter;
  base.assumptions = inferAssumptions(base);
  return { model: base, diagnostics };
}

function buildTransition(
  source: string,
  file: string,
  node: ASTNode,
  stateNames: Set<string>,
  limits: GovernanceAnalysisLimits,
): { transition: GovernanceTransition; truncated: boolean } {
  const fn = node as NodeRecord;
  const parameters = (fn.parameters ?? [])
    .map((parameter) => (parameter as NodeRecord).name)
    .filter((name): name is string => Boolean(name));
  const parameterSet = new Set(parameters);
  const reads = new Set<string>();
  const writes = new Set<string>();
  const calls = new Set<string>();
  const operations: GovernanceOperation[] = [];
  let truncated = false;

  walkNode(node, (child) => {
    if (operations.length >= limits.maxOperationsPerFunction) {
      truncated = true;
      return false;
    }
    const record = child as NodeRecord;
    if (record.type === "Assignment" ||
      (record.type === "BinaryOperation" && isAssignmentOperator(record.operator))) {
      const names = expressionNames(record.left);
      for (const name of names) if (stateNames.has(name)) writes.add(name);
      addOperation(operations, "write", [...names].join(",") || "assignment", child, source, file, parameterSet);
    } else if (record.type === "UnaryOperation" && ["++", "--", "delete"].includes(record.operator ?? "")) {
      const names = expressionNames(record.expression);
      for (const name of names) if (stateNames.has(name)) writes.add(name);
      addOperation(operations, "write", [...names].join(",") || "unary", child, source, file, parameterSet);
    } else if (record.type === "FunctionCall") {
      const name = calledName(record.expression);
      if (name) {
        calls.add(name);
        addOperation(
          operations,
          name === "require" || name === "assert" ? "guard" : "call",
          name,
          child,
          source,
          file,
          parameterSet,
        );
      }
    } else if (record.type === "IfStatement" && record.condition) {
      addOperation(operations, "guard", "if", record.condition, source, file, parameterSet);
    } else if (record.type === "BinaryOperation") {
      addOperation(operations, "arithmetic", record.operator ?? "binary", child, source, file, parameterSet);
    } else if (record.type === "Identifier" && record.name && stateNames.has(record.name)) {
      reads.add(record.name);
    } else if (record.type === "MemberAccess" && record.memberName && stateNames.has(record.memberName)) {
      reads.add(record.memberName);
    }
    return true;
  });

  const name = fn.name ?? "<fallback>";
  return {
    transition: {
      name,
      role: classifyFunction(name),
      visibility: fn.visibility ?? "default",
      modifiers: (fn.modifiers ?? []).map(modifierName).filter((value): value is string => Boolean(value)).sort(),
      parameters,
      reads: [...reads].sort(),
      writes: [...writes].sort(),
      calls: [...calls].sort(),
      operations: operations.sort(byOperation),
      location: nodeLocation(fn, file),
      source: nodeSnippet(source, fn),
    },
    truncated,
  };
}

function addOperation(
  operations: GovernanceOperation[],
  kind: GovernanceOperation["kind"],
  name: string,
  node: ASTNode,
  source: string,
  file: string,
  parameters: Set<string>,
): void {
  const record = node as NodeRecord;
  const expression = compact(nodeSnippet(source, record));
  operations.push({
    order: record.range?.[0] ?? operations.length,
    kind,
    name,
    expression,
    parameterSources: [...parameters].filter((parameter) =>
      new RegExp(`\\b${escapeRegExp(parameter)}\\b`).test(expression),
    ).sort(),
    location: nodeLocation(record, file),
  });
}

function classifyVariable(name: string, typeName: string): GovernanceVariableRole {
  const value = normalize(name);
  if (/(governancetoken|votestoken|govtoken|token)/.test(value) && !/(timelock|tokenuri)/.test(value)) return "governance-token";
  if (/(proposalcount|proposalnonce|latestproposalid)/.test(value)) return "proposal-count";
  if (/(proposals|proposalstate|proposalstatus)/.test(value)) return "proposal-state";
  if (/proposalthreshold/.test(value)) return "proposal-threshold";
  if (/quorumnumerator/.test(value)) return "quorum-numerator";
  if (/quorumdenominator/.test(value)) return "quorum-denominator";
  if (/(quorumvotes|quorumthreshold|quorum)/.test(value)) return "quorum";
  if (/votingdelay/.test(value)) return "voting-delay";
  if (/(votingperiod|votingwindow)/.test(value)) return "voting-period";
  if (/(proposalsnapshot|snapshotblock|startblock|votestart)/.test(value)) return "vote-snapshot";
  if (/(receipts|hasvoted|votereceipt)/.test(value)) return "vote-receipt";
  if (/(votingpower|voteweight|votescast)/.test(value)) return "vote-weight";
  if (/(proposaleta|queuedat|executiontime|eta)/.test(value)) return "proposal-eta";
  if (/(mindelay|minimumdelay|timelockdelay)/.test(value)) return "minimum-delay";
  if (/(operationhash|operationid|timestamps)/.test(value)) return "operation-hash";
  if (/(executed|isexecuted)/.test(value)) return "executed-state";
  if (/(canceled|cancelled|iscanceled)/.test(value)) return "canceled-state";
  if (/(nonce|nonces)/.test(value)) return "nonce";
  if (/salt/.test(value)) return "salt";
  if (/predecessor/.test(value)) return "predecessor";
  if (/proposerrole/.test(value)) return "proposer-role";
  if (/executorrole/.test(value)) return "executor-role";
  if (/(adminrole|defaultadminrole|timelockadmin)/.test(value)) return "admin-role";
  if (/(guardian|emergencycouncil|securitycouncil)/.test(value)) return "guardian";
  if (/(owners|signers|members)/.test(value) && (typeName.startsWith("mapping(") || typeName.endsWith("[]"))) return "signer-set";
  if (/(signaturethreshold|multisigthreshold|threshold)/.test(value)) return "signature-threshold";
  if (/(sourcechainid|chainid|domainseparator|domain)/.test(value)) return "chain-domain";
  if (/(messageid|processedmessages|consumedmessages)/.test(value)) return "message-id";
  if (/(upgradeauthority|upgrader|proxyadmin)/.test(value)) return "upgrade-authority";
  return "unknown";
}

function classifyFunction(name: string): GovernanceFunctionRole {
  const value = normalize(name);
  if (/^(propose|createproposal|submitproposal)$/.test(value)) return "propose";
  if (/^(castvote|castvotewithreason|vote|castvotebysig)$/.test(value)) return "cast-vote";
  if (/^(getvotes|getpastvotes|getpriorvotes|votingpower|getvotingpower)$/.test(value)) return "voting-power";
  if (/^(quorum|quorumvotes|getquorum)$/.test(value)) return "quorum";
  if (/^(state|proposalstate|getproposalstate)$/.test(value)) return "proposal-state";
  if (/^(queue|queueproposal)$/.test(value)) return "queue";
  if (/^(schedule|schedulebatch|scheduleoperation)$/.test(value)) return "schedule";
  if (/^(execute|executeproposal|executebatch)$/.test(value)) return "execute";
  if (/^(cancel|cancelproposal|canceloperation)$/.test(value)) return "cancel";
  if (/^(updatedelay|setdelay|setmindelay|changetimelockdelay)$/.test(value)) return "set-delay";
  if (/^(hashproposal|getproposalid)$/.test(value)) return "hash-proposal";
  if (/^(hashoperation|hashoperationbatch)$/.test(value)) return "hash-operation";
  if (/^grantrole$/.test(value)) return "grant-role";
  if (/^revokerole$/.test(value)) return "revoke-role";
  if (/^(emergencyexecute|guardianexecute|fastexecute|emergencyupgrade)$/.test(value)) return "emergency-execute";
  if (/^(upgradeto|upgradetoandcall|authorizeupgrade|upgrade)$/.test(value)) return "upgrade";
  if (/^(receivemessage|handlemessage|executemessage|processmessage|relaymessage)$/.test(value)) return "cross-chain-receive";
  if (/^(checksignatures|validatesignatures|verifysignatures)$/.test(value)) return "validate-signatures";
  if (/^(exectransaction|executetransaction|multisigexecute)$/.test(value)) return "multisig-execute";
  if (/^(delegate|delegatevotes|delegatebysig)$/.test(value)) return "delegate-votes";
  return "unknown";
}

function isRelevant(model: GovernanceContractModel): boolean {
  const roles = new Set(model.transitions.map((transition) => transition.role));
  const variableRoles = model.stateVariables.filter((variable) => variable.role !== "unknown");
  return roles.has("propose") || roles.has("cast-vote") || roles.has("schedule") ||
    roles.has("multisig-execute") || roles.has("cross-chain-receive") ||
    (roles.has("execute") && variableRoles.length >= 2) || variableRoles.length >= 4;
}

function inferAssumptions(model: GovernanceContractModel): string[] {
  const assumptions: string[] = [];
  if (model.transitions.some((transition) => transition.role === "cast-vote")) {
    assumptions.push("Recorded voting weight is intended to remain stable for a proposal snapshot");
  }
  if (model.transitions.some((transition) => ["execute", "schedule"].includes(transition.role))) {
    assumptions.push("Queued operations can invoke privileged external state transitions");
  }
  if (model.transitions.some((transition) => transition.role === "cross-chain-receive")) {
    assumptions.push("The cross-chain transport may redeliver a previously accepted message");
  }
  return assumptions;
}

function isPrivilegedCall(name: string, expression: string): boolean {
  return /^(call|delegatecall|functionCall|functionCallWithValue|upgradeTo|upgradeToAndCall|execute)$/i.test(name) ||
    /\.call\s*\{|\.delegatecall\s*\(|upgradeTo(?:AndCall)?\s*\(/i.test(expression);
}

function stringifyType(node: ASTNode | undefined): string {
  if (!node) return "unknown";
  const type = node as NodeRecord;
  if (type.type === "Mapping") return `mapping(${stringifyType(type.keyType)}=>${stringifyType(type.valueType)})`;
  if (type.type === "ArrayTypeName") return `${stringifyType(type.baseTypeName)}[]`;
  return type.name ?? type.namePath ?? type.type ?? "unknown";
}

function calledName(node: ASTNode | undefined): string | undefined {
  const value = node as NodeRecord | undefined;
  return value?.name ?? value?.memberName ?? value?.namePath ?? calledName(value?.expression);
}

function modifierName(node: ASTNode): string | undefined {
  const value = node as NodeRecord;
  return value.name ?? value.namePath;
}

function expressionNames(root: ASTNode | undefined): Set<string> {
  const names = new Set<string>();
  if (!root) return names;
  walkNode(root, (node) => {
    const value = node as NodeRecord;
    if (value.type === "Identifier" && value.name) names.add(value.name);
    if (value.type === "MemberAccess" && value.memberName) names.add(value.memberName);
    return true;
  });
  return names;
}

function collectNodes(root: ASTNode, type: string, signal?: GovernanceCancellationSignal): ASTNode[] {
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
  while (stack.length) {
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
    for (const key of Object.keys(record).filter((key) => key !== "loc" && key !== "range").sort().reverse()) {
      stack.push(record[key]);
    }
  }
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

function nodeLocation(node: NodeRecord, file: string): GovernanceSourceLocation {
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
  return start && end ? source.split("\n").slice(start - 1, end).join("\n") : "";
}

function compact(value: string): string {
  const result = value.replace(/\s+/g, " ").trim();
  return result.length > 280 ? `${result.slice(0, 277)}...` : result;
}

function isAssignmentOperator(operator: string | undefined): boolean {
  return operator !== undefined && ["=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>="].includes(operator);
}

function byOperation(left: GovernanceOperation, right: GovernanceOperation): number {
  return left.order - right.order || left.kind.localeCompare(right.kind) || left.name.localeCompare(right.name);
}

function byLocationThenName<T extends { location: GovernanceSourceLocation; name: string }>(left: T, right: T): number {
  return left.location.line - right.location.line || left.location.column - right.location.column ||
    left.name.localeCompare(right.name);
}

function limited(
  code: "GOV_SOURCE_LIMIT" | "GOV_CONTRACT_LIMIT" | "GOV_FUNCTION_LIMIT",
  message: string,
  file: string,
): BuildGovernanceModelsResult {
  return { models: [], diagnostics: [{ code, severity: "warning", message, location: startLocation(file) }] };
}

function parseFailure(file: string, message: string): BuildGovernanceModelsResult {
  return {
    models: [],
    diagnostics: [{ code: "GOV_PARSE_ERROR", severity: "error", message, location: startLocation(file) }],
  };
}

function sanitizeParseError(error: string | undefined): string {
  const detail = error?.replace(/^Parse error in <governance-source>:\s*/, "").replace(/\s+/g, " ").trim();
  return `Solidity source could not be parsed${detail ? `: ${detail.slice(0, 300)}` : ""}`;
}

function sanitizeParserMessage(message: string | undefined): string {
  return (message ?? "syntax error").replace(/[\r\n]+/g, " ").slice(0, 300);
}

function startLocation(file: string): GovernanceSourceLocation {
  return { file, line: 1, column: 1 };
}

function checkCancelled(signal?: GovernanceCancellationSignal): void {
  if (signal?.aborted) throw new GovernanceAnalysisCancelledError();
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
