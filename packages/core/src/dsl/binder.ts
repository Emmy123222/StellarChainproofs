import type { MergedContractView, MergedMember } from "../ast/import-graph";
import type { ASTNode } from "../types";
import { DiagnosticBag } from "./diagnostics";
import type { InvariantScopeRaw } from "./types";

export interface FunctionSignature {
  member: MergedMember;
  name: string;
  paramTypes: string[];
  signature: string;
}

function typeNameToString(typeName: ASTNode | null | undefined): string {
  if (!typeName) return "unknown";
  const t = typeName as { type?: string; name?: string; namePath?: string; keyType?: ASTNode; valueType?: ASTNode; baseTypeName?: ASTNode };
  if (t.type === "ElementaryTypeName") return t.name ?? "unknown";
  if (t.type === "UserDefinedTypeName") return t.namePath ?? "unknown";
  if (t.type === "Mapping") return `mapping(${typeNameToString(t.keyType)}=>${typeNameToString(t.valueType)})`;
  if (t.type === "ArrayTypeName") return `${typeNameToString(t.baseTypeName)}[]`;
  return "unknown";
}

/** Extract the `(type1,type2,...)` signature suffix for a function member, for overload disambiguation. */
export function functionSignature(member: MergedMember): FunctionSignature {
  const node = member.node as { name?: string; parameters?: ASTNode[] };
  const paramTypes = (node.parameters ?? []).map((p) => {
    const param = p as { typeName?: ASTNode };
    return typeNameToString(param.typeName);
  });
  return {
    member,
    name: member.name,
    paramTypes,
    signature: `${member.name}(${paramTypes.join(",")})`,
  };
}

export interface ResolvedScope {
  contractView: MergedContractView;
  /** Undefined for contract-wide invariants (`state`, `cross-function` without `scope.function`). */
  functionMember?: MergedMember;
}

/**
 * Resolve an {@link InvariantScopeRaw} against the parsed/merged contract
 * views for the current target set. Reports `DSL012`/`DSL013`/`DSL014`
 * diagnostics for an unknown contract, unknown function, or an ambiguous
 * overloaded-function reference (multiple functions share a name and
 * `scope.signature` wasn't given to disambiguate).
 */
export function resolveScope(
  scope: InvariantScopeRaw,
  views: MergedContractView[],
  diagnostics: DiagnosticBag,
  invariantId: string,
  requiresFunction: boolean,
): ResolvedScope | undefined {
  const contractView = views.find((v) => v.name === scope.contract);
  if (!contractView) {
    diagnostics.error(
      "DSL012",
      `${invariantId}: unknown contract '${scope.contract}' — no matching contract found in the scanned targets`,
      undefined,
      invariantId,
    );
    return undefined;
  }

  if (!scope.function) {
    if (requiresFunction) {
      diagnostics.error(
        "DSL020",
        `${invariantId}: 'scope.function' is required for this invariant kind`,
        undefined,
        invariantId,
      );
      return undefined;
    }
    return { contractView };
  }

  const candidates = contractView.members.filter(
    (m) => m.kind === "function" && m.name === scope.function,
  );

  if (candidates.length === 0) {
    diagnostics.error(
      "DSL013",
      `${invariantId}: unknown function '${scope.function}' on contract '${scope.contract}'`,
      undefined,
      invariantId,
    );
    return undefined;
  }

  if (candidates.length === 1) {
    return { contractView, functionMember: candidates[0] };
  }

  // Overloaded function — require an explicit signature to disambiguate.
  const signatures = candidates.map(functionSignature);
  if (scope.signature) {
    const match = signatures.find((s) => s.signature === scope.signature);
    if (match) return { contractView, functionMember: match.member };
    diagnostics.error(
      "DSL014",
      `${invariantId}: signature '${scope.signature}' does not match any overload of '${scope.function}'. ` +
        `Available: ${signatures.map((s) => s.signature).join(", ")}`,
      undefined,
      invariantId,
    );
    return undefined;
  }

  diagnostics.error(
    "DSL014",
    `${invariantId}: '${scope.function}' is overloaded (${signatures.map((s) => s.signature).join(", ")}) — ` +
      `add 'scope.signature' to disambiguate`,
    undefined,
    invariantId,
  );
  return undefined;
}
