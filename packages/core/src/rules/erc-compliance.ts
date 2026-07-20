import { visit, getSnippet } from "../ast/parser";
import type { Finding, ASTNode } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";
import type { MergedMember } from "../ast/import-graph";

export function detectERCStandard(ast: ASTNode): "ERC20" | "ERC721" | "ERC1155" | null {
  const functionNames = new Set<string>();

  visit(ast, {
    FunctionDefinition(node: ASTNode) {
      const fn = node as { name?: string };
      if (fn.name) {
        functionNames.add(fn.name);
      }
    },
  });

  // ERC-1155 heuristics
  if (
    functionNames.has("balanceOfBatch") ||
    functionNames.has("safeBatchTransferFrom") ||
    functionNames.has("onERC1155Received") ||
    functionNames.has("onERC1155BatchReceived")
  ) {
    return "ERC1155";
  }

  // ERC-721 heuristics
  if (
    functionNames.has("ownerOf") ||
    functionNames.has("safeTransferFrom") ||
    functionNames.has("tokenURI") ||
    functionNames.has("onERC721Received")
  ) {
    return "ERC721";
  }

  // ERC-20 heuristics
  if (
    functionNames.has("transfer") &&
    (functionNames.has("allowance") ||
      functionNames.has("approve") ||
      functionNames.has("decimals") ||
      functionNames.has("balanceOf") ||
      functionNames.has("totalSupply"))
  ) {
    return "ERC20";
  }

  return null;
}

export function checkERC20Compliance(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions
): Finding[] {
  const findings: Finding[] = [];
  const members = options?.contractView?.members ?? [];

  const functionsToCheck: Array<{ member?: MergedMember; node: ASTNode; source: string }> =
    members.length > 0
      ? members
          .filter((m) => m.kind === "function")
          .map((m) => ({ member: m, node: m.node, source: m.source }))
      : [];

  if (functionsToCheck.length === 0) {
    visit(ast, {
      FunctionDefinition(node: ASTNode) {
        functionsToCheck.push({ node, source });
      },
    });
  }

  // Event check
  const eventNames = new Set<string>();
  visit(ast, {
    EventDefinition(node: ASTNode) {
      const evt = node as { name?: string };
      if (evt.name) eventNames.add(evt.name);
    },
  });

  if (!eventNames.has("Transfer") || !eventNames.has("Approval")) {
    const line = 1;
    const missing = [];
    if (!eventNames.has("Transfer")) missing.push("Transfer");
    if (!eventNames.has("Approval")) missing.push("Approval");

    findings.push(
      applyFindingContext(
        {
          id: "CP-ERC20-EVENTS",
          title: "Missing standard ERC-20 event declarations",
          description:
            `ERC-20 standard requires Transfer and Approval events to be declared and emitted. ` +
            `Missing events: ${missing.join(", ")}.`,
          recommendation:
            "Declare `event Transfer(address indexed from, address indexed to, uint256 value);` " +
            "and `event Approval(address indexed owner, address indexed spender, uint256 value);`.",
          severity: "high",
          file: filePath,
          line,
        },
        undefined,
        options?.contractView
      )
    );
  }

  let hasApprove = false;
  let hasIncreaseAllowance = false;

  for (const { member, node, source: memberSource } of functionsToCheck) {
    const fn = node as {
      name?: string;
      visibility?: string;
      returnParameters?: ASTNode[];
      parameters?: ASTNode[];
      loc?: { start?: { line?: number } };
    };

    if (!fn.name) continue;

    // Check return value of transfer / transferFrom
    if (fn.name === "transfer" || fn.name === "transferFrom") {
      const returns = fn.returnParameters ?? [];
      let returnsBool = false;

      if (returns.length === 1) {
        const retType = returns[0] as { typeAnnotation?: { name?: string }; typeName?: { name?: string } };
        const typeName = retType.typeName?.name ?? retType.typeAnnotation?.name;
        if (typeName === "bool") {
          returnsBool = true;
        }
      }

      if (!returnsBool) {
        const line = fn.loc?.start?.line ?? 1;
        findings.push(
          applyFindingContext(
            {
              id: "CP-ERC20-RETURN",
              title: `Non-standard return type on ${fn.name}`,
              description:
                `Function "${fn.name}" in ERC-20 token does not return a boolean value. ` +
                `The ERC-20 standard specifies returning a boolean indicating success. Missing bool returns break integrators and DEX routers.`,
              recommendation: `Update "${fn.name}" to specify \`returns (bool)\` and return \`true\` on success.`,
              severity: "high",
              file: filePath,
              line,
              snippet: getSnippet(memberSource, node),
            },
            member,
            options?.contractView
          )
        );
      }
    }

    // Check decimals return type
    if (fn.name === "decimals") {
      const returns = fn.returnParameters ?? [];
      let returnsUint8 = false;

      if (returns.length === 1) {
        const retType = returns[0] as { typeName?: { name?: string } };
        if (retType.typeName?.name === "uint8") {
          returnsUint8 = true;
        }
      }

      if (!returnsUint8) {
        const line = fn.loc?.start?.line ?? 1;
        findings.push(
          applyFindingContext(
            {
              id: "CP-ERC20-DECIMALS",
              title: "Non-standard decimals return type",
              description:
                `Function "decimals()" returns non-uint8 type. Standard ERC-20 requires decimals to return uint8.`,
              recommendation: 'Change return type of decimals() to uint8.',
              severity: "medium",
              file: filePath,
              line,
              snippet: getSnippet(memberSource, node),
            },
            member,
            options?.contractView
          )
        );
      }
    }

    if (fn.name === "approve") hasApprove = true;
    if (fn.name === "increaseAllowance") hasIncreaseAllowance = true;
  }

  if (hasApprove && !hasIncreaseAllowance) {
    findings.push(
      applyFindingContext(
        {
          id: "CP-ERC20-APPROVE-RACE",
          title: "ERC-20 approve race condition vulnerability",
          description:
            "Contract provides approve() without increaseAllowance()/decreaseAllowance() helpers. " +
            "Changing approvals directly via approve() is vulnerable to front-running double-spend attacks.",
          recommendation:
            "Implement increaseAllowance and decreaseAllowance helper functions or enforce resetting approval to zero before updating.",
          severity: "low",
          file: filePath,
          line: 1,
        },
        undefined,
        options?.contractView
      )
    );
  }

  return findings;
}

export function checkERC721Compliance(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions
): Finding[] {
  const findings: Finding[] = [];
  const members = options?.contractView?.members ?? [];

  const functionsToCheck: Array<{ member?: MergedMember; node: ASTNode; source: string }> =
    members.length > 0
      ? members
          .filter((m) => m.kind === "function")
          .map((m) => ({ member: m, node: m.node, source: m.source }))
      : [];

  if (functionsToCheck.length === 0) {
    visit(ast, {
      FunctionDefinition(node: ASTNode) {
        functionsToCheck.push({ node, source });
      },
    });
  }

  let hasSupportsInterface = false;

  for (const { member, node, source: memberSource } of functionsToCheck) {
    const fn = node as {
      name?: string;
      visibility?: string;
      modifiers?: ASTNode[];
      loc?: { start?: { line?: number } };
    };

    if (!fn.name) continue;

    if (fn.name === "supportsInterface") {
      hasSupportsInterface = true;
    }

    // Check reentrancy in safeTransferFrom / _safeTransfer
    if (fn.name === "safeTransferFrom" || fn.name === "_safeTransfer" || fn.name === "_safeMint") {
      const fnStr = JSON.stringify(node);
      const invokesCallback =
        fnStr.includes("onERC721Received") || fnStr.includes("_checkOnERC721Received");
      const hasReentrancyGuard =
        fn.modifiers?.some((m) => {
          const modName = (m as { name?: string }).name ?? "";
          return modName.includes("nonReentrant") || modName.includes("reentrancy");
        }) ?? false;

      if (invokesCallback && !hasReentrancyGuard) {
        const line = fn.loc?.start?.line ?? 1;
        findings.push(
          applyFindingContext(
            {
              id: "CP-ERC721-REENTRANCY",
              title: "Missing reentrancy guard on ERC-721 safe transfer callback",
              description:
                `Function "${fn.name}" invokes the onERC721Received receiver callback on arbitrary recipient addresses ` +
                `without a reentrancy guard. Malicious contracts can reenter the NFT contract during mint/transfer.`,
              recommendation:
                "Apply OpenZeppelin's `nonReentrant` modifier to safeTransferFrom and safeMint functions.",
              severity: "high",
              file: filePath,
              line,
              snippet: getSnippet(memberSource, node),
            },
            member,
            options?.contractView
          )
        );
      }
    }

    // Check unrestricted minting
    if (
      (fn.name === "mint" || fn.name === "safeMint" || fn.name === "_mint") &&
      (fn.visibility === "public" || fn.visibility === "external")
    ) {
      const hasAccessControl =
        fn.modifiers?.some((m) => {
          const modName = (m as { name?: string }).name ?? "";
          return (
            modName.includes("onlyOwner") ||
            modName.includes("onlyRole") ||
            modName.includes("auth") ||
            modName.startsWith("only")
          );
        }) ?? false;

      if (!hasAccessControl) {
        const line = fn.loc?.start?.line ?? 1;
        findings.push(
          applyFindingContext(
            {
              id: "CP-ERC721-UNRESTRICTED-MINT",
              title: "Unrestricted minting function",
              description:
                `Public/external mint function "${fn.name}" is callable without access control guards. ` +
                `Any external user can freely mint NFTs.`,
              recommendation: "Add access control modifier (e.g. onlyOwner or onlyRole) to restriction minting.",
              severity: "critical",
              file: filePath,
              line,
              snippet: getSnippet(memberSource, node),
            },
            member,
            options?.contractView
          )
        );
      }
    }
  }

  if (!hasSupportsInterface) {
    findings.push(
      applyFindingContext(
        {
          id: "CP-ERC721-ERC165",
          title: "Missing ERC-165 supportsInterface implementation",
          description:
            "ERC-721 standard mandates support for ERC-165 supportsInterface(bytes4) function to allow interface detection.",
          recommendation: "Implement supportsInterface(bytes4 interfaceId) returning true for ERC-721 interface ID (0x80ac58cd).",
          severity: "medium",
          file: filePath,
          line: 1,
        },
        undefined,
        options?.contractView
      )
    );
  }

  return findings;
}

export function checkERC1155Compliance(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: RuleOptions
): Finding[] {
  const findings: Finding[] = [];
  const members = options?.contractView?.members ?? [];

  const functionsToCheck: Array<{ member?: MergedMember; node: ASTNode; source: string }> =
    members.length > 0
      ? members
          .filter((m) => m.kind === "function")
          .map((m) => ({ member: m, node: m.node, source: m.source }))
      : [];

  if (functionsToCheck.length === 0) {
    visit(ast, {
      FunctionDefinition(node: ASTNode) {
        functionsToCheck.push({ node, source });
      },
    });
  }

  // Event check
  const eventNames = new Set<string>();
  visit(ast, {
    EventDefinition(node: ASTNode) {
      const evt = node as { name?: string };
      if (evt.name) eventNames.add(evt.name);
    },
  });

  if (!eventNames.has("TransferSingle") || !eventNames.has("TransferBatch")) {
    const line = 1;
    const missing = [];
    if (!eventNames.has("TransferSingle")) missing.push("TransferSingle");
    if (!eventNames.has("TransferBatch")) missing.push("TransferBatch");

    findings.push(
      applyFindingContext(
        {
          id: "CP-ERC1155-EVENTS",
          title: "Missing standard ERC-1155 transfer events",
          description:
            `ERC-1155 standard requires TransferSingle and TransferBatch events to be declared and emitted. ` +
            `Missing events: ${missing.join(", ")}.`,
          recommendation:
            "Declare `event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);` " +
            "and `event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values);`.",
          severity: "high",
          file: filePath,
          line,
        },
        undefined,
        options?.contractView
      )
    );
  }

  for (const { member, node, source: memberSource } of functionsToCheck) {
    const fn = node as {
      name?: string;
      modifiers?: ASTNode[];
      loc?: { start?: { line?: number } };
    };

    if (!fn.name) continue;

    if (
      fn.name === "safeTransferFrom" ||
      fn.name === "safeBatchTransferFrom" ||
      fn.name === "_doSafeTransferAcceptanceCheck" ||
      fn.name === "_doSafeBatchTransferAcceptanceCheck"
    ) {
      const fnStr = JSON.stringify(node);
      const invokesCallback =
        fnStr.includes("onERC1155Received") || fnStr.includes("onERC1155BatchReceived");
      const hasReentrancyGuard =
        fn.modifiers?.some((m) => {
          const modName = (m as { name?: string }).name ?? "";
          return modName.includes("nonReentrant") || modName.includes("reentrancy");
        }) ?? false;

      if (invokesCallback && !hasReentrancyGuard) {
        const line = fn.loc?.start?.line ?? 1;
        findings.push(
          applyFindingContext(
            {
              id: "CP-ERC1155-REENTRANCY",
              title: "Missing reentrancy guard on ERC-1155 callback",
              description:
                `Function "${fn.name}" triggers onERC1155Received / onERC1155BatchReceived callback on recipient address ` +
                `without a reentrancy guard.`,
              recommendation:
                "Apply `nonReentrant` modifier to safe batch and single transfer functions.",
              severity: "high",
              file: filePath,
              line,
              snippet: getSnippet(memberSource, node),
            },
            member,
            options?.contractView
          )
        );
      }
    }
  }

  return findings;
}
