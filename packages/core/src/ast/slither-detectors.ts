import type { Severity } from "../types";

/**
 * Static metadata about a single Slither detector, used to enrich a raw
 * Slither finding with a title, an optional SWC cross-reference, and a
 * `category` used to deduplicate against ChainProof's own built-in rules
 * (see {@link mergeSlitherFindings} in `./slither.ts`).
 *
 * @internal
 */
export interface SlitherDetectorInfo {
  /**
   * Rule-category id this detector overlaps with. When a built-in ChainProof
   * rule already covers the same vulnerability class, use that rule's id
   * (e.g. `"CP-107"`) so the two engines' findings can be deduplicated. When
   * there is no built-in equivalent, use a stable `"CP-SL-*"` id.
   */
  category: string;
  /** SWC Registry cross-reference, if one applies. */
  swcId?: string;
  /** Human-readable title shown in reports, in place of the raw check name. */
  title: string;
  /**
   * Force a specific ChainProof severity regardless of Slither's
   * impact/confidence, for detectors whose real-world risk doesn't track
   * Slither's own classification (e.g. `suicidal` is always critical).
   */
  severityOverride?: Severity;
}

/**
 * Registry of Slither's built-in detectors, mapped to ChainProof rule
 * categories, SWC references, and display titles.
 *
 * Detectors not present here still produce a finding (see
 * {@link buildFindingFromDetector} in `./slither.ts`) with a humanized title
 * derived from the check name and no SWC reference — this table exists to
 * enrich, not gate, Slither's output.
 *
 * @internal
 */
export const DETECTOR_MAP: Record<string, SlitherDetectorInfo> = {
  // ─── Reentrancy ──────────────────────────────────────────────────────────
  "reentrancy-eth": {
    category: "CP-107",
    swcId: "SWC-107",
    title: "Reentrancy (ETH transfer)",
  },
  "reentrancy-no-eth": {
    category: "CP-107",
    swcId: "SWC-107",
    title: "Reentrancy (no ETH transfer)",
  },
  "reentrancy-benign": {
    category: "CP-107",
    swcId: "SWC-107",
    title: "Reentrancy (benign — state written before the read-only call)",
  },
  "reentrancy-events": {
    category: "CP-107",
    swcId: "SWC-107",
    title: "Reentrancy affecting event ordering",
  },
  "reentrancy-unlimited-gas": {
    category: "CP-107",
    swcId: "SWC-107",
    title: "Reentrancy via a call forwarding all remaining gas",
  },

  // ─── Access control / privileged operations ─────────────────────────────
  suicidal: {
    category: "CP-SL-SUICIDAL",
    swcId: "SWC-106",
    title: "Unprotected self-destruct",
    severityOverride: "critical",
  },
  "arbitrary-send-eth": {
    category: "CP-SL-ARBITRARY-SEND-ETH",
    swcId: "SWC-105",
    title: "Arbitrary ETH send to a user-controlled address",
    severityOverride: "critical",
  },
  "arbitrary-send-erc20": {
    category: "CP-SL-ARBITRARY-SEND-ERC20",
    title: "Arbitrary `transferFrom` on behalf of an uncontrolled address",
    severityOverride: "critical",
  },
  "arbitrary-send-erc20-permit": {
    category: "CP-SL-ARBITRARY-SEND-ERC20",
    title: "ERC20 permit used without validating the owner",
  },
  "controlled-delegatecall": {
    category: "CP-SL-CONTROLLED-DELEGATECALL",
    swcId: "SWC-112",
    title: "Delegatecall to a user-controlled address",
    severityOverride: "critical",
  },
  "delegatecall-loop": {
    category: "CP-SL-DELEGATECALL-LOOP",
    swcId: "SWC-112",
    title: "Delegatecall inside a loop",
  },
  "unprotected-upgrade": {
    category: "CP-116",
    title: "Unprotected upgradeable contract initializer/authorizer",
    severityOverride: "critical",
  },
  "tx-origin": {
    category: "CP-115",
    swcId: "SWC-115",
    title: "Use of tx.origin for authentication",
  },
  "protected-vars": {
    category: "CP-SL-PROTECTED-VARS",
    title: "State variable lacks access control on a sensitive setter",
  },
  "unchecked-transfer": {
    category: "CP-104",
    swcId: "SWC-104",
    title: "Unchecked ERC20 transfer/transferFrom return value",
  },

  // ─── Uninitialized / storage layout ─────────────────────────────────────
  "uninitialized-state": {
    category: "CP-SL-UNINITIALIZED-STATE",
    swcId: "SWC-109",
    title: "Uninitialized state variable",
  },
  "uninitialized-storage": {
    category: "CP-SL-UNINITIALIZED-STORAGE",
    swcId: "SWC-109",
    title: "Uninitialized storage pointer",
    severityOverride: "critical",
  },
  "uninitialized-local": {
    category: "CP-SL-UNINITIALIZED-LOCAL",
    title: "Uninitialized local variable",
  },
  "uninitialized-fptr-cst": {
    category: "CP-SL-UNINITIALIZED-FPTR",
    title: "Uninitialized function pointer called in a constructor",
    severityOverride: "critical",
  },
  "storage-array": {
    category: "CP-SL-STORAGE-ARRAY",
    title: "Storage array deletion may leave a nested mapping's data intact",
  },
  "delegatecall-to-fptr": {
    category: "CP-SL-DELEGATECALL-LOOP",
    title: "Delegatecall to a storage-stored function pointer",
  },

  // ─── Correctness ─────────────────────────────────────────────────────────
  "incorrect-equality": {
    category: "CP-SL-INCORRECT-EQUALITY",
    swcId: "SWC-132",
    title: "Dangerous strict equality on a balance or timestamp",
  },
  "incorrect-modifier": {
    category: "CP-SL-INCORRECT-MODIFIER",
    title: "Modifier with a return path that never executes the function body",
    severityOverride: "critical",
  },
  "incorrect-unary": {
    category: "CP-SL-INCORRECT-UNARY",
    title: "Dangerous unary expression (e.g. `x =- 1` instead of `x -= 1`)",
  },
  "divide-before-multiply": {
    category: "CP-SL-DIVIDE-BEFORE-MULTIPLY",
    title: "Division before multiplication causes precision loss",
  },
  "tautology": {
    category: "CP-SL-TAUTOLOGY",
    title: "Tautology or contradiction in a conditional expression",
  },
  "boolean-cst": {
    category: "CP-SL-BOOLEAN-MISUSE",
    title: "Misuse of a boolean constant",
  },
  "boolean-equal": {
    category: "CP-SL-BOOLEAN-MISUSE",
    title: "Comparison to a boolean constant",
  },
  "return-leave": {
    category: "CP-SL-RETURN-LEAVE",
    title: "Inline assembly `leave` skips the function's remaining logic",
    severityOverride: "critical",
  },
  "write-after-write": {
    category: "CP-SL-WRITE-AFTER-WRITE",
    title: "Variable written twice without being read in between",
  },
  "shadowing-state": {
    category: "CP-SL-SHADOWING-STATE",
    swcId: "SWC-119",
    title: "State variable shadows one from an inherited contract",
    severityOverride: "high",
  },
  "shadowing-abstract": {
    category: "CP-SL-SHADOWING-STATE",
    swcId: "SWC-119",
    title: "State variable shadows one from an abstract base contract",
  },
  "shadowing-builtin": {
    category: "CP-SL-SHADOWING-BUILTIN",
    title: "Local variable shadows a Solidity builtin symbol",
  },
  "shadowing-local": {
    category: "CP-SL-SHADOWING-LOCAL",
    title: "Local variable shadows another declaration in the same scope",
  },
  "void-cst": {
    category: "CP-SL-VOID-CONSTRUCTOR",
    title: "Constructor call looks like a function call and has no effect",
  },
  "name-reused": {
    category: "CP-SL-NAME-REUSED",
    title: "Contract name reused across multiple files, ambiguous imports",
  },
  "domain-separator-collision": {
    category: "CP-SL-DOMAIN-SEPARATOR",
    title: "EIP-712 domain separator collides with an inherited function",
  },
  "erc20-interface": {
    category: "CP-SL-ERC20-INTERFACE",
    title: "ERC20 interface does not match the standard signature",
  },
  "erc721-interface": {
    category: "CP-SL-ERC721-INTERFACE",
    title: "ERC721 interface does not match the standard signature",
  },
  "unchecked-lowlevel": {
    category: "CP-104",
    swcId: "SWC-104",
    title: "Unchecked low-level call return value",
  },
  "unchecked-send": {
    category: "CP-104",
    swcId: "SWC-104",
    title: "Unchecked `.send()` return value",
  },
  "unused-return": {
    category: "CP-SL-UNUSED-RETURN",
    title: "Ignored return value of a call that can fail",
  },
  "locked-ether": {
    category: "CP-SL-LOCKED-ETHER",
    title: "Contract can receive ETH but has no way to withdraw it",
  },
  "mapping-deletion": {
    category: "CP-SL-STORAGE-ARRAY",
    title: "Deleting a struct containing a mapping leaves the mapping's data",
  },
  "reused-constructor": {
    category: "CP-SL-REUSED-CONSTRUCTOR",
    title: "Base constructor arguments provided both inline and in the derived constructor",
  },
  "multiple-constructor-schemes": {
    category: "CP-SL-MULTIPLE-CONSTRUCTORS",
    title: "Contract defines a constructor using both old and new syntax",
  },
  "public-mappings-nested": {
    category: "CP-SL-PUBLIC-MAPPINGS-NESTED",
    title: "Public mapping with a nested variable-length key/value type",
  },

  // ─── Weak randomness / timestamp ─────────────────────────────────────────
  "weak-prng": {
    category: "CP-SL-WEAK-PRNG",
    swcId: "SWC-120",
    title: "Weak source of randomness (block attributes, blockhash)",
  },
  timestamp: {
    category: "CP-SL-TIMESTAMP",
    swcId: "SWC-116",
    title: "Dangerous reliance on `block.timestamp`",
  },

  // ─── Low-level / style — informational-leaning ──────────────────────────
  assembly: {
    category: "CP-SL-ASSEMBLY",
    title: "Use of inline assembly",
  },
  "low-level-calls": {
    category: "CP-SL-LOW-LEVEL-CALLS",
    title: "Use of a low-level `.call()`",
  },
  "calls-loop": {
    category: "CP-SL-CALLS-LOOP",
    title: "External call inside a loop",
  },
  "msg-value-loop": {
    category: "CP-SL-MSG-VALUE-LOOP",
    title: "`msg.value` used inside a loop",
    severityOverride: "high",
  },
  "rtlo": {
    category: "CP-SL-RTLO",
    title: "Right-to-left-override unicode character in source",
    severityOverride: "high",
  },
  "constant-function-asm": {
    category: "CP-SL-CONSTANT-FUNCTION",
    title: "Function flagged `view`/`pure` but contains state-changing assembly",
  },
  "constant-function-state": {
    category: "CP-SL-CONSTANT-FUNCTION",
    title: "Function flagged `view`/`pure` but changes state",
  },
  "too-many-digits": {
    category: "CP-SL-TOO-MANY-DIGITS",
    title: "Literal with a large number of digits — a magnitude typo risk",
  },
  "unindexed-erc20-transfer": {
    category: "CP-SL-UNINDEXED-EVENT",
    title: "ERC20 `Transfer`/`Approval` event missing `indexed` on address params",
  },
  "constable-states": {
    category: "CP-SL-CONSTABLE-STATES",
    title: "State variable could be declared `constant`",
  },
  "immutable-states": {
    category: "CP-SL-IMMUTABLE-STATES",
    title: "State variable could be declared `immutable`",
  },
  "external-function": {
    category: "CP-SL-EXTERNAL-FUNCTION",
    title: "Public function is never called internally — could be `external`",
  },
  "dead-code": {
    category: "CP-SL-DEAD-CODE",
    title: "Unused private/internal function",
  },
  "costly-loop": {
    category: "CP-SL-COSTLY-LOOP",
    title: "Storage read/write inside a loop wastes gas",
  },
  "cache-array-length": {
    category: "CP-SL-CACHE-ARRAY-LENGTH",
    title: "Array length not cached before a loop",
  },
  "similar-names": {
    category: "CP-SL-SIMILAR-NAMES",
    title: "Variable names differ only by case or a single character",
  },
  "unused-state": {
    category: "CP-SL-UNUSED-STATE",
    title: "Unused state variable",
  },
  "naming-convention": {
    category: "CP-SL-NAMING-CONVENTION",
    title: "Identifier does not follow Solidity naming conventions",
  },
  pragma: {
    category: "CP-SL-PRAGMA",
    title: "Multiple or overly permissive Solidity pragma directives",
  },
  "solc-version": {
    category: "CP-SL-SOLC-VERSION",
    title: "Outdated or unsupported Solidity compiler version",
  },
  "unimplemented-functions": {
    category: "CP-SL-UNIMPLEMENTED-FUNCTIONS",
    title: "Contract does not implement all functions of its interface",
  },
  "redundant-statements": {
    category: "CP-SL-REDUNDANT-STATEMENTS",
    title: "Statement has no effect",
  },
  "controlled-array-length": {
    category: "CP-SL-CONTROLLED-ARRAY-LENGTH",
    title: "Direct write to a dynamic array's `.length`",
    severityOverride: "high",
  },
  "array-by-reference": {
    category: "CP-SL-ARRAY-BY-REFERENCE",
    title: "Storage array parameter passed by reference where a copy was likely intended",
  },
  "assert-state-change": {
    category: "CP-SL-ASSERT-STATE-CHANGE",
    title: "`assert()` condition contains a state-changing expression",
  },
  "codex": {
    category: "CP-SL-CODEX",
    title: "Codex (AI-assisted) detector finding",
  },
  "encode-packed-collision": {
    category: "CP-SL-ENCODE-PACKED-COLLISION",
    title: "`abi.encodePacked()` with multiple dynamic types risks a hash collision",
    severityOverride: "high",
  },
  "missing-zero-check": {
    category: "CP-SL-MISSING-ZERO-CHECK",
    title: "Address parameter never checked against the zero address",
  },
  "reentrancy-eth-modifier": {
    category: "CP-107",
    swcId: "SWC-107",
    title: "Reentrancy guard modifier ordering issue",
  },
  "unused-import": {
    category: "CP-SL-UNUSED-IMPORT",
    title: "Unused import statement",
  },
  "unused-modifier": {
    category: "CP-SL-UNUSED-MODIFIER",
    title: "Unused modifier",
  },
  "events-access": {
    category: "CP-SL-EVENTS-ACCESS",
    title: "Missing event emission for an access-control-sensitive state change",
  },
  "events-maths": {
    category: "CP-SL-EVENTS-MATHS",
    title: "Missing event emission for a critical arithmetic parameter change",
  },
  "function-init-state": {
    category: "CP-SL-FUNCTION-INIT-STATE",
    title: "State variable read before its initializer has run",
  },
  "missing-inheritance": {
    category: "CP-SL-MISSING-INHERITANCE",
    title: "Contract implements an interface without formally inheriting it",
  },
  "out-of-order-retryable": {
    category: "CP-SL-OUT-OF-ORDER-RETRYABLE",
    title: "Arbitrum retryable tickets created out of execution order",
  },
  "unchecked-lowlevel-storage": {
    category: "CP-104",
    swcId: "SWC-104",
    title: "Unchecked low-level call result used before validating success",
  },
  "deprecated-standards": {
    category: "CP-SL-DEPRECATED-STANDARDS",
    title: "Use of a deprecated Solidity/EVM construct (`throw`, `sha3`, `callcode`, `suicide`, `years`)",
  },
  "incorrect-exp": {
    category: "CP-SL-INCORRECT-EXP",
    title: "Exponentiation operator precedence likely misread by the author",
  },
  "variable-scope": {
    category: "CP-SL-VARIABLE-SCOPE",
    title: "Variable used outside the scope it was declared in (pre-0.5 quirk)",
  },
  "abiencoderv2-array": {
    category: "CP-SL-ABIENCODERV2-ARRAY",
    title: "ABIEncoderV2 array storage bug (affected solc versions)",
    severityOverride: "high",
  },
};

/**
 * Look up display metadata for a Slither detector by its `check` id
 * (e.g. `"reentrancy-eth"`).
 *
 * @internal
 */
export function getDetectorInfo(
  check: string,
): SlitherDetectorInfo | undefined {
  return DETECTOR_MAP[check.toLowerCase()];
}
