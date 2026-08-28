import type { Severity } from "@chainproof/core";

export interface RuleMeta {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  swcId?: string;
  category: "security" | "gas" | "best-practice";
}

/**
 * Static registry of all built-in ChainProof rules.
 * Kept in the server package so the REST endpoint and the CLI serve
 * the same metadata without importing AST-heavy rule modules.
 */
export const RULES: RuleMeta[] = [
  {
    id: "CP-107",
    swcId: "SWC-107",
    title: "Reentrancy vulnerability",
    severity: "critical",
    category: "security",
    description:
      "Detects functions that perform external calls (call/transfer/send) before " +
      "updating state variables, enabling re-entrant drain attacks (e.g. the DAO hack). " +
      "Apply the Checks-Effects-Interactions pattern or use ReentrancyGuard.",
  },
  {
    id: "CP-115",
    swcId: "SWC-115",
    title: "Use of tx.origin for authentication",
    severity: "high",
    category: "security",
    description:
      "tx.origin refers to the original EOA that started the transaction. " +
      "A malicious intermediate contract can exploit this to perform unauthorized actions. " +
      "Replace with msg.sender for authorization checks.",
  },
  {
    id: "CP-101",
    swcId: "SWC-101",
    title: "Integer overflow / underflow",
    severity: "high",
    category: "security",
    description:
      "Arithmetic operations on Solidity < 0.8.0 without SafeMath silently wrap on " +
      "overflow/underflow. Upgrade to ^0.8.0 or use OpenZeppelin SafeMath.",
  },
  {
    id: "CP-104",
    swcId: "SWC-104",
    title: "Unchecked call return value",
    severity: "medium",
    category: "security",
    description:
      ".call() and .send() return a boolean indicating success. " +
      "Ignoring this leaves the contract in an inconsistent state on failure. " +
      "Always check the return value or use transfer().",
  },
  {
    id: "CP-122",
    title: "Vault share-price inflation",
    severity: "high",
    category: "security",
    description:
      "Detects ERC-4626-style vaults that combine naive share-ratio math with live " +
      "token-balance accounting and no virtual offset, dead shares, or minimum-liquidity " +
      "initialization, exposing later depositors to first-depositor donation attacks.",
  },
  {
    id: "CP-CB-CEI",
    title: "Incomplete state update before standards-driven callback",
    severity: "critical",
    category: "security",
    description:
      "Detects ERC-721/1155/777 receiver/sender hooks and ERC-3156-style flash-loan callbacks fired " +
      "while contract state is still unfinalized (or, for flash callbacks, with no post-callback " +
      "repayment invariant check) — a Checks-Effects-Interactions violation invisible to raw " +
      "external-call detection.",
  },
  {
    id: "CP-CB-CROSSFN",
    title: "Cross-function reentrancy via callback",
    severity: "critical",
    category: "security",
    description:
      "Detects a sibling function reading or writing state that the callback-triggering function left " +
      "stale across a standards-driven callback, allowing an attacker to re-enter through that sibling.",
  },
  {
    id: "CP-CB-READONLY",
    title: "Read-only reentrancy via callback",
    severity: "high",
    category: "security",
    description:
      "Detects a `view` function exposing a value (e.g. a share/exchange price) that is only finalized " +
      "after a standards-driven callback fires, letting an integrator read a stale value mid-callback.",
  },
  {
    id: "CP-CB-SPOOF",
    title: "Callback spoofing",
    severity: "high",
    category: "security",
    description:
      "Detects a receiver-hook-shaped function (onERC721Received, tokensReceived, a project-defined " +
      "onXHook, ...) that mutates sensitive state without verifying msg.sender is the expected " +
      "token/vault/operator contract.",
  },
  {
    id: "CP-CB-BATCH",
    title: "Unbounded batch callback",
    severity: "medium",
    category: "security",
    description:
      "Detects a standards-driven callback fired once per loop iteration over a caller-supplied array " +
      "with no explicit length cap, multiplying the reentrancy surface and enabling gas-griefing DoS.",
  },
  {
    id: "GAS-LOOP-STORAGE",
    title: "Storage read inside loop",
    severity: "gas",
    category: "gas",
    description:
      "Each SLOAD costs 2100 gas on a cold access. " +
      "Cache storage variables in a local memory variable before entering the loop.",
  },
  {
    id: "GAS-PUBLIC-STRING",
    title: "Public string/bytes state variable",
    severity: "gas",
    category: "gas",
    description:
      "Public string/bytes variables auto-generate an external getter. " +
      "If only accessed externally, a private variable with a manual external getter saves deployment gas.",
  },
  {
    id: "GAS-LTE-LOOP",
    title: "Loop uses <= comparison",
    severity: "gas",
    category: "gas",
    description:
      "Replacing `i <= n` with `i < n + 1` avoids an ISZERO opcode per iteration, " +
      "saving ~3 gas per loop iteration.",
  },
  {
    id: "GAS-KECCAK-RUNTIME",
    title: "keccak256 called at runtime on constant input",
    severity: "gas",
    category: "gas",
    description:
      "If the input to keccak256() is a compile-time constant, precompute it as a " +
      "constant bytes32 to save ~30 gas per call.",
  },
  {
    id: "GAS-SMALL-UINT",
    title: "Small integer type in storage",
    severity: "gas",
    category: "gas",
    description:
      "The EVM operates on 32-byte words; uint8/uint16/int8/int16 only save gas when " +
      "tightly packed in adjacent storage slots. Verify packing or use uint256.",
  },
];
