import type { CallbackKind, CallbackStandard } from "./types";

/**
 * Registry of standard receiver/callback function signatures.
 *
 * `paramCount` is the arity a spec-compliant implementation must have; it is
 * used (together with the name) to tell a real hook implementation apart
 * from an unrelated function that merely shares a name.
 */
export interface ReceiverHookSignature {
  name: string;
  standard: CallbackStandard;
  kind: CallbackKind;
  paramCount: number;
  /** The 4-byte selector this hook must return per its governing standard (ERC-165 style acceptance), if any. */
  requiredReturnSelector?: string;
}

export const RECEIVER_HOOK_SIGNATURES: ReceiverHookSignature[] = [
  {
    name: "onERC721Received",
    standard: "ERC721",
    kind: "receiver-hook",
    paramCount: 4,
    requiredReturnSelector: "0x150b7a02",
  },
  {
    name: "onERC1155Received",
    standard: "ERC1155",
    kind: "receiver-hook",
    paramCount: 4,
    requiredReturnSelector: "0xf23a6e61",
  },
  {
    name: "onERC1155BatchReceived",
    standard: "ERC1155",
    kind: "batch-receiver-hook",
    paramCount: 5,
    requiredReturnSelector: "0xbc197c81",
  },
  { name: "tokensReceived", standard: "ERC777", kind: "receiver-hook", paramCount: 6 },
  { name: "tokensToSend", standard: "ERC777", kind: "sender-hook", paramCount: 6 },
  { name: "onFlashLoan", standard: "ERC3156", kind: "flash-callback", paramCount: 5 },
  // Aave-style third-party flash loan callback; not a ratified EIP but
  // widespread enough in production DeFi to warrant first-class coverage.
  { name: "executeOperation", standard: "CUSTOM", kind: "flash-callback", paramCount: 5 },
  // ERC-677 transferAndCall receiver hook.
  { name: "onTokenTransfer", standard: "CUSTOM", kind: "custom-hook", paramCount: 3 },
  // Legacy ERC-223-style token fallback, invoked by the token on every
  // transfer to a contract recipient.
  { name: "tokenFallback", standard: "CUSTOM", kind: "custom-hook", paramCount: 3 },
];

export const RECEIVER_HOOK_NAMES = new Set(RECEIVER_HOOK_SIGNATURES.map((h) => h.name));

export function getReceiverHookSignature(name: string): ReceiverHookSignature | undefined {
  return RECEIVER_HOOK_SIGNATURES.find((h) => h.name === name);
}

/**
 * Internal helper function names that well-known OpenZeppelin-style
 * implementations use to trigger a standard callback. Matching one of these
 * as the *name of the function currently being analyzed* is strong evidence
 * that its body performs the corresponding callback, even when the actual
 * low-level call is buried behind further internal indirection that static
 * analysis can't fully unwind (e.g. `abi.encodeWithSelector` composition).
 */
export interface CallbackTriggerHelper {
  functionNamePattern: RegExp;
  standard: CallbackStandard;
  kind: CallbackKind;
  detail: string;
}

export const CALLBACK_TRIGGER_HELPERS: CallbackTriggerHelper[] = [
  {
    functionNamePattern: /^_checkOnERC721Received$/,
    standard: "ERC721",
    kind: "receiver-hook",
    detail: "OpenZeppelin-style ERC-721 receiver-acceptance helper",
  },
  {
    functionNamePattern: /^_doSafeTransferAcceptanceCheck$/,
    standard: "ERC1155",
    kind: "receiver-hook",
    detail: "OpenZeppelin-style ERC-1155 single-transfer acceptance helper",
  },
  {
    functionNamePattern: /^_doSafeBatchTransferAcceptanceCheck$/,
    standard: "ERC1155",
    kind: "batch-receiver-hook",
    detail: "OpenZeppelin-style ERC-1155 batch-transfer acceptance helper",
  },
  {
    functionNamePattern: /^_callTokensReceived$/,
    standard: "ERC777",
    kind: "receiver-hook",
    detail: "OpenZeppelin-style ERC-777 tokensReceived dispatch helper",
  },
  {
    functionNamePattern: /^_callTokensToSend$/,
    standard: "ERC777",
    kind: "sender-hook",
    detail: "OpenZeppelin-style ERC-777 tokensToSend dispatch helper",
  },
];

/** ERC-165 interface IDs commonly checked/returned by receiver-hook contracts. */
export const KNOWN_ERC165_SELECTORS = new Set(
  RECEIVER_HOOK_SIGNATURES.map((h) => h.requiredReturnSelector).filter(
    (s): s is string => Boolean(s),
  ),
);

/**
 * Function-name heuristic for detecting bespoke, non-standard callback hooks
 * that a contract exposes for other contracts to call into (e.g.
 * `onVaultDeposit`, `notifyCallback`, `afterSwapHook`). Deliberately
 * conservative: requires an `on`-prefix or `Callback`/`Hook` suffix so
 * ordinary business-logic functions aren't misclassified.
 */
export const CUSTOM_HOOK_NAME_PATTERN = /^on[A-Z]\w*|.*(Callback|Hook)$/;

/** Names that indicate a state variable/function guards or moves sensitive value. */
export const SENSITIVE_STATE_NAME_PATTERN =
  /balance|debt|collateral|share|supply|credit|reserve|deposit|owed|allowance|stake/i;

export const TRUSTED_RECEIVER_NAME_PATTERN = /trusted|whitelist|allowlist|approved|known|registered/i;

export const REENTRANCY_GUARD_MODIFIER_PATTERN = /nonreentrant|reentrancyguard/i;
