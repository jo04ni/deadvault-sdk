/**
 * @deadvault/sdk — Decentralized credential store for AI agents & humans.
 *
 * @example
 * ```ts
 * import { DeadVault } from "@deadvault/sdk";
 *
 * const vault = new DeadVault({ chain: "base" });
 * const data = await vault.read({ address: "0x...", password: "secret" });
 * const entry = vault.findEntry(data, { label: "OpenAI" });
 * console.log(entry?.secret); // sk-...
 * ```
 */

// Main client
export { DeadVault } from "./client";

// Types
export type {
  VaultEntry,
  VaultData,
  DeadVaultConfig,
  ReadOptions,
  WriteOptions,
  WriteResult,
  FeeInfo,
} from "./types";

// Re-export viem's PrivateKeyAccount + privateKeyToAccount for convenience
export type { PrivateKeyAccount } from "viem/accounts";
export { privateKeyToAccount } from "viem/accounts";

// TOTP utilities
export {
  generateTOTP,
  getTOTPTimeRemaining,
  isValidTOTPSecret,
  base32Decode,
  type TOTPParams,
  type TOTPAlgorithm,
} from "./totp";

// Chain info
export { VAULT_ADDRESSES, CHAIN_NAME_TO_ID } from "./chains";

// Crypto (low-level — for advanced use)
export {
  encrypt,
  encryptV2,
  encryptV3,
  decrypt,
  detectVersionFromHex,
  KDF_SIGN_MESSAGE,
  DEFAULT_PBKDF2_ITERATIONS,
} from "./crypto";
