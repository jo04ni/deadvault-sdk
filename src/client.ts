/**
 * DeadVault SDK — Main client class.
 *
 * Usage:
 *   const vault = new DeadVault({ chain: "base" });
 *   const data  = await vault.read({ address, password, walletSignature });
 *   const entry = vault.findEntry(data, { label: "OpenAI" });
 *   const code  = await vault.generateTOTP(entry);
 */

import type { PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type {
  DeadVaultConfig,
  ReadOptions,
  WriteOptions,
  WriteResult,
  FeeInfo,
  VaultData,
  VaultEntry,
} from "./types";
import { CHAIN_NAME_TO_ID } from "./chains";
import {
  makePublicClient,
  readVaultFromChain,
  readNativeFee,
  checkUnlimitedPass,
  hasVault as checkHasVault,
  writeVaultToChain,
  getVaultAddress,
  signMessage,
} from "./contract";
import { decrypt, encryptV2, detectVersionFromHex, KDF_SIGN_MESSAGE } from "./crypto";
import { generateTOTP as totpGenerate, getTOTPTimeRemaining, type TOTPParams } from "./totp";

const VAULT_DATA_VERSION = 1;

function parseVault(plaintext: string): VaultData {
  try {
    const parsed = JSON.parse(plaintext);
    if (parsed && typeof parsed === "object" && Array.isArray(parsed.entries)) {
      return parsed as VaultData;
    }
    return wrapLegacy(plaintext);
  } catch {
    return wrapLegacy(plaintext);
  }
}

function wrapLegacy(plaintext: string): VaultData {
  return {
    version: VAULT_DATA_VERSION,
    entries: [
      {
        id: crypto.randomUUID(),
        label: "Legacy Secret",
        secret: plaintext,
        category: "Imported",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      },
    ],
  };
}

function serializeVault(data: VaultData): string {
  return JSON.stringify(data);
}

export class DeadVault {
  private readonly chainId: number;
  private readonly rpcUrl?: string;
  private readonly vaultAddress: `0x${string}`;
  private client: PublicClient;

  constructor(config: DeadVaultConfig = {}) {
    if (config.chainId) {
      this.chainId = config.chainId;
    } else if (config.chain) {
      const id = CHAIN_NAME_TO_ID[config.chain];
      if (!id) throw new Error(`Unknown chain: "${config.chain}". Use: base, ethereum, arbitrum, optimism`);
      this.chainId = id;
    } else {
      this.chainId = 8453; // default: Base
    }

    this.rpcUrl = config.rpcUrl;
    this.vaultAddress = getVaultAddress(this.chainId);
    this.client = makePublicClient(this.chainId, this.rpcUrl);
  }

  /**
   * Read and decrypt a vault from the chain.
   * Returns the decrypted VaultData with all entries.
   */
  async read(options: ReadOptions): Promise<VaultData> {
    const { address, password, walletSignature } = options;

    const { hasSecret, ciphertext } = await readVaultFromChain(
      this.client,
      this.vaultAddress,
      address,
    );

    if (!hasSecret || !ciphertext) {
      return { version: VAULT_DATA_VERSION, entries: [] };
    }

    const version = detectVersionFromHex(ciphertext);
    if (version >= 2 && !walletSignature) {
      throw new Error("This vault uses v2 encryption. Provide walletSignature for decryption.");
    }

    const plaintext = await decrypt(ciphertext, password, walletSignature);
    return parseVault(plaintext);
  }

  /**
   * Encrypt and write vault data on-chain.
   * Requires a private key for the transaction + wallet signature for v2 encryption.
   */
  async write(options: WriteOptions): Promise<WriteResult> {
    const { data, password, privateKey, walletSignature } = options;

    const plaintext = serializeVault(data);
    const ciphertext = await encryptV2(plaintext, password, walletSignature);
    const payload = ciphertext as `0x${string}`;

    // Derive the wallet address from private key for the pass check
    const hex = (privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`) as `0x${string}`;
    const account = privateKeyToAccount(hex);

    const hasPass = await checkUnlimitedPass(
      this.client,
      this.vaultAddress,
      account.address,
    );

    let fee = 0n;
    if (!hasPass) {
      fee = await readNativeFee(this.client, this.vaultAddress);
    }

    return writeVaultToChain(
      this.chainId,
      this.vaultAddress,
      privateKey,
      payload,
      fee,
      this.rpcUrl,
    );
  }

  /**
   * Find an entry in vault data by label, category, URL, or custom predicate.
   */
  findEntry(
    data: VaultData,
    match: { label?: string; category?: string; url?: string } | ((entry: VaultEntry) => boolean),
  ): VaultEntry | undefined {
    if (typeof match === "function") {
      return data.entries.find(match);
    }
    return data.entries.find((e) => {
      if (match.label && !e.label.toLowerCase().includes(match.label.toLowerCase())) return false;
      if (match.category && e.category?.toLowerCase() !== match.category.toLowerCase()) return false;
      if (match.url && !e.url?.toLowerCase().includes(match.url.toLowerCase())) return false;
      return true;
    });
  }

  /**
   * Find all matching entries.
   */
  findEntries(
    data: VaultData,
    match: { label?: string; category?: string; url?: string; type?: "password" | "totp" } | ((entry: VaultEntry) => boolean),
  ): VaultEntry[] {
    if (typeof match === "function") {
      return data.entries.filter(match);
    }
    return data.entries.filter((e) => {
      if (match.label && !e.label.toLowerCase().includes(match.label.toLowerCase())) return false;
      if (match.category && e.category?.toLowerCase() !== match.category.toLowerCase()) return false;
      if (match.url && !e.url?.toLowerCase().includes(match.url.toLowerCase())) return false;
      if (match.type && (e.type || "password") !== match.type) return false;
      return true;
    });
  }

  /**
   * Generate a TOTP code from a vault entry.
   * The entry must have type "totp" and contain a base32 secret.
   */
  async generateTOTP(entry: VaultEntry): Promise<string> {
    const params: TOTPParams = {
      secret: entry.secret,
      algorithm: entry.totpConfig?.algorithm,
      digits: entry.totpConfig?.digits,
      period: entry.totpConfig?.period,
    };
    return totpGenerate(params);
  }

  /**
   * Get the remaining seconds in the current TOTP window.
   */
  getTOTPTimeRemaining(period = 30): number {
    return getTOTPTimeRemaining(period);
  }

  /**
   * Get the write fee for this chain.
   */
  async getWriteFee(): Promise<FeeInfo> {
    const wei = await readNativeFee(this.client, this.vaultAddress);
    const eth = (Number(wei) / 1e18).toFixed(8);
    return { wei, eth };
  }

  /**
   * Check if an address has an unlimited pass (no fee required).
   */
  async hasPass(address: string): Promise<boolean> {
    return checkUnlimitedPass(this.client, this.vaultAddress, address);
  }

  /**
   * Check if an address has a vault on-chain.
   */
  async hasVault(address: string): Promise<boolean> {
    return checkHasVault(this.client, this.vaultAddress, address);
  }

  /**
   * Sign the KDF message with a private key.
   * Returns the wallet signature needed for v2 read/write operations.
   */
  async signKdfMessage(privateKey: string): Promise<string> {
    return signMessage(privateKey, KDF_SIGN_MESSAGE);
  }

  /** Get the chain ID this client is configured for */
  getChainId(): number {
    return this.chainId;
  }

  /** Get the vault contract address */
  getVaultAddress(): `0x${string}` {
    return this.vaultAddress;
  }
}
