/**
 * @deadvault/sdk — Type definitions.
 * @module
 */

// ── Vault Data Types ────────────────────────────────

/** A single vault entry (password, API key, TOTP secret, etc.) */
export interface VaultEntry {
  /** Unique identifier (UUID v4) */
  id: string;
  /** Human‑readable label (e.g. "GitHub", "OpenAI API") */
  label: string;
  /** The secret value (password, API key, or Base32 TOTP seed) */
  secret: string;
  /** Optional URL for autofill matching */
  url?: string;
  /** Category tag (e.g. "API Keys", "Passwords") */
  category?: string;
  /** Unix timestamp in milliseconds when created */
  createdAt: number;
  /** Unix timestamp in milliseconds when last modified */
  updatedAt: number;
  /** Entry type — defaults to `"password"` for backward compatibility */
  type?: "password" | "totp";
  /** TOTP‑specific configuration (only relevant when `type === "totp"`) */
  totpConfig?: {
    /** HMAC algorithm — defaults to `"SHA1"` (standard) */
    algorithm?: "SHA1" | "SHA256";
    /** Code length — defaults to `6` */
    digits?: 6 | 8;
    /** Time step in seconds — defaults to `30` */
    period?: number;
  };
}

/** Decrypted vault payload */
export interface VaultData {
  /** Data format version (currently `1`) */
  version: number;
  /** All vault entries */
  entries: VaultEntry[];
}

// ── SDK Configuration ───────────────────────────────

/** Supported chain name shorthands */
export type ChainName = "base" | "ethereum" | "arbitrum" | "optimism";

/** Constructor options for {@link DeadVault} */
export interface DeadVaultConfig {
  /** Chain name shorthand (default: `"base"`) */
  chain?: ChainName;
  /** Numeric chain ID — takes precedence over `chain` */
  chainId?: number;
  /** Custom JSON‑RPC endpoint (overrides built‑in defaults) */
  rpcUrl?: string;
}

// ── Read / Write Options ────────────────────────────

/** Options for {@link DeadVault.read} */
export interface ReadOptions {
  /** Wallet address that owns the vault (`0x…`) */
  address: string;
  /** Master password used during encryption */
  password: string;
  /** Wallet signature needed for v2‑encrypted vaults */
  walletSignature?: string;
}

/** Options for {@link DeadVault.write} */
export interface WriteOptions {
  /** Vault data to encrypt and store on‑chain */
  data: VaultData;
  /** Master password for encryption */
  password: string;
  /** Hex‑encoded private key for signing the transaction (`0x…`) */
  privateKey: string;
  /** Wallet signature for v2 encryption (created via {@link DeadVault.signKdfMessage}) */
  walletSignature: string;
}

// ── Result Types ────────────────────────────────────

/** Result returned by {@link DeadVault.write} */
export interface WriteResult {
  /** Transaction hash (`0x…`) */
  hash: string;
  /** Block number the transaction was mined in */
  blockNumber: bigint;
}

/** Fee information returned by {@link DeadVault.getWriteFee} */
export interface FeeInfo {
  /** Fee amount in wei */
  wei: bigint;
  /** Fee formatted as a decimal ETH string */
  eth: string;
}

// ── Search / Filter ─────────────────────────────────

/** Filter criteria for {@link DeadVault.findEntry} and {@link DeadVault.findEntries} */
export interface EntryFilter {
  /** Case‑insensitive substring match against the label */
  label?: string;
  /** Exact (case‑insensitive) category match */
  category?: string;
  /** Case‑insensitive substring match against the URL */
  url?: string;
  /** Filter by entry type (`"password"` or `"totp"`) */
  type?: "password" | "totp";
}
