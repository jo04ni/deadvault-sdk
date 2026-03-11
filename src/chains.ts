/**
 * Chain configuration — contract addresses, RPCs, chain objects, and ABI.
 * @module
 */
import { base, mainnet, arbitrum, optimism, type Chain } from "viem/chains";

// ── Contract Addresses ──────────────────────────────

/** DeadVault proxy addresses per chain ID */
export const VAULT_ADDRESSES: Record<number, `0x${string}`> = {
  8453:  "0xF74C1131E11aF8dc10F25bAa977dD0B86d4A5C37", // Base
  1:     "0xF74C1131E11aF8dc10F25bAa977dD0B86d4A5C37", // Ethereum
  42161: "0x33939ede1A19A64EE755F1B5B3284A8E71F68484", // Arbitrum One
  10:    "0x33939ede1A19A64EE755F1B5B3284A8E71F68484", // Optimism
} as const;

/** Default public RPC endpoints (rate‑limited, for light use) */
export const RPC_URLS: Record<number, string> = {
  8453:  "https://mainnet.base.org",
  1:     "https://ethereum-rpc.publicnode.com",
  42161: "https://arbitrum-one-rpc.publicnode.com",
  10:    "https://optimism-rpc.publicnode.com",
} as const;

/** Human‑friendly chain name → chain ID lookup */
export const CHAIN_NAME_TO_ID: Record<string, number> = {
  "base":         8453,
  "ethereum":     1,
  "arbitrum":     42161,
  "optimism":     10,
} as const;

/** viem Chain objects keyed by chain ID */
export const CHAINS: Record<number, Chain> = {
  8453:  base,
  1:     mainnet,
  42161: arbitrum,
  10:    optimism,
};

// ── ABI ─────────────────────────────────────────────

/** Minimal DeadVault ABI (only the functions the SDK uses) */
export const DEAD_VAULT_ABI = [
  {
    type: "function",
    name: "deleteSecret",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getNativeWriteFee",
    inputs: [],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getSecret",
    inputs: [{ name: "agent", type: "address", internalType: "address" }],
    outputs: [{ name: "", type: "bytes", internalType: "bytes" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "hasSecret",
    inputs: [{ name: "agent", type: "address", internalType: "address" }],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "hasUnlimitedPass",
    inputs: [{ name: "agent", type: "address", internalType: "address" }],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "storeSecret",
    inputs: [{ name: "payload", type: "bytes", internalType: "bytes" }],
    outputs: [],
    stateMutability: "payable",
  },
] as const;
