import { describe, it, expect } from "vitest";
import {
  VAULT_ADDRESSES,
  RPC_URLS,
  CHAIN_NAME_TO_ID,
  CHAINS,
  DEAD_VAULT_ABI,
} from "../src/chains";
import { getVaultAddress } from "../src/contract";

describe("chains", () => {
  const SUPPORTED_IDS = [8453, 1, 42161, 10];

  it("has no Sepolia (84532) in any config", () => {
    expect(VAULT_ADDRESSES[84532]).toBeUndefined();
    expect(RPC_URLS[84532]).toBeUndefined();
    expect(CHAINS[84532]).toBeUndefined();
    expect(CHAIN_NAME_TO_ID["base-sepolia"]).toBeUndefined();
  });

  it("has all mainnet chains configured", () => {
    for (const id of SUPPORTED_IDS) {
      expect(VAULT_ADDRESSES[id]).toBeDefined();
      expect(RPC_URLS[id]).toBeDefined();
      expect(CHAINS[id]).toBeDefined();
    }
  });

  it("addresses are checksummed 0x-prefixed 42-char strings", () => {
    for (const id of SUPPORTED_IDS) {
      const addr = VAULT_ADDRESSES[id];
      expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
    }
  });

  it("RPC URLs are valid https URLs", () => {
    for (const id of SUPPORTED_IDS) {
      expect(RPC_URLS[id]).toMatch(/^https:\/\//);
    }
  });

  it("chain name mapping is complete", () => {
    expect(CHAIN_NAME_TO_ID["base"]).toBe(8453);
    expect(CHAIN_NAME_TO_ID["ethereum"]).toBe(1);
    expect(CHAIN_NAME_TO_ID["arbitrum"]).toBe(42161);
    expect(CHAIN_NAME_TO_ID["optimism"]).toBe(10);
  });

  it("ABI includes required functions", () => {
    const fns = DEAD_VAULT_ABI.map((e) => e.name);
    expect(fns).toContain("getSecret");
    expect(fns).toContain("hasSecret");
    expect(fns).toContain("storeSecret");
    expect(fns).toContain("getNativeWriteFee");
    expect(fns).toContain("hasUnlimitedPass");
    expect(fns).toContain("deleteSecret");
  });

  it("getVaultAddress returns correct address for Base", () => {
    expect(getVaultAddress(8453)).toBe("0xF74C1131E11aF8dc10F25bAa977dD0B86d4A5C37");
  });

  it("getVaultAddress throws for unsupported chain", () => {
    expect(() => getVaultAddress(99999)).toThrow("No DeadVault contract");
  });
});
