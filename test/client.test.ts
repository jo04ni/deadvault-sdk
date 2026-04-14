import { describe, it, expect } from "vitest";
import { DeadVault } from "../src/client";
import { privateKeyToAccount } from "viem/accounts";
import type { VaultData, VaultEntry } from "../src/types";

// ── Constructor Tests ───────────────────────────────

describe("DeadVault constructor", () => {
  it("defaults to Base (8453)", () => {
    const vault = new DeadVault();
    expect(vault.getChainId()).toBe(8453);
    expect(vault.getVaultAddress()).toBe("0xF74C1131E11aF8dc10F25bAa977dD0B86d4A5C37");
  });

  it("accepts chain name", () => {
    const vault = new DeadVault({ chain: "ethereum" });
    expect(vault.getChainId()).toBe(1);
  });

  it("accepts chainId (overrides chain name)", () => {
    const vault = new DeadVault({ chain: "ethereum", chainId: 42161 });
    expect(vault.getChainId()).toBe(42161);
  });

  it("throws for unknown chain name", () => {
    // @ts-expect-error testing invalid input
    expect(() => new DeadVault({ chain: "solana" })).toThrow("Unknown chain");
  });

  it("throws for unsupported chainId", () => {
    expect(() => new DeadVault({ chainId: 99999 })).toThrow("No DeadVault contract");
  });

  it("does NOT accept base-sepolia", () => {
    // @ts-expect-error testing removed chain
    expect(() => new DeadVault({ chain: "base-sepolia" })).toThrow("Unknown chain");
  });
});

// ── findEntry / findEntries Tests ───────────────────

const mockData: VaultData = {
  version: 1,
  entries: [
    {
      id: "1",
      label: "OpenAI API Key",
      secret: "sk-abc123",
      category: "API Keys",
      url: "https://platform.openai.com",
      createdAt: 1000,
      updatedAt: 1000,
      type: "password",
    },
    {
      id: "2",
      label: "GitHub 2FA",
      secret: "JBSWY3DPEHPK3PXP",
      category: "2FA",
      url: "https://github.com",
      createdAt: 2000,
      updatedAt: 2000,
      type: "totp",
      totpConfig: { algorithm: "SHA1", digits: 6, period: 30 },
    },
    {
      id: "3",
      label: "AWS Access Key",
      secret: "AKIAIOSFODNN7EXAMPLE",
      category: "API Keys",
      createdAt: 3000,
      updatedAt: 3000,
    },
    {
      id: "4",
      label: "Discord Bot Token",
      secret: "MTk4...",
      category: "Tokens",
      url: "https://discord.com",
      createdAt: 4000,
      updatedAt: 4000,
      type: "password",
    },
  ],
};

describe("DeadVault.findEntry", () => {
  const vault = new DeadVault();

  it("finds by label (case-insensitive substring)", () => {
    const entry = vault.findEntry(mockData, { label: "openai" });
    expect(entry?.id).toBe("1");
  });

  it("finds by category (exact, case-insensitive)", () => {
    const entry = vault.findEntry(mockData, { category: "api keys" });
    expect(entry?.id).toBe("1");
  });

  it("finds by URL (case-insensitive substring)", () => {
    const entry = vault.findEntry(mockData, { url: "github.com" });
    expect(entry?.id).toBe("2");
  });

  it("finds by custom predicate", () => {
    const entry = vault.findEntry(mockData, (e) => e.secret.startsWith("sk-"));
    expect(entry?.id).toBe("1");
  });

  it("returns undefined when no match", () => {
    const entry = vault.findEntry(mockData, { label: "nonexistent" });
    expect(entry).toBeUndefined();
  });

  it("matches multiple criteria (AND)", () => {
    const entry = vault.findEntry(mockData, { label: "AWS", category: "API Keys" });
    expect(entry?.id).toBe("3");
  });
});

describe("DeadVault.findEntries", () => {
  const vault = new DeadVault();

  it("finds all entries by category", () => {
    const entries = vault.findEntries(mockData, { category: "API Keys" });
    expect(entries).toHaveLength(2);
    expect(entries.map((e) => e.id).sort()).toEqual(["1", "3"]);
  });

  it("finds by type 'totp'", () => {
    const entries = vault.findEntries(mockData, { type: "totp" });
    expect(entries).toHaveLength(1);
    expect(entries[0].id).toBe("2");
  });

  it("finds by type 'password' (includes entries without explicit type)", () => {
    const entries = vault.findEntries(mockData, { type: "password" });
    // entries 1 and 4 have type: "password", entry 3 has no type (defaults to "password")
    expect(entries).toHaveLength(3);
  });

  it("returns empty array when no matches", () => {
    const entries = vault.findEntries(mockData, { label: "zzz-no-match" });
    expect(entries).toHaveLength(0);
  });

  it("works with custom predicate", () => {
    const entries = vault.findEntries(mockData, (e) => (e.url ?? "").includes("com"));
    expect(entries.length).toBeGreaterThanOrEqual(3);
  });
});

// ── signKdfMessage Test ─────────────────────────────

describe("DeadVault.signKdfMessage", () => {
  const vault = new DeadVault();
  // Use a throwaway test key (no real funds)
  const testAccount = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

  it("signs the KDF message with an account and returns a 0x-prefixed signature", async () => {
    const sig = await vault.signKdfMessage(testAccount);
    expect(sig).toMatch(/^0x[0-9a-f]+$/i);
    expect(sig.length).toBeGreaterThan(100); // secp256k1 sigs are 130+ hex chars
  });

  it("same account always produces the same deterministic signature", async () => {
    const sig1 = await vault.signKdfMessage(testAccount);
    const sig2 = await vault.signKdfMessage(testAccount);
    expect(sig1).toBe(sig2);
  });
});
