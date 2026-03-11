import { describe, it, expect } from "vitest";
import {
  encrypt,
  encryptV2,
  decrypt,
  detectVersionFromHex,
  KDF_SIGN_MESSAGE,
} from "../src/crypto";

describe("crypto", () => {
  const password = "test-password-123";
  const walletSig = "0xfakesignatureforunittesting1234567890abcdef";
  const plaintext = '{"version":1,"entries":[{"id":"1","label":"Test","secret":"sk-123","createdAt":0,"updatedAt":0}]}';

  describe("v1 encrypt/decrypt", () => {
    it("round-trips plaintext through v1 encryption", async () => {
      const ciphertext = await encrypt(plaintext, password);
      expect(ciphertext).toMatch(/^0x[0-9a-f]+$/i);

      const result = await decrypt(ciphertext, password);
      expect(result).toBe(plaintext);
    });

    it("detects v1 from hex", async () => {
      const ciphertext = await encrypt("hello", password);
      expect(detectVersionFromHex(ciphertext)).toBe(1);
    });

    it("different encryptions produce different ciphertext (random salt/iv)", async () => {
      const a = await encrypt("hello", password);
      const b = await encrypt("hello", password);
      expect(a).not.toBe(b);
    });

    it("wrong password fails to decrypt", async () => {
      const ciphertext = await encrypt("secret", password);
      await expect(decrypt(ciphertext, "wrong-password")).rejects.toThrow();
    });
  });

  describe("v2 encrypt/decrypt", () => {
    it("round-trips plaintext through v2 encryption", async () => {
      const ciphertext = await encryptV2(plaintext, password, walletSig);
      expect(ciphertext).toMatch(/^0x[0-9a-f]+$/i);

      const result = await decrypt(ciphertext, password, walletSig);
      expect(result).toBe(plaintext);
    });

    it("detects v2 from hex (starts with dead0002)", async () => {
      const ciphertext = await encryptV2("hello", password, walletSig);
      expect(detectVersionFromHex(ciphertext)).toBe(2);
      // Verify magic header
      expect(ciphertext.slice(2, 10).toLowerCase()).toBe("dead0002");
    });

    it("v2 decryption without signature throws", async () => {
      const ciphertext = await encryptV2("hello", password, walletSig);
      await expect(decrypt(ciphertext, password)).rejects.toThrow(
        "Wallet signature required"
      );
    });

    it("v2 wrong signature fails to decrypt", async () => {
      const ciphertext = await encryptV2("hello", password, walletSig);
      await expect(decrypt(ciphertext, password, "0xwrongsig")).rejects.toThrow();
    });
  });

  describe("detectVersionFromHex", () => {
    it("returns 1 for arbitrary hex", () => {
      expect(detectVersionFromHex("0xabcdef")).toBe(1);
    });

    it("returns 2 for dead0002 prefix", () => {
      expect(detectVersionFromHex("0xdead00020000")).toBe(2);
    });

    it("handles without 0x prefix", () => {
      expect(detectVersionFromHex("dead00020000")).toBe(2);
    });
  });

  it("KDF_SIGN_MESSAGE is defined and non-empty", () => {
    expect(KDF_SIGN_MESSAGE).toBeTruthy();
    expect(KDF_SIGN_MESSAGE).toContain("DeadVault");
    expect(KDF_SIGN_MESSAGE).toContain("does NOT authorize");
  });
});
