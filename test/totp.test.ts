import { describe, it, expect } from "vitest";
import {
  base32Decode,
  generateTOTP,
  getTOTPTimeRemaining,
  isValidTOTPSecret,
} from "../src/totp";

describe("totp", () => {
  // RFC 6238 test vector secret (Base32 of "12345678901234567890")
  const TEST_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  describe("base32Decode", () => {
    it("decodes a known Base32 string", () => {
      // "JBSWY3DP" = "Hello" in Base32
      const result = base32Decode("JBSWY3DP");
      const text = new TextDecoder().decode(result);
      expect(text).toBe("Hello");
    });

    it("handles lowercase input", () => {
      const result = base32Decode("jbswy3dp");
      const text = new TextDecoder().decode(result);
      expect(text).toBe("Hello");
    });

    it("strips spaces and padding", () => {
      const a = base32Decode("JBSW Y3DP");
      const b = base32Decode("JBSWY3DP====");
      expect(a).toEqual(b);
    });

    it("returns empty array for empty input", () => {
      const result = base32Decode("");
      expect(result.length).toBe(0);
    });
  });

  describe("generateTOTP", () => {
    it("produces a 6-digit code", async () => {
      const code = await generateTOTP({ secret: TEST_SECRET });
      expect(code).toMatch(/^\d{6}$/);
    });

    it("produces an 8-digit code when requested", async () => {
      const code = await generateTOTP({ secret: TEST_SECRET, digits: 8 });
      expect(code).toMatch(/^\d{8}$/);
    });

    it("produces consistent results for the same time window", async () => {
      const a = await generateTOTP({ secret: TEST_SECRET, period: 30 });
      const b = await generateTOTP({ secret: TEST_SECRET, period: 30 });
      expect(a).toBe(b);
    });

    it("works with SHA256 algorithm", async () => {
      const code = await generateTOTP({ secret: TEST_SECRET, algorithm: "SHA256" });
      expect(code).toMatch(/^\d{6}$/);
    });
  });

  describe("getTOTPTimeRemaining", () => {
    it("returns a number between 1 and period", () => {
      const remaining = getTOTPTimeRemaining(30);
      expect(remaining).toBeGreaterThanOrEqual(1);
      expect(remaining).toBeLessThanOrEqual(30);
    });

    it("works with custom period", () => {
      const remaining = getTOTPTimeRemaining(60);
      expect(remaining).toBeGreaterThanOrEqual(1);
      expect(remaining).toBeLessThanOrEqual(60);
    });
  });

  describe("isValidTOTPSecret", () => {
    it("returns true for a valid secret (>= 10 bytes)", () => {
      expect(isValidTOTPSecret(TEST_SECRET)).toBe(true);
    });

    it("returns false for a too-short secret", () => {
      expect(isValidTOTPSecret("JBSWY")).toBe(false);
    });

    it("returns false for empty string", () => {
      expect(isValidTOTPSecret("")).toBe(false);
    });
  });
});
