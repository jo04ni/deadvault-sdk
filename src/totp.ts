/**
 * TOTP (Time-Based One-Time Password) Generator — RFC 6238
 * Uses Web Crypto API for HMAC. No external dependencies.
 */

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Decode a Base32-encoded string */
export function base32Decode(input: string): Uint8Array {
  const cleaned = input.replace(/[\s=-]/g, "").toUpperCase();
  const out: number[] = [];
  let bits = 0;
  let value = 0;

  for (const char of cleaned) {
    const idx = BASE32_CHARS.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }

  return new Uint8Array(out);
}

export type TOTPAlgorithm = "SHA1" | "SHA256";

export interface TOTPParams {
  secret: string;         // Base32-encoded secret
  algorithm?: TOTPAlgorithm;
  digits?: 6 | 8;
  period?: number;        // seconds (default 30)
}

/** Generate the current TOTP code */
export async function generateTOTP(params: TOTPParams): Promise<string> {
  const { secret, algorithm = "SHA1", digits = 6, period = 30 } = params;
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / period);
  return generateHOTP(secret, counter, algorithm, digits);
}

/** Get remaining seconds in the current TOTP window */
export function getTOTPTimeRemaining(period = 30): number {
  const now = Math.floor(Date.now() / 1000);
  return period - (now % period);
}

async function generateHOTP(
  base32Secret: string,
  counter: number,
  algorithm: TOTPAlgorithm,
  digits: number,
): Promise<string> {
  const key = base32Decode(base32Secret);

  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(4, counter, false);

  const algo = algorithm === "SHA256" ? "SHA-256" : "SHA-1";
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key.buffer as ArrayBuffer,
    { name: "HMAC", hash: algo },
    false,
    ["sign"],
  );
  const hmac = await crypto.subtle.sign("HMAC", cryptoKey, counterBuf);
  const hmacBytes = new Uint8Array(hmac);

  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const code =
    ((hmacBytes[offset] & 0x7f) << 24) |
    ((hmacBytes[offset + 1] & 0xff) << 16) |
    ((hmacBytes[offset + 2] & 0xff) << 8) |
    (hmacBytes[offset + 3] & 0xff);

  const otp = code % 10 ** digits;
  return otp.toString().padStart(digits, "0");
}

/** Validate a base32 TOTP secret — checks it decodes to >= 10 bytes */
export function isValidTOTPSecret(secret: string): boolean {
  try {
    const decoded = base32Decode(secret);
    return decoded.length >= 10;
  } catch {
    return false;
  }
}
