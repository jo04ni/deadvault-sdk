/**
 * AES-256-GCM encryption/decryption using Web Crypto API.
 * Compatible with Node.js 18+, Deno, Bun, and Cloudflare Workers.
 *
 * v1: PBKDF2(password, salt, 600k, SHA-256) → AES-256-GCM
 *     Format: salt(16) || iv(12) || ciphertext
 *
 * v2: PBKDF2(password + walletSignature, salt, 600k, SHA-256) → AES-256-GCM
 *     Format: 0xDEAD00 || 0x02 || salt(16) || iv(12) || ciphertext
 */

const PBKDF2_ITERATIONS = 600_000;
const MAGIC = new Uint8Array([0xde, 0xad, 0x00]);
const VERSION_V2 = 0x02;
const HEADER_V2 = new Uint8Array([...MAGIC, VERSION_V2]);

export const KDF_SIGN_MESSAGE =
  "DeadVault Encryption Key Derivation\n\n" +
  "Sign this message to derive your personal encryption key.\n" +
  "This signature is used locally and does NOT authorize any transaction or transfer.";

function detectVersion(packed: Uint8Array): { version: number; offset: number } {
  if (packed.length >= 4 && packed[0] === 0xde && packed[1] === 0xad && packed[2] === 0x00) {
    return { version: packed[3], offset: 4 };
  }
  return { version: 1, offset: 0 };
}

export function detectVersionFromHex(hexCiphertext: string): number {
  const hex = hexCiphertext.startsWith("0x") ? hexCiphertext.slice(2) : hexCiphertext;
  if (hex.length >= 8 && hex.slice(0, 6).toLowerCase() === "dead00") {
    return parseInt(hex.slice(6, 8), 16);
  }
  return 1;
}

function toHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length === 0) throw new Error("Cannot decode empty hex string");
  const pairs = clean.match(/.{1,2}/g);
  if (!pairs) throw new Error("Invalid hex string");
  return new Uint8Array(pairs.map((byte) => parseInt(byte, 16)));
}

async function deriveKeyV1(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength) as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function deriveKeyV2(password: string, walletSignature: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const combined = enc.encode(password + walletSignature);
  const keyMaterial = await crypto.subtle.importKey("raw", combined, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength) as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Encrypt plaintext with password only (v1 format) */
export async function encrypt(plaintext: string, password: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyV1(password, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext)));
  const packed = new Uint8Array(salt.length + iv.length + ct.length);
  packed.set(salt, 0);
  packed.set(iv, salt.length);
  packed.set(ct, salt.length + iv.length);
  return toHex(packed);
}

/** Encrypt plaintext with password + wallet signature (v2 format) */
export async function encryptV2(plaintext: string, password: string, walletSignature: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyV2(password, walletSignature, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext)));
  const packed = new Uint8Array(HEADER_V2.length + salt.length + iv.length + ct.length);
  packed.set(HEADER_V2, 0);
  packed.set(salt, HEADER_V2.length);
  packed.set(iv, HEADER_V2.length + salt.length);
  packed.set(ct, HEADER_V2.length + salt.length + iv.length);
  return toHex(packed);
}

/** Decrypt a hex ciphertext. Auto-detects v1/v2 format. */
export async function decrypt(hexCiphertext: string, password: string, walletSignature?: string): Promise<string> {
  const packed = fromHex(hexCiphertext);
  const { version, offset } = detectVersion(packed);
  const salt = packed.slice(offset, offset + 16);
  const iv = packed.slice(offset + 16, offset + 28);
  const ciphertext = packed.slice(offset + 28);

  let key: CryptoKey;
  if (version === 1) {
    key = await deriveKeyV1(password, salt);
  } else if (version === 2) {
    if (!walletSignature) throw new Error("Wallet signature required for v2 decryption.");
    key = await deriveKeyV2(password, walletSignature, salt);
  } else {
    throw new Error(`Unknown encryption version: ${version}`);
  }

  const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plainBuffer);
}
