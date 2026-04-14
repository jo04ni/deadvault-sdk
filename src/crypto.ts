/**
 * AES-256-GCM encryption/decryption using Web Crypto API.
 * Compatible with Node.js 18+, Deno, Bun, and Cloudflare Workers.
 *
 * v1: PBKDF2(password, salt, 600k, SHA-256) → AES-256-GCM
 *     Format: salt(16) || iv(12) || ciphertext
 *
 * v2: PBKDF2(password + walletSignature, salt, 600k, SHA-256) → AES-256-GCM
 *     Format: 0xDEAD00 || 0x02 || salt(16) || iv(12) || ciphertext
 *
 * v3: PBKDF2(password || 0x00 || walletSignature, salt, N, SHA-256) → AES-256-GCM
 *     Format: 0xDEAD00 || 0x03 || iterations(4 bytes, big-endian) || salt(16) || iv(12) || ciphertext
 *     Null-byte domain separation prevents length confusion attacks.
 *     Iterations are user-configurable (default 720k).
 */

const PBKDF2_ITERATIONS_V1V2 = 600_000;
export const DEFAULT_PBKDF2_ITERATIONS = 720_000;

const MAGIC = new Uint8Array([0xde, 0xad, 0x00]);
const VERSION_V2 = 0x02;
const VERSION_V3 = 0x03;
const HEADER_V2 = new Uint8Array([...MAGIC, VERSION_V2]);
const HEADER_V3 = new Uint8Array([...MAGIC, VERSION_V3]);

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

async function deriveKey(input: string | Uint8Array, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const raw = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const keyMaterial = await crypto.subtle.importKey("raw", raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength) as ArrayBuffer, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Build domain-separated KDF input: password || 0x00 || walletSignature */
function buildV3Input(password: string, walletSignature: string): Uint8Array {
  const enc = new TextEncoder();
  const pw = enc.encode(password);
  const sig = enc.encode(walletSignature);
  const combined = new Uint8Array(pw.length + 1 + sig.length);
  combined.set(pw, 0);
  combined[pw.length] = 0x00;
  combined.set(sig, pw.length + 1);
  return combined;
}

/** Encrypt plaintext with password only (v1 format, legacy) */
export async function encrypt(plaintext: string, password: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS_V1V2);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext)));
  const packed = new Uint8Array(salt.length + iv.length + ct.length);
  packed.set(salt, 0);
  packed.set(iv, salt.length);
  packed.set(ct, salt.length + iv.length);
  return toHex(packed);
}

/** Encrypt plaintext with password + wallet signature (v2 format, legacy — use encryptV3 for new vaults) */
export async function encryptV2(plaintext: string, password: string, walletSignature: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password + walletSignature, salt, PBKDF2_ITERATIONS_V1V2);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext)));
  const packed = new Uint8Array(HEADER_V2.length + salt.length + iv.length + ct.length);
  packed.set(HEADER_V2, 0);
  packed.set(salt, HEADER_V2.length);
  packed.set(iv, HEADER_V2.length + salt.length);
  packed.set(ct, HEADER_V2.length + salt.length + iv.length);
  return toHex(packed);
}

/** Encrypt plaintext with password + wallet signature (v3 format with configurable iterations) */
export async function encryptV3(
  plaintext: string,
  password: string,
  walletSignature: string,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(buildV3Input(password, walletSignature), salt, iterations);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext)));

  // iterations as 4 bytes big-endian
  const iterBytes = new Uint8Array(4);
  new DataView(iterBytes.buffer).setUint32(0, iterations, false);

  const packed = new Uint8Array(HEADER_V3.length + iterBytes.length + salt.length + iv.length + ct.length);
  let offset = 0;
  packed.set(HEADER_V3, offset); offset += HEADER_V3.length;
  packed.set(iterBytes, offset);  offset += iterBytes.length;
  packed.set(salt, offset);       offset += salt.length;
  packed.set(iv, offset);         offset += iv.length;
  packed.set(ct, offset);
  return toHex(packed);
}

/** Decrypt a hex ciphertext. Auto-detects v1/v2/v3 format. */
export async function decrypt(hexCiphertext: string, password: string, walletSignature?: string): Promise<string> {
  const packed = fromHex(hexCiphertext);
  const { version, offset: versionOffset } = detectVersion(packed);

  let salt: Uint8Array;
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  let key: CryptoKey;

  if (version === 1) {
    salt = packed.slice(versionOffset, versionOffset + 16);
    iv = packed.slice(versionOffset + 16, versionOffset + 28);
    ciphertext = packed.slice(versionOffset + 28);
    key = await deriveKey(password, salt, PBKDF2_ITERATIONS_V1V2);
  } else if (version === 2) {
    if (!walletSignature) throw new Error("Wallet signature required for v2 decryption.");
    salt = packed.slice(versionOffset, versionOffset + 16);
    iv = packed.slice(versionOffset + 16, versionOffset + 28);
    ciphertext = packed.slice(versionOffset + 28);
    key = await deriveKey(password + walletSignature, salt, PBKDF2_ITERATIONS_V1V2);
  } else if (version === 3) {
    if (!walletSignature) throw new Error("Wallet signature required for v3 decryption.");
    const iterations = new DataView(packed.buffer, packed.byteOffset + versionOffset, 4).getUint32(0, false);
    const dataOffset = versionOffset + 4;
    salt = packed.slice(dataOffset, dataOffset + 16);
    iv = packed.slice(dataOffset + 16, dataOffset + 28);
    ciphertext = packed.slice(dataOffset + 28);
    key = await deriveKey(buildV3Input(password, walletSignature), salt, iterations);
  } else {
    throw new Error(`Unknown encryption version: ${version}`);
  }

  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer },
    key,
    ciphertext.buffer.slice(ciphertext.byteOffset, ciphertext.byteOffset + ciphertext.byteLength) as ArrayBuffer,
  );
  return new TextDecoder().decode(plainBuffer);
}
