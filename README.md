# @deadvault/sdk

Decentralized credential store SDK for AI agents, servers & scripts. Read, write, and manage encrypted secrets stored on-chain via the [DeadVault](https://deadvault.xyz/) smart contract.

Part of the [DEADBOX](https://dead.box) ecosystem.

## Features

- **Read & write** encrypted vaults on-chain (Base, Ethereum, Arbitrum, Optimism)
- **AES-256-GCM** encryption with PBKDF2 key derivation (720k iterations)
- **TOTP generation** — RFC 6238 codes from vault entries
- **Zero dependencies** beyond `viem` as a peer dependency
- **Isomorphic** — works in Node.js 18+, Deno, Bun, Cloudflare Workers
- **ESM + CJS** dual output with full TypeScript types

## Install

```bash
npm install @deadvault/sdk viem
```

## Quick Start

```ts
import { DeadVault } from "@deadvault/sdk";

const vault = new DeadVault({ chain: "base" });

// Read & decrypt
const data = await vault.read({
  address: "0xYourAddress",
  password: "master-password",
});

// Find a specific entry
const key = vault.findEntry(data, { label: "OpenAI" });
console.log(key?.secret); // sk-...
```

## Constructor

```ts
const vault = new DeadVault(config);
```

| Option    | Type     | Default  | Description                                          |
|-----------|----------|----------|------------------------------------------------------|
| `chain`   | `string` | `"base"` | Chain name: `base`, `ethereum`, `arbitrum`, `optimism` |
| `chainId` | `number` | `8453`   | Chain ID (overrides `chain`)                         |
| `rpcUrl`  | `string \| string[]` | —        | Custom RPC URL(s) — pass an array for automatic fallback |

## Reading Secrets

```ts
const data = await vault.read({
  address: "0x...",
  password: "secret",
  walletSignature: "0x...", // required for v2 vaults
});
```

Returns `VaultData` with an `entries` array of `VaultEntry` objects.

## Finding Entries

```ts
// By label (case-insensitive substring)
vault.findEntry(data, { label: "OpenAI" });

// By category
vault.findEntry(data, { category: "API Keys" });

// By URL
vault.findEntry(data, { url: "github.com" });

// Custom predicate
vault.findEntry(data, (e) => e.secret.startsWith("sk-"));

// Find all matching
vault.findEntries(data, { type: "totp" });
```

## Writing Secrets

```ts
import { DeadVault, privateKeyToAccount } from "@deadvault/sdk";

const vault = new DeadVault({ chain: "base" });
const account = privateKeyToAccount("0xYourPrivateKey");

// Sign the KDF message (needed for v2 encryption)
const sig = await vault.signKdfMessage(account);

// Read existing vault
const data = await vault.read({
  address: account.address,
  password: "secret",
  walletSignature: sig,
});

// Add an entry
data.entries.push({
  id: crypto.randomUUID(),
  label: "New API Key",
  secret: "sk-abc123...",
  category: "API Keys",
  createdAt: Date.now(),
  updatedAt: Date.now(),
});

// Write back on-chain (v3 format, default 720k PBKDF2 iterations)
const result = await vault.write({
  data,
  password: "secret",
  account,
  walletSignature: sig,
  // iterations: 1_000_000, // optional: override PBKDF2 iteration count
});

console.log("TX:", result.hash);
console.log("Block:", result.blockNumber);
```

## TOTP Generation

```ts
const totpEntries = vault.findEntries(data, { type: "totp" });

for (const entry of totpEntries) {
  const code = await vault.generateTOTP(entry);
  const remaining = vault.getTOTPTimeRemaining();
  console.log(`${entry.label}: ${code} (${remaining}s remaining)`);
}
```

## Utilities

```ts
// Check write fee
const fee = await vault.getWriteFee();
console.log(fee.wei);  // 23255813953488n
console.log(fee.eth);  // "0.00002326"

// Check unlimited pass
const hasPass = await vault.hasPass("0x...");

// Check if vault exists
const exists = await vault.hasVault("0x...");
```

## Supported Chains

| Chain        | ID      | Contract                                       |
|--------------|---------|-------------------------------------------------|
| Base         | `8453`  | `0xF74C1131E11aF8dc10F25bAa977dD0B86d4A5C37`   |
| Ethereum     | `1`     | `0xF74C1131E11aF8dc10F25bAa977dD0B86d4A5C37`   |
| Arbitrum One | `42161` | `0x33939ede1A19A64EE755F1B5B3284A8E71F68484`   |
| Optimism     | `10`    | `0x33939ede1A19A64EE755F1B5B3284A8E71F68484`   |

## Encryption

All vault data is encrypted client-side before being stored on-chain.

- **v1**: `PBKDF2(password, salt, 600k, SHA-256)` → AES-256-GCM (legacy)
- **v2**: `PBKDF2(password + walletSignature, salt, 600k, SHA-256)` → AES-256-GCM (legacy)
- **v3**: `PBKDF2(password + walletSignature, salt, N, SHA-256)` → AES-256-GCM (current, iterations stored in header)

The SDK writes v3 (default 720k iterations) and can read all formats. You can customize iterations via the `iterations` option in `write()`.

## Low-Level Exports

For advanced use cases, the SDK also exports crypto and chain primitives:

```ts
import {
  encrypt,
  encryptV2,
  decrypt,
  detectVersionFromHex,
  KDF_SIGN_MESSAGE,
  generateTOTP,
  getTOTPTimeRemaining,
  isValidTOTPSecret,
  base32Decode,
  VAULT_ADDRESSES,
  CHAIN_NAME_TO_ID,
  privateKeyToAccount,  // re-exported from viem
} from "@deadvault/sdk";
```

## Security

- Encryption keys are derived locally — private keys and passwords never leave the client
- All on-chain data is encrypted ciphertext — the contract stores opaque blobs
- PBKDF2 with configurable iterations (default 720k, NIST SP 800-132 compliant)
- v2 encryption binds the key to the wallet via a signature, preventing password-only attacks

## Requirements

- Node.js ≥ 18 (Web Crypto API)
- `viem` ≥ 2.0.0 as peer dependency

## License

MIT — see [LICENSE](./LICENSE)
