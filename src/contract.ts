/**
 * On-chain contract interactions using viem.
 * No browser dependencies — works in Node.js, Deno, Bun, Workers.
 */
import {
  createPublicClient,
  createWalletClient,
  http,
  encodeFunctionData,
  type PublicClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { VAULT_ADDRESSES, RPC_URLS, CHAINS, DEAD_VAULT_ABI } from "./chains";

/** Create a public client for the given chain + optional custom RPC */
export function makePublicClient(chainId: number, rpcUrl?: string): PublicClient {
  const chain = CHAINS[chainId];
  if (!chain) throw new Error(`Unsupported chain ID: ${chainId}`);
  const transport = http(rpcUrl || RPC_URLS[chainId]);
  return createPublicClient({ chain, transport });
}

/** Read the on-chain encrypted vault blob for an address */
export async function readVaultFromChain(
  client: PublicClient,
  vaultAddress: `0x${string}`,
  userAddress: string,
): Promise<{ hasSecret: boolean; ciphertext: string | null }> {
  const addr = userAddress as `0x${string}`;

  const [hasSecret, rawBytes] = await Promise.all([
    client.readContract({
      address: vaultAddress,
      abi: DEAD_VAULT_ABI,
      functionName: "hasSecret",
      args: [addr],
    }),
    client.readContract({
      address: vaultAddress,
      abi: DEAD_VAULT_ABI,
      functionName: "getSecret",
      args: [addr],
    }),
  ]);

  let ciphertext: string | null = null;
  if (hasSecret && rawBytes) {
    ciphertext =
      typeof rawBytes === "string"
        ? rawBytes
        : "0x" +
          Array.from(rawBytes as Uint8Array)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
  }

  return { hasSecret: hasSecret as boolean, ciphertext };
}

/** Read the native write fee */
export async function readNativeFee(
  client: PublicClient,
  vaultAddress: `0x${string}`,
): Promise<bigint> {
  return (await client.readContract({
    address: vaultAddress,
    abi: DEAD_VAULT_ABI,
    functionName: "getNativeWriteFee",
  })) as bigint;
}

/** Check if an address has an unlimited pass */
export async function checkUnlimitedPass(
  client: PublicClient,
  vaultAddress: `0x${string}`,
  userAddress: string,
): Promise<boolean> {
  return (await client.readContract({
    address: vaultAddress,
    abi: DEAD_VAULT_ABI,
    functionName: "hasUnlimitedPass",
    args: [userAddress as `0x${string}`],
  })) as boolean;
}

/** Check if an address has a vault on-chain */
export async function hasVault(
  client: PublicClient,
  vaultAddress: `0x${string}`,
  userAddress: string,
): Promise<boolean> {
  return (await client.readContract({
    address: vaultAddress,
    abi: DEAD_VAULT_ABI,
    functionName: "hasSecret",
    args: [userAddress as `0x${string}`],
  })) as boolean;
}

/** Write encrypted vault data on-chain */
export async function writeVaultToChain(
  chainId: number,
  vaultAddress: `0x${string}`,
  privateKey: string,
  payload: `0x${string}`,
  value: bigint,
  rpcUrl?: string,
): Promise<{ hash: string; blockNumber: bigint }> {
  const chain = CHAINS[chainId];
  if (!chain) throw new Error(`Unsupported chain ID: ${chainId}`);

  const hex = privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`;
  const account = privateKeyToAccount(hex as `0x${string}`);

  const walletClient = createWalletClient({
    account,
    chain,
    transport: http(rpcUrl || RPC_URLS[chainId]),
  });

  const calldata = encodeFunctionData({
    abi: DEAD_VAULT_ABI,
    functionName: "storeSecret",
    args: [payload],
  });

  const hash = await walletClient.sendTransaction({
    account,
    chain,
    to: vaultAddress,
    data: calldata,
    value,
  });

  const publicClient = makePublicClient(chainId, rpcUrl);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });

  return { hash, blockNumber: receipt.blockNumber };
}

/** Get the vault contract address for a chain */
export function getVaultAddress(chainId: number): `0x${string}` {
  const addr = VAULT_ADDRESSES[chainId];
  if (!addr) throw new Error(`No DeadVault contract on chain ${chainId}`);
  return addr;
}

/** Sign a message with a private key (for v2 encryption KDF) */
export async function signMessage(privateKey: string, message: string): Promise<string> {
  const hex = (privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`) as `0x${string}`;
  const account = privateKeyToAccount(hex);
  return account.signMessage({ message });
}
