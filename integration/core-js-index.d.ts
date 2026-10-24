// Type declarations for the compiled WezWordnCore-TS. Patch 02 copies this
// file to `src/wezwordn/core-js/index.d.ts`, next to the compiled
// `index.js`, so the desktop main build resolves the import normally.
// Only the surface used by wezwordn.main.ts is declared; the implementation
// is the tested core build (see core/README.md for its test evidence).
import type { KeyObject } from "crypto";

export declare function encryptFile(source: string, destination: string, key: Buffer): void;
export declare function decryptFile(source: string, destination: string, key: Buffer): void;

export declare function totpRecordCurrentCode(
  record: {
    secretBase32: string;
    period: number;
    digits: number;
    algorithm: "SHA1" | "SHA256" | "SHA512";
  },
  dateMs?: number,
): string;

export declare function analyzeVaultHealth(
  items: Array<Record<string, unknown>>,
  nowMs?: number,
): Record<string, unknown>;

export interface GeneratedKeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}
export declare function generateX25519KeyPair(): GeneratedKeyPair;

export interface SharePackageLike {
  fingerprint: string;
  [key: string]: unknown;
}
export declare function createSharePackage(
  item: Record<string, unknown>,
  recipientPublicKey: KeyObject,
): SharePackageLike;
export declare function exportSharePackage(pkg: SharePackageLike): string;
export declare function importSharePackage(text: string): SharePackageLike;
export declare function openSharePackage(pkg: SharePackageLike, recipientPrivateKey: KeyObject): unknown;

export declare function createRecoveryPackage(
  vaultKey: Buffer,
  recipientPublicKey: KeyObject,
  ownerLabel: string,
): unknown;
export declare function recoverVaultKey(pkg: unknown, recipientPrivateKey: KeyObject): Buffer;
