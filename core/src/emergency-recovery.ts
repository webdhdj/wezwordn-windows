/**
 * EmergencyRecovery — literal port of the Swift module of the same name
 * (WezWordnCore/Sources/EmergencyRecovery).
 *
 * Local emergency-recovery package.
 *
 * Scheme: an ephemeral Curve25519 (X25519) key pair is generated per
 * package. ephemeralPrivate x recipientPublic -> shared secret ->
 * HKDF-SHA256 (salt = random 32 bytes, info =
 * "WezWordn-EmergencyRecovery-v1") -> AES-256-GCM encryption of the vault
 * key. `ciphertext` in the package is ciphertext || 16-byte GCM tag
 * concatenated. Only the holder of the recipient private key can recover
 * the vault key; a wrong private key fails GCM authentication. There is no
 * server, no waiting period and no revocation in this local design — those
 * guarantees require a trusted service and are explicitly NOT claimed here.
 */
import {
  createCipheriv,
  createDecipheriv,
  diffieHellman,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import { canonicalJSON, iso8601NoFraction, parseISO8601 } from "./canonical-json.js";
import { generateX25519KeyPair, publicKeyFromRaw, rawPublicKey } from "./x25519-raw.js";

export interface RecoveryPackage {
  version: number;
  ephemeralPublicKey: Buffer;
  salt: Buffer;
  nonce: Buffer;
  /** ciphertext || tag */
  ciphertext: Buffer;
  createdAt: Date;
  ownerLabel: string;
}

export type EmergencyRecoveryErrorCode =
  | "unsupportedVersion"
  | "malformedPackage"
  | "decryptionFailed";

export class EmergencyRecoveryError extends Error {
  readonly code: EmergencyRecoveryErrorCode;
  readonly detail: string | number | null;
  constructor(code: EmergencyRecoveryErrorCode, detail: string | number | null = null) {
    super(detail === null ? code : `${code}: ${detail}`);
    this.code = code;
    this.detail = detail;
  }
}

export const EMERGENCY_RECOVERY_CURRENT_VERSION = 1;
const HKDF_INFO = Buffer.from("WezWordn-EmergencyRecovery-v1", "utf8");

function deriveKey(sharedSecret: Buffer, salt: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", sharedSecret, salt, HKDF_INFO, 32));
}

export function createRecoveryPackage(
  vaultKey: Buffer,
  recipientPublicKey: KeyObject,
  ownerLabel: string,
  createdAt: Date = new Date(),
): RecoveryPackage {
  const ephemeral = generateX25519KeyPair();
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientPublicKey });
  const salt = randomBytes(32);
  const key = deriveKey(shared, salt);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const sealed = Buffer.concat([cipher.update(vaultKey), cipher.final()]);
  const combined = Buffer.concat([sealed, cipher.getAuthTag()]);
  return {
    version: EMERGENCY_RECOVERY_CURRENT_VERSION,
    ephemeralPublicKey: ephemeral.publicKeyRaw,
    salt,
    nonce,
    ciphertext: combined,
    createdAt,
    ownerLabel,
  };
}

export function recoverVaultKey(pkg: RecoveryPackage, recipientPrivateKey: KeyObject): Buffer {
  if (pkg.version !== EMERGENCY_RECOVERY_CURRENT_VERSION) {
    throw new EmergencyRecoveryError("unsupportedVersion", pkg.version);
  }
  if (!(pkg.ciphertext.length > 16) || pkg.nonce.length !== 12) {
    throw new EmergencyRecoveryError("malformedPackage", "ciphertext/nonce length");
  }
  let ephemeralPublic: KeyObject;
  try {
    ephemeralPublic = publicKeyFromRaw(pkg.ephemeralPublicKey);
  } catch {
    throw new EmergencyRecoveryError("malformedPackage", "ephemeral public key");
  }
  const shared = diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeralPublic });
  const key = deriveKey(shared, pkg.salt);
  const cipher = pkg.ciphertext.subarray(0, pkg.ciphertext.length - 16);
  const tag = pkg.ciphertext.subarray(pkg.ciphertext.length - 16);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, pkg.nonce);
    decipher.setAuthTag(Buffer.from(tag));
    return Buffer.concat([decipher.update(Buffer.from(cipher)), decipher.final()]);
  } catch {
    throw new EmergencyRecoveryError("decryptionFailed");
  }
}

/** Package (de)serialisation. The Swift module defines only the Codable
 * struct (no export helper); this port uses the same canonical encoding
 * the project uses for .wezshare files — sorted-keys JSON, Data as base64,
 * dates as ISO-8601 — so an iOS-produced package and a Windows-produced
 * package have identical bytes for identical fields. */
export function recoveryPackageToJSON(pkg: RecoveryPackage): Record<string, unknown> {
  return {
    version: pkg.version,
    ephemeralPublicKey: pkg.ephemeralPublicKey,
    salt: pkg.salt,
    nonce: pkg.nonce,
    ciphertext: pkg.ciphertext,
    createdAt: iso8601NoFraction(pkg.createdAt),
    ownerLabel: pkg.ownerLabel,
  };
}

export function recoveryPackageFromJSON(data: Record<string, unknown>): RecoveryPackage {
  return {
    version: data.version as number,
    ephemeralPublicKey: Buffer.from(data.ephemeralPublicKey as string, "base64"),
    salt: Buffer.from(data.salt as string, "base64"),
    nonce: Buffer.from(data.nonce as string, "base64"),
    ciphertext: Buffer.from(data.ciphertext as string, "base64"),
    createdAt: parseISO8601(data.createdAt as string),
    ownerLabel: data.ownerLabel as string,
  };
}

export function exportRecoveryPackage(pkg: RecoveryPackage): string {
  return canonicalJSON(recoveryPackageToJSON(pkg));
}

export function importRecoveryPackage(text: string): RecoveryPackage {
  return recoveryPackageFromJSON(JSON.parse(text) as Record<string, unknown>);
}

export { rawPublicKey };
