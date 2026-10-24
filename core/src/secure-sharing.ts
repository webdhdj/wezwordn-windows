/**
 * SecureSharing — literal port of the Swift module of the same name
 * (WezWordnCore/Sources/SecureSharing).
 *
 * Encrypted single-item sharing package (`.wezshare`, JSON encoded).
 *
 * Same envelope scheme as EmergencyRecovery, independently implemented for
 * this module: ephemeral X25519 -> HKDF-SHA256 (info
 * "WezWordn-SecureSharing-v1") -> AES-256-GCM over the JSON-serialised
 * item. `ciphertext` is ciphertext || 16-byte GCM tag.
 * `fingerprint` = lowercase hex SHA-256(ephemeralPublicKey || salt || nonce
 * || ciphertext): a non-secret integrity/display value the sender and
 * recipient can compare out-of-band before import. Import verifies the
 * fingerprint AND the GCM tag; either failure rejects the package.
 * Once a recipient decrypts a copy, it cannot be revoked from them — this
 * is documented behaviour, not a limitation we claim to solve.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  diffieHellman,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import { canonicalJSON, iso8601NoFraction, parseISO8601 } from "./canonical-json.js";
import { generateX25519KeyPair, publicKeyFromRaw } from "./x25519-raw.js";

export interface ShareableItem {
  title: string;
  username: string | null;
  email: string | null;
  password: string | null;
  notes: string | null;
  url: string | null;
}

export function shareableItem(partial: Partial<ShareableItem> & { title: string }): ShareableItem {
  return {
    title: partial.title,
    username: partial.username ?? null,
    email: partial.email ?? null,
    password: partial.password ?? null,
    notes: partial.notes ?? null,
    url: partial.url ?? null,
  };
}

export interface SharePackage {
  version: number;
  ephemeralPublicKey: Buffer;
  salt: Buffer;
  nonce: Buffer;
  /** ciphertext || tag */
  ciphertext: Buffer;
  createdAt: Date;
  fingerprint: string;
}

export type SecureSharingErrorCode =
  | "unsupportedVersion"
  | "fingerprintMismatch"
  | "malformedPackage"
  | "decryptionFailed";

export class SecureSharingError extends Error {
  readonly code: SecureSharingErrorCode;
  readonly detail: string | number | null;
  constructor(code: SecureSharingErrorCode, detail: string | number | null = null) {
    super(detail === null ? code : `${code}: ${detail}`);
    this.code = code;
    this.detail = detail;
  }
}

export const SECURE_SHARING_CURRENT_VERSION = 1;
export const WEZSHARE_FILE_EXTENSION = "wezshare";
const HKDF_INFO = Buffer.from("WezWordn-SecureSharing-v1", "utf8");

export function computeShareFingerprint(
  ephemeralPublicKey: Buffer,
  salt: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
): string {
  const hasher = createHash("sha256");
  hasher.update(ephemeralPublicKey);
  hasher.update(salt);
  hasher.update(nonce);
  hasher.update(ciphertext);
  return hasher.digest("hex");
}

export function shareFingerprintIsValid(pkg: SharePackage): boolean {
  return (
    computeShareFingerprint(pkg.ephemeralPublicKey, pkg.salt, pkg.nonce, pkg.ciphertext) ===
    pkg.fingerprint
  );
}

function deriveKey(sharedSecret: Buffer, salt: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", sharedSecret, salt, HKDF_INFO, 32));
}

function shareableItemToJSON(item: ShareableItem): Record<string, unknown> {
  const out: Record<string, unknown> = { title: item.title };
  if (item.username !== null) out.username = item.username;
  if (item.email !== null) out.email = item.email;
  if (item.password !== null) out.password = item.password;
  if (item.notes !== null) out.notes = item.notes;
  if (item.url !== null) out.url = item.url;
  return out;
}

function shareableItemFromJSON(data: Record<string, unknown>): ShareableItem {
  return shareableItem({
    title: data.title as string,
    username: (data.username as string | undefined) ?? null,
    email: (data.email as string | undefined) ?? null,
    password: (data.password as string | undefined) ?? null,
    notes: (data.notes as string | undefined) ?? null,
    url: (data.url as string | undefined) ?? null,
  });
}

/** The payload serialisation inside the envelope mirrors the Swift module:
 * a plain JSONEncoder encoding of the item (no sortedKeys/date strategy is
 * applied there — the item has no dates and key order is irrelevant to the
 * decoder). This port encodes canonically (sorted keys); any conforming
 * JSON decoder, including Swift's, reads it identically. */
export function createSharePackage(
  item: ShareableItem,
  recipientPublicKey: KeyObject,
  createdAt: Date = new Date(),
): SharePackage {
  const payload = Buffer.from(canonicalJSON(shareableItemToJSON(item)), "utf8");
  const ephemeral = generateX25519KeyPair();
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientPublicKey });
  const salt = randomBytes(32);
  const key = deriveKey(shared, salt);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const sealed = Buffer.concat([cipher.update(payload), cipher.final()]);
  const combined = Buffer.concat([sealed, cipher.getAuthTag()]);
  const eph = ephemeral.publicKeyRaw;
  const fingerprint = computeShareFingerprint(eph, salt, nonce, combined);
  return {
    version: SECURE_SHARING_CURRENT_VERSION,
    ephemeralPublicKey: eph,
    salt,
    nonce,
    ciphertext: combined,
    createdAt,
    fingerprint,
  };
}

export function openSharePackage(pkg: SharePackage, recipientPrivateKey: KeyObject): ShareableItem {
  if (pkg.version !== SECURE_SHARING_CURRENT_VERSION) {
    throw new SecureSharingError("unsupportedVersion", pkg.version);
  }
  if (!shareFingerprintIsValid(pkg)) throw new SecureSharingError("fingerprintMismatch");
  if (!(pkg.ciphertext.length > 16) || pkg.nonce.length !== 12) {
    throw new SecureSharingError("malformedPackage", "ciphertext/nonce length");
  }
  let ephemeralPublic: KeyObject;
  try {
    ephemeralPublic = publicKeyFromRaw(pkg.ephemeralPublicKey);
  } catch {
    throw new SecureSharingError("malformedPackage", "ephemeral public key");
  }
  const shared = diffieHellman({ privateKey: recipientPrivateKey, publicKey: ephemeralPublic });
  const key = deriveKey(shared, pkg.salt);
  let plain: Buffer;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, pkg.nonce);
    decipher.setAuthTag(Buffer.from(pkg.ciphertext.subarray(pkg.ciphertext.length - 16)));
    plain = Buffer.concat([
      decipher.update(Buffer.from(pkg.ciphertext.subarray(0, pkg.ciphertext.length - 16))),
      decipher.final(),
    ]);
  } catch {
    throw new SecureSharingError("decryptionFailed");
  }
  try {
    return shareableItemFromJSON(JSON.parse(plain.toString("utf8")) as Record<string, unknown>);
  } catch {
    throw new SecureSharingError("malformedPackage", "payload JSON");
  }
}

/** Serialises a package to `.wezshare` JSON (sorted keys, ISO-8601 dates,
 * Data as base64 — the Swift exportData configuration). */
export function exportSharePackage(pkg: SharePackage): string {
  return canonicalJSON({
    version: pkg.version,
    ephemeralPublicKey: pkg.ephemeralPublicKey,
    salt: pkg.salt,
    nonce: pkg.nonce,
    ciphertext: pkg.ciphertext,
    createdAt: iso8601NoFraction(pkg.createdAt),
    fingerprint: pkg.fingerprint,
  });
}

export function importSharePackage(text: string): SharePackage {
  const data = JSON.parse(text) as Record<string, unknown>;
  return {
    version: data.version as number,
    ephemeralPublicKey: Buffer.from(data.ephemeralPublicKey as string, "base64"),
    salt: Buffer.from(data.salt as string, "base64"),
    nonce: Buffer.from(data.nonce as string, "base64"),
    ciphertext: Buffer.from(data.ciphertext as string, "base64"),
    createdAt: parseISO8601(data.createdAt as string),
    fingerprint: data.fingerprint as string,
  };
}
