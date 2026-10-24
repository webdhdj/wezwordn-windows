/**
 * Internal X25519 raw-key conversion helpers.
 *
 * Node's KeyObject exports X25519 keys as DER: SPKI (44 bytes) for public
 * keys and PKCS#8 (48 bytes) for private keys. In both encodings the raw
 * 32-byte key material is the LAST 32 bytes — verified directly against
 * node:crypto — which is exactly swift-crypto's `rawRepresentation`.
 * Re-import wraps a raw key in the fixed DER prefix for its encoding.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";

const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex"); // 12 bytes
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex"); // 16 bytes

export interface X25519KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  privateKeyRaw: Buffer;
  publicKeyRaw: Buffer;
}

export function generateX25519KeyPair(): X25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    privateKey,
    publicKey,
    privateKeyRaw: rawPrivateKey(privateKey),
    publicKeyRaw: rawPublicKey(publicKey),
  };
}

export function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ type: "spki", format: "der" });
  return Buffer.from(der.subarray(der.length - 32));
}

export function rawPrivateKey(key: KeyObject): Buffer {
  const der = key.export({ type: "pkcs8", format: "der" });
  return Buffer.from(der.subarray(der.length - 32));
}

export function publicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error("X25519 public key must be 32 bytes");
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

export function privateKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error("X25519 private key must be 32 bytes");
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, raw]),
    format: "der",
    type: "pkcs8",
  });
}
