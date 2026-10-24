/**
 * LocalEncryptedStorage — literal port of the Swift module of the same name
 * (WezWordnCore/Sources/LocalEncryptedStorage).
 *
 * Chunked, streaming AES-256-GCM file encryption.
 *
 * On-disk format (all integers big-endian):
 *   Header:
 *     magic      4 bytes  ASCII "WZEN"
 *     version    1 byte   0x01
 *     baseNonce 12 bytes  cryptographically random, fresh per encryption
 *     chunkSize  4 bytes  UInt32, plaintext bytes per chunk (1...16 MiB)
 *   Then one record per chunk, counter i = 0, 1, 2, ...:
 *     plainLen   4 bytes  UInt32; 1...chunkSize for a data chunk,
 *                         0 marks the explicit end-of-stream record (no
 *                         ciphertext/tag follow it) and MUST be present —
 *                         a file without it is treated as truncated/corrupt.
 *     ciphertext plainLen bytes, followed by the 16-byte GCM tag.
 *   Chunk nonce: baseNonce with its last 8 bytes XORed with the big-endian
 *   UInt64 chunk counter (first 4 bytes unchanged). Because baseNonce is
 *   random per file and the counter is unique per chunk within the file,
 *   a (key, nonce) pair is never reused across chunks or files.
 * Authentication: each chunk is independently authenticated by its GCM tag;
 * any tampering, wrong key, or truncation fails decryption and the partial
 * plaintext output file is deleted.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readSync,
  renameSync,
  rmSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";

export type EncryptedFileErrorCode =
  | "badMagic"
  | "unsupportedVersion"
  | "invalidChunkSize"
  | "invalidKeySize"
  | "truncated"
  | "authenticationFailed"
  | "ioError";

export class EncryptedFileError extends Error {
  readonly code: EncryptedFileErrorCode;
  readonly detail: string | number | null;
  constructor(code: EncryptedFileErrorCode, detail: string | number | null = null) {
    super(detail === null ? code : `${code}: ${detail}`);
    this.code = code;
    this.detail = detail;
  }
}

export interface KeyProvider {
  encryptionKey(): Buffer;
}

/** In-memory key provider for tests / non-Keychain use. Production Windows
 * code supplies a DPAPI/Credential-Manager-backed provider with the same
 * protocol. */
export class InMemoryKeyProvider implements KeyProvider {
  private readonly keyData: Buffer;
  constructor(keyData?: Buffer) {
    this.keyData = keyData ?? randomBytes(32);
  }
  encryptionKey(): Buffer {
    if (this.keyData.length !== 32) throw new EncryptedFileError("invalidKeySize");
    return Buffer.from(this.keyData);
  }
  get rawKeyData(): Buffer {
    return Buffer.from(this.keyData);
  }
}

export const WZEN_MAGIC = Buffer.from("WZEN", "ascii");
export const WZEN_VERSION = 1;
export const DEFAULT_CHUNK_SIZE = 64 * 1024;
const MAX_CHUNK_SIZE = 16 * 1024 * 1024;

/** Chunk nonce: baseNonce with bytes [4..12) XORed with BE UInt64(counter). */
export function chunkNonce(baseNonce: Buffer, counter: bigint | number): Buffer {
  const nonce = Buffer.from(baseNonce);
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(BigInt(counter));
  for (let i = 0; i < 8; i++) nonce[4 + i] ^= counterBytes[i];
  return nonce;
}

function assertKey(key: Buffer): void {
  if (key.length !== 32) throw new EncryptedFileError("invalidKeySize");
}

function assertChunkSize(chunkSize: number): void {
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) {
    throw new EncryptedFileError("invalidChunkSize");
  }
}

function readExactly(fd: number, length: number): Buffer | null {
  if (length === 0) return Buffer.alloc(0);
  const buf = Buffer.alloc(length);
  let read = 0;
  while (read < length) {
    const n = readSync(fd, buf, read, length - read, null);
    if (n === 0) break;
    read += n;
  }
  return read === length ? buf : null;
}

function writeAll(fd: number, data: Buffer): void {
  let written = 0;
  while (written < data.length) {
    written += writeSync(fd, data, written, data.length - written);
  }
}

export interface EncryptOptions {
  chunkSize?: number;
  /** TEST HOOK ONLY: fixes the base nonce so cross-platform test vectors are
   * reproducible. Production callers must omit it (fresh random per file),
   * exactly like the Swift API, which exposes no such parameter. */
  baseNonceForTesting?: Buffer;
}

export function encryptFile(
  source: string,
  destination: string,
  key: Buffer,
  options: EncryptOptions = {},
): void {
  assertKey(key);
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
  assertChunkSize(chunkSize);
  const baseNonce = options.baseNonceForTesting
    ? Buffer.from(options.baseNonceForTesting)
    : randomBytes(12);
  if (baseNonce.length !== 12) throw new EncryptedFileError("ioError", "baseNonce must be 12 bytes");
  let reader = -1;
  let writer = -1;
  try {
    try {
      reader = openSync(source, "r");
      writer = openSync(destination, "w");
    } catch {
      throw new EncryptedFileError("ioError", "cannot open source or destination");
    }
    const header = Buffer.alloc(21);
    WZEN_MAGIC.copy(header, 0);
    header[4] = WZEN_VERSION;
    baseNonce.copy(header, 5);
    header.writeUInt32BE(chunkSize, 17);
    writeAll(writer, header);

    let counter = 0n;
    for (;;) {
      const chunk = Buffer.alloc(chunkSize);
      let filled = 0;
      while (filled < chunkSize) {
        const n = readSync(reader, chunk, filled, chunkSize - filled, null);
        if (n === 0) break;
        filled += n;
      }
      if (filled === 0) break;
      const plain = filled === chunkSize ? chunk : chunk.subarray(0, filled);
      const nonce = chunkNonce(baseNonce, counter);
      const cipher = createCipheriv("aes-256-gcm", key, nonce);
      const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
      const tag = cipher.getAuthTag();
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32BE(plain.length, 0);
      writeAll(writer, lenBuf);
      writeAll(writer, ciphertext);
      writeAll(writer, tag);
      counter += 1n;
    }
    // Explicit end-of-stream marker: plainLen == 0.
    writeAll(writer, Buffer.alloc(4));
    fsyncSync(writer);
  } catch (e) {
    if (reader >= 0) try { closeSync(reader); } catch { /* ignore */ }
    if (writer >= 0) try { closeSync(writer); } catch { /* ignore */ }
    try { rmSync(destination, { force: true }); } catch { /* ignore */ }
    if (e instanceof EncryptedFileError) throw e;
    throw new EncryptedFileError("ioError", String(e));
  }
  closeSync(reader);
  closeSync(writer);
}

export function encryptFileWithProvider(
  source: string,
  destination: string,
  keyProvider: KeyProvider,
  options: EncryptOptions = {},
): void {
  encryptFile(source, destination, keyProvider.encryptionKey(), options);
}

export function decryptFile(source: string, destination: string, key: Buffer): void {
  assertKey(key);
  let reader = -1;
  let writer = -1;
  let closed = false;
  try {
    try {
      reader = openSync(source, "r");
    } catch {
      throw new EncryptedFileError("ioError", "cannot open encrypted file");
    }
    const header = readExactly(reader, 21);
    if (header === null || header.length !== 21) throw new EncryptedFileError("truncated");
    if (!header.subarray(0, 4).equals(WZEN_MAGIC)) throw new EncryptedFileError("badMagic");
    if (header[4] !== WZEN_VERSION) throw new EncryptedFileError("unsupportedVersion", header[4]);
    const baseNonce = Buffer.from(header.subarray(5, 17));
    const chunkSize = header.readUInt32BE(17);
    if (chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) throw new EncryptedFileError("invalidChunkSize");

    try {
      writer = openSync(destination, "w");
    } catch {
      throw new EncryptedFileError("ioError", "cannot open destination");
    }

    let counter = 0n;
    for (;;) {
      const lenData = readExactly(reader, 4);
      if (lenData === null) throw new EncryptedFileError("truncated");
      const plainLen = lenData.readUInt32BE(0);
      if (plainLen === 0) break; // end-of-stream marker
      if (plainLen > chunkSize) throw new EncryptedFileError("truncated");
      const cipher = readExactly(reader, plainLen);
      const tag = readExactly(reader, 16);
      if (cipher === null || tag === null) throw new EncryptedFileError("truncated");
      const nonce = chunkNonce(baseNonce, counter);
      let plain: Buffer;
      try {
        const decipher = createDecipheriv("aes-256-gcm", key, nonce);
        decipher.setAuthTag(tag);
        plain = Buffer.concat([decipher.update(cipher), decipher.final()]);
      } catch {
        throw new EncryptedFileError("authenticationFailed");
      }
      writeAll(writer, plain);
      counter += 1n;
    }
    fsyncSync(writer);
    closeSync(writer);
    closed = true;
  } catch (e) {
    if (reader >= 0) try { closeSync(reader); } catch { /* ignore */ }
    if (writer >= 0 && !closed) try { closeSync(writer); } catch { /* ignore */ }
    try { rmSync(destination, { force: true }); } catch { /* ignore */ }
    if (e instanceof EncryptedFileError) throw e;
    throw new EncryptedFileError("ioError", String(e));
  }
  closeSync(reader);
}

export function decryptFileWithProvider(source: string, destination: string, keyProvider: KeyProvider): void {
  decryptFile(source, destination, keyProvider.encryptionKey());
}

/**
 * Re-encrypts an existing WZEN file from `oldKey` to `newKey` in place.
 *
 * Safety contract (identical to Swift): the original file is only replaced
 * after BOTH the full decryption with `oldKey` and the full re-encryption
 * with `newKey` have succeeded in temporary sibling files. On any failure
 * (wrong old key, I/O error) the temporary files are deleted and the
 * original file is left byte-for-byte untouched.
 */
export function rekeyFile(url: string, oldKey: Buffer, newKey: Buffer, chunkSize: number = DEFAULT_CHUNK_SIZE): void {
  const dir = dirname(url);
  const suffix = randomBytes(8).toString("hex");
  const plainTmp = join(dir, `.rekey-plain-${suffix}`);
  const encTmp = join(dir, `.rekey-enc-${suffix}`);
  try {
    decryptFile(url, plainTmp, oldKey);
    encryptFile(plainTmp, encTmp, newKey, { chunkSize });
    rmSync(plainTmp, { force: true });
    rmSync(url, { force: true });
    renameSync(encTmp, url);
  } finally {
    try { rmSync(plainTmp, { force: true }); } catch { /* ignore */ }
    try { rmSync(encTmp, { force: true }); } catch { /* ignore */ }
  }
}

export function rekeyFileWithProviders(
  url: string,
  oldKeyProvider: KeyProvider,
  newKeyProvider: KeyProvider,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): void {
  rekeyFile(url, oldKeyProvider.encryptionKey(), newKeyProvider.encryptionKey(), chunkSize);
}

/** Existence helper mirroring FileManager.fileExists in the Swift tests. */
export function fileExists(path: string): boolean {
  return existsSync(path);
}
