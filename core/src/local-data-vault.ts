/**
 * LocalDataVault — literal port of the Swift module of the same name
 * (WezWordnCore/Sources/LocalDataVault: LocalDataVault.swift +
 * VaultBackup.swift).
 *
 * Local sidecar data vault: binds WezWordn-only data (extra login email,
 * local TOTP secrets, encrypted-file references) to Bitwarden vault items
 * by the composite key (accountId, cipherId), without touching Bitwarden's
 * synced data model.
 *
 * Storage layout under `directory`:
 *   vault-sidecar.wzen   — SidecarStore JSON, encrypted with
 *                          LocalEncryptedStorage (chunked AES-256-GCM,
 *                          "WZEN" format) under the KeyProvider key.
 *   files/<fileId>.wzen  — referenced encrypted files, same scheme/key.
 *
 * Integrity rules:
 * - Every mutation is persisted to the encrypted sidecar immediately.
 * - `schemaVersion` is checked on open; an unknown newer version throws
 *   `unsupportedSchemaVersion` and nothing is modified (no silent data
 *   loss). Older versions go through `migrateStore` (v1 is current, so
 *   the only accepted on-disk version today is 1).
 * - Deleting a cipher cascades: its records AND its encrypted files are
 *   removed. `orphanSweep` applies the same cascade to ciphers that a
 *   sync/account switch left behind.
 * - Plaintext sidecar JSON only ever exists in short-lived temp files
 *   inside the vault directory, deleted on every path.
 *
 * The Swift class serialises access with an NSLock; Node's single-threaded
 * synchronous execution makes every method atomic by construction, so no
 * lock equivalent is needed (or faked).
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
} from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";
import { canonicalJSON, iso8601NoFraction, parseISO8601 } from "./canonical-json.js";
import {
  decryptFile,
  encryptFile,
  EncryptedFileError,
  rekeyFile,
  type KeyProvider,
} from "./local-encrypted-storage.js";
import { Base32, OTPGenerator, type OTPAlgorithm } from "./local-totp.js";
import { deriveKeySHA256 } from "./pbkdf2.js";

// MARK: - Public record types

/** Composite binding key for every sidecar record. The account component is
 * what guarantees account isolation: records of account A are stored,
 * listed, swept and deleted strictly under A's key space, even if a
 * `cipherId` collides with one of account B's items. */
export interface VaultRecordKey {
  accountId: string;
  cipherId: string;
}

function keyId(key: VaultRecordKey): string {
  return key.accountId + "\u0000" + key.cipherId;
}

/** A locally stored TOTP secret bound to one vault item. The secret itself
 * stays inside the encrypted sidecar file; it is never synced through
 * Bitwarden and never logged. */
export interface TOTPSecretRecord {
  secretBase32: string;
  issuer: string | null;
  accountName: string;
  algorithm: OTPAlgorithm;
  digits: number;
  period: number;
}

export function totpSecretRecord(partial: {
  secretBase32: string;
  issuer?: string | null;
  accountName: string;
  algorithm?: OTPAlgorithm;
  digits?: number;
  period?: number;
}): TOTPSecretRecord {
  return {
    secretBase32: partial.secretBase32,
    issuer: partial.issuer ?? null,
    accountName: partial.accountName,
    algorithm: partial.algorithm ?? "SHA1",
    digits: partial.digits ?? 6,
    period: partial.period ?? 30,
  };
}

/** Generates the current TOTP code with the real RFC 6238 implementation
 * from LocalTOTP. `dateMs` is milliseconds since the Unix epoch. */
export function totpRecordCurrentCode(record: TOTPSecretRecord, dateMs: number = Date.now()): string {
  const secret = Base32.decode(record.secretBase32);
  return OTPGenerator.totp(secret, dateMs, record.period, record.digits, record.algorithm);
}

/** Reference to one encrypted file held by LocalEncryptedStorage.
 * The file's bytes live at `<vault>/files/<fileId>.wzen`; this record is
 * the metadata needed to find, verify and cascade-delete it. */
export interface EncryptedFileRef {
  fileId: string;
  /** Original display name of the plaintext file. */
  name: string;
  /** Plaintext size in bytes. */
  size: number;
  /** Lowercase hex SHA-256 of the plaintext, captured at store time. */
  sha256: string;
}

export type LocalDataVaultErrorCode =
  | "unsupportedSchemaVersion"
  | "corruptSidecar"
  | "fileNotFound"
  | "backupBadPasswordOrCorrupt"
  | "backupFingerprintMismatch"
  | "backupFormatInvalid"
  | "ioError";

export class LocalDataVaultError extends Error {
  readonly code: LocalDataVaultErrorCode;
  readonly detail: string | number | null;
  constructor(code: LocalDataVaultErrorCode, detail: string | number | null = null) {
    super(detail === null ? code : `${code}: ${detail}`);
    this.code = code;
    this.detail = detail;
  }
}

// MARK: - On-disk sidecar representation

/** Array-form snapshot of all sidecar records. Arrays (not a dictionary
 * keyed by a stringified composite key) are used so that any
 * accountId/cipherId characters survive a roundtrip unambiguously. */
export interface SidecarStore {
  schemaVersion: number;
  emails: { accountId: string; cipherId: string; email: string }[];
  totps: { accountId: string; cipherId: string; record: TOTPSecretRecord }[];
  files: { accountId: string; cipherId: string; ref: EncryptedFileRef }[];
}

function totpRecordToJSON(record: TOTPSecretRecord): Record<string, unknown> {
  const out: Record<string, unknown> = {
    secretBase32: record.secretBase32,
    accountName: record.accountName,
    algorithm: record.algorithm,
    digits: record.digits,
    period: record.period,
  };
  if (record.issuer !== null) out.issuer = record.issuer;
  return out;
}

function totpRecordFromJSON(data: Record<string, unknown>): TOTPSecretRecord {
  return totpSecretRecord({
    secretBase32: data.secretBase32 as string,
    issuer: (data.issuer as string | undefined) ?? null,
    accountName: data.accountName as string,
    algorithm: data.algorithm as OTPAlgorithm,
    digits: data.digits as number,
    period: data.period as number,
  });
}

function storeToJSON(store: SidecarStore): Record<string, unknown> {
  return {
    schemaVersion: store.schemaVersion,
    emails: store.emails.map((e) => ({ accountId: e.accountId, cipherId: e.cipherId, email: e.email })),
    totps: store.totps.map((t) => ({
      accountId: t.accountId,
      cipherId: t.cipherId,
      record: totpRecordToJSON(t.record),
    })),
    files: store.files.map((f) => ({
      accountId: f.accountId,
      cipherId: f.cipherId,
      ref: { fileId: f.ref.fileId, name: f.ref.name, size: f.ref.size, sha256: f.ref.sha256 },
    })),
  };
}

function storeFromJSON(data: Record<string, unknown>): SidecarStore {
  const emails = (data.emails as Record<string, unknown>[] | undefined) ?? [];
  const totps = (data.totps as Record<string, unknown>[] | undefined) ?? [];
  const files = (data.files as Record<string, unknown>[] | undefined) ?? [];
  return {
    schemaVersion: data.schemaVersion as number,
    emails: emails.map((e) => ({
      accountId: e.accountId as string,
      cipherId: e.cipherId as string,
      email: e.email as string,
    })),
    totps: totps.map((t) => ({
      accountId: t.accountId as string,
      cipherId: t.cipherId as string,
      record: totpRecordFromJSON(t.record as Record<string, unknown>),
    })),
    files: files.map((f) => {
      const ref = f.ref as Record<string, unknown>;
      return {
        accountId: f.accountId as string,
        cipherId: f.cipherId as string,
        ref: {
          fileId: ref.fileId as string,
          name: ref.name as string,
          size: ref.size as number,
          sha256: ref.sha256 as string,
        },
      };
    }),
  };
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

// MARK: - LocalDataVault

export class LocalDataVault {
  static readonly currentSchemaVersion = 1;
  static readonly sidecarFileName = "vault-sidecar.wzen";
  static readonly filesDirectoryName = "files";
  static readonly backupFormat = "WEZBACKUP";
  static readonly backupFormatVersion = 1;
  static readonly defaultBackupIterations = 210_000;

  private readonly directory: string;
  readonly filesDirectory: string;
  private readonly sidecarPath: string;
  private keyProvider: KeyProvider;

  private emails = new Map<string, { key: VaultRecordKey; email: string }>();
  private totps = new Map<string, { key: VaultRecordKey; record: TOTPSecretRecord }>();
  private fileRefs = new Map<string, { key: VaultRecordKey; refs: EncryptedFileRef[] }>();

  /** Opens (or creates) a vault in `directory`. If a sidecar exists it is
   * decrypted with `keyProvider`'s key — a wrong key throws
   * `EncryptedFileError` (authenticationFailed) and nothing is written. */
  constructor(directory: string, keyProvider: KeyProvider) {
    this.directory = directory;
    this.filesDirectory = join(directory, LocalDataVault.filesDirectoryName);
    this.sidecarPath = join(directory, LocalDataVault.sidecarFileName);
    this.keyProvider = keyProvider;
    try {
      mkdirSync(this.filesDirectory, { recursive: true });
    } catch (e) {
      throw new LocalDataVaultError("ioError", `cannot create vault directory: ${String(e)}`);
    }
    if (existsSync(this.sidecarPath)) {
      const store = LocalDataVault.loadStore(this.sidecarPath, keyProvider);
      for (const entry of store.emails) {
        const key = { accountId: entry.accountId, cipherId: entry.cipherId };
        this.emails.set(keyId(key), { key, email: entry.email });
      }
      for (const entry of store.totps) {
        const key = { accountId: entry.accountId, cipherId: entry.cipherId };
        this.totps.set(keyId(key), { key, record: entry.record });
      }
      for (const entry of store.files) {
        const key = { accountId: entry.accountId, cipherId: entry.cipherId };
        const id = keyId(key);
        const bucket = this.fileRefs.get(id) ?? { key, refs: [] };
        bucket.refs.push(entry.ref);
        this.fileRefs.set(id, bucket);
      }
    } else {
      this.persist();
    }
  }

  // MARK: Snapshot / persistence

  private snapshot(): SidecarStore {
    const store: SidecarStore = {
      schemaVersion: LocalDataVault.currentSchemaVersion,
      emails: [...this.emails.values()]
        .map((v) => ({ accountId: v.key.accountId, cipherId: v.key.cipherId, email: v.email }))
        .sort((a, b) => compareStrings(a.accountId, b.accountId) || compareStrings(a.cipherId, b.cipherId)),
      totps: [...this.totps.values()]
        .map((v) => ({ accountId: v.key.accountId, cipherId: v.key.cipherId, record: v.record }))
        .sort((a, b) => compareStrings(a.accountId, b.accountId) || compareStrings(a.cipherId, b.cipherId)),
      files: [...this.fileRefs.values()]
        .flatMap((v) => v.refs.map((ref) => ({ accountId: v.key.accountId, cipherId: v.key.cipherId, ref })))
        .sort(
          (a, b) =>
            compareStrings(a.accountId, b.accountId) ||
            compareStrings(a.cipherId, b.cipherId) ||
            compareStrings(a.ref.fileId, b.ref.fileId),
        ),
    };
    return store;
  }

  private persist(): void {
    LocalDataVault.writeStore(this.snapshot(), this.sidecarPath, this.keyProvider);
  }

  private static writeStore(store: SidecarStore, sidecarPath: string, keyProvider: KeyProvider): void {
    const dir = join(sidecarPath, "..");
    const plainTmp = join(dir, `.sidecar-plain-${randomUUID()}`);
    const encTmp = join(dir, `.sidecar-enc-${randomUUID()}`);
    try {
      try {
        writeFileSync(plainTmp, Buffer.from(canonicalJSON(storeToJSON(store)), "utf8"));
        encryptFile(plainTmp, encTmp, keyProvider.encryptionKey());
      } catch (e) {
        if (e instanceof EncryptedFileError) throw e;
        throw new LocalDataVaultError("ioError", `persist failed: ${String(e)}`);
      }
      rmSync(plainTmp, { force: true });
      // Swap in only after the new sidecar is fully encrypted.
      if (existsSync(sidecarPath)) {
        try {
          rmSync(sidecarPath, { force: true });
        } catch (e) {
          throw new LocalDataVaultError("ioError", `cannot replace sidecar: ${String(e)}`);
        }
      }
      try {
        renameSync(encTmp, sidecarPath);
      } catch (e) {
        throw new LocalDataVaultError("ioError", `cannot install sidecar: ${String(e)}`);
      }
    } finally {
      try { rmSync(plainTmp, { force: true }); } catch { /* ignore */ }
      try { rmSync(encTmp, { force: true }); } catch { /* ignore */ }
    }
  }

  private static loadStore(sidecarPath: string, keyProvider: KeyProvider): SidecarStore {
    const dir = join(sidecarPath, "..");
    const plainTmp = join(dir, `.sidecar-load-${randomUUID()}`);
    try {
      // A wrong key throws EncryptedFileError(authenticationFailed) here.
      decryptFile(sidecarPath, plainTmp, keyProvider.encryptionKey());
      let data: Buffer;
      try {
        data = readFileSync(plainTmp);
      } catch (e) {
        throw new LocalDataVaultError("ioError", `cannot read decrypted sidecar: ${String(e)}`);
      }
      let raw: SidecarStore;
      try {
        raw = storeFromJSON(JSON.parse(data.toString("utf8")) as Record<string, unknown>);
      } catch {
        throw new LocalDataVaultError("corruptSidecar", "sidecar JSON undecodable");
      }
      return LocalDataVault.migrateStore(raw);
    } finally {
      try { rmSync(plainTmp, { force: true }); } catch { /* ignore */ }
    }
  }

  /** Schema gate + migration. v1 is the current (and first) schema, so any
   * other version is rejected explicitly rather than silently dropped:
   * a NEWER version was written by a newer build and must be opened by it;
   * anything below 1 was never a valid sidecar. */
  static migrateStore(store: SidecarStore): SidecarStore {
    if (store.schemaVersion === LocalDataVault.currentSchemaVersion) return store;
    throw new LocalDataVaultError("unsupportedSchemaVersion", store.schemaVersion);
  }

  // MARK: - Email (ExtendedLoginFields sidecar)

  email(accountId: string, cipherId: string): string | null {
    return this.emails.get(keyId({ accountId, cipherId }))?.email ?? null;
  }

  setEmail(email: string, accountId: string, cipherId: string): void {
    const key = { accountId, cipherId };
    this.emails.set(keyId(key), { key, email });
    this.persist();
  }

  /** Convenience binding for an `ExtendedLogin`: stores its independent
   * `email` field under the item's composite key. */
  setEmailFromLogin(login: { email: string | null }, accountId: string, cipherId: string): void {
    if (login.email === null || login.email.length === 0) return;
    this.setEmail(login.email, accountId, cipherId);
  }

  removeEmail(accountId: string, cipherId: string): boolean {
    const id = keyId({ accountId, cipherId });
    if (!this.emails.has(id)) return false;
    this.emails.delete(id);
    this.persist();
    return true;
  }

  // MARK: - TOTP secrets

  totpRecord(accountId: string, cipherId: string): TOTPSecretRecord | null {
    return this.totps.get(keyId({ accountId, cipherId }))?.record ?? null;
  }

  setTOTP(record: TOTPSecretRecord, accountId: string, cipherId: string): void {
    const key = { accountId, cipherId };
    this.totps.set(keyId(key), { key, record });
    this.persist();
  }

  removeTOTP(accountId: string, cipherId: string): boolean {
    const id = keyId({ accountId, cipherId });
    if (!this.totps.has(id)) return false;
    this.totps.delete(id);
    this.persist();
    return true;
  }

  // MARK: - Encrypted files

  private filePathFor(ref: EncryptedFileRef): string {
    return join(this.filesDirectory, `${ref.fileId}.wzen`);
  }

  /** Encrypts `plaintextPath` into the vault's file store and registers
   * its reference under the composite key. The plaintext file's SHA-256
   * and size are captured by streaming, before encryption. */
  storeFile(plaintextPath: string, accountId: string, cipherId: string, name?: string): EncryptedFileRef {
    const { size, sha256 } = LocalDataVault.fingerprintOfFile(plaintextPath);
    const ref: EncryptedFileRef = {
      fileId: randomUUID(),
      name: name ?? basename(plaintextPath),
      size,
      sha256,
    };
    const dest = this.filePathFor(ref);
    encryptFile(plaintextPath, dest, this.keyProvider.encryptionKey());
    const key = { accountId, cipherId };
    const id = keyId(key);
    const bucket = this.fileRefs.get(id) ?? { key, refs: [] };
    bucket.refs.push(ref);
    this.fileRefs.set(id, bucket);
    try {
      this.persist();
    } catch (e) {
      // Roll back the just-written encrypted file so a failed persist never
      // leaves unreferenced ciphertext behind.
      bucket.refs = bucket.refs.filter((r) => r.fileId !== ref.fileId);
      if (bucket.refs.length === 0) this.fileRefs.delete(id);
      try { rmSync(dest, { force: true }); } catch { /* ignore */ }
      throw e;
    }
    return ref;
  }

  fileRefsFor(accountId: string, cipherId: string): EncryptedFileRef[] {
    return [...(this.fileRefs.get(keyId({ accountId, cipherId }))?.refs ?? [])];
  }

  /** Decrypts a referenced file to `destination` with the current key. */
  decryptStoredFile(ref: EncryptedFileRef, destination: string): void {
    const src = this.filePathFor(ref);
    if (!existsSync(src)) throw new LocalDataVaultError("fileNotFound", ref.fileId);
    decryptFile(src, destination, this.keyProvider.encryptionKey());
  }

  /** Decrypts a referenced file fully into memory (small files / tests). */
  decryptedData(ref: EncryptedFileRef): Buffer {
    const tmp = join(this.directory, `.dec-${randomUUID()}`);
    try {
      this.decryptStoredFile(ref, tmp);
      try {
        return readFileSync(tmp);
      } catch (e) {
        throw new LocalDataVaultError("ioError", `cannot read decrypted file: ${String(e)}`);
      }
    } finally {
      try { rmSync(tmp, { force: true }); } catch { /* ignore */ }
    }
  }

  removeFile(ref: EncryptedFileRef, accountId: string, cipherId: string): boolean {
    const id = keyId({ accountId, cipherId });
    const bucket = this.fileRefs.get(id);
    if (bucket === undefined || !bucket.refs.some((r) => r.fileId === ref.fileId)) return false;
    bucket.refs = bucket.refs.filter((r) => r.fileId !== ref.fileId);
    if (bucket.refs.length === 0) this.fileRefs.delete(id);
    try { rmSync(this.filePathFor(ref), { force: true }); } catch { /* ignore */ }
    this.persist();
    return true;
  }

  static fingerprintOfFile(path: string): { size: number; sha256: string } {
    let fd: number;
    try {
      fd = openSync(path, "r");
    } catch {
      throw new LocalDataVaultError("ioError", "cannot open file for fingerprinting");
    }
    try {
      const hasher = createHash("sha256");
      let total = 0;
      const chunk = Buffer.alloc(64 * 1024);
      for (;;) {
        const n = readSync(fd, chunk, 0, chunk.length, null);
        if (n === 0) break;
        hasher.update(chunk.subarray(0, n));
        total += n;
      }
      return { size: total, sha256: hasher.digest("hex") };
    } finally {
      closeSync(fd);
    }
  }

  // MARK: - Cascade delete & orphan sweep

  /** Deletes EVERYTHING bound to (accountId, cipherId): the email record,
   * the TOTP record, all file references and the referenced encrypted
   * files themselves from disk. */
  deleteCipher(accountId: string, cipherId: string): void {
    const id = keyId({ accountId, cipherId });
    this.emails.delete(id);
    this.totps.delete(id);
    const bucket = this.fileRefs.get(id);
    if (bucket !== undefined) {
      for (const ref of bucket.refs) {
        try { rmSync(this.filePathFor(ref), { force: true }); } catch { /* ignore */ }
      }
      this.fileRefs.delete(id);
    }
    this.persist();
  }

  /** Removes every record (and referenced file) under `accountId` whose
   * cipherId is not in `liveCipherIds` — the debris left after items are
   * deleted upstream or a sync prunes the vault. Returns the number of
   * distinct cipherIds swept. Other accounts are never touched. */
  orphanSweep(accountId: string, liveCipherIds: ReadonlySet<string>): number {
    const doomed = new Set<string>();
    for (const [id, v] of this.emails) {
      if (v.key.accountId === accountId && !liveCipherIds.has(v.key.cipherId)) doomed.add(id);
    }
    for (const [id, v] of this.totps) {
      if (v.key.accountId === accountId && !liveCipherIds.has(v.key.cipherId)) doomed.add(id);
    }
    for (const [id, v] of this.fileRefs) {
      if (v.key.accountId === accountId && !liveCipherIds.has(v.key.cipherId)) doomed.add(id);
    }
    if (doomed.size === 0) return 0;
    for (const id of doomed) {
      this.emails.delete(id);
      this.totps.delete(id);
      const bucket = this.fileRefs.get(id);
      if (bucket !== undefined) {
        for (const ref of bucket.refs) {
          try { rmSync(this.filePathFor(ref), { force: true }); } catch { /* ignore */ }
        }
        this.fileRefs.delete(id);
      }
    }
    this.persist();
    // Swift returns the number of distinct VaultRecordKeys swept.
    return doomed.size;
  }

  /** Record counts for one account (diagnostics / UI badges). */
  counts(accountId: string): { emails: number; totps: number; files: number } {
    let emails = 0, totps = 0, files = 0;
    for (const v of this.emails.values()) if (v.key.accountId === accountId) emails += 1;
    for (const v of this.totps.values()) if (v.key.accountId === accountId) totps += 1;
    for (const v of this.fileRefs.values()) if (v.key.accountId === accountId) files += v.refs.length;
    return { emails, totps, files };
  }

  // MARK: - Key rotation

  /** Re-encrypts the whole vault under a new storage key: every referenced
   * encrypted file is rekeyed (old -> new) and finally the sidecar itself
   * is rewritten under the new key.
   *
   * Failure semantics: each file rekey is individually safe (see
   * `rekeyFile`) — a file whose rekey fails keeps its old-key ciphertext.
   * If any file fails, all already-rotated files are best-effort rotated
   * back and the error is rethrown with the vault still on the old key.
   * After success the old key can no longer open the sidecar or any file,
   * and this instance uses the new key. */
  rotateStorageKey(newKeyProvider: KeyProvider): void {
    const oldKey = this.keyProvider.encryptionKey();
    const newKey = newKeyProvider.encryptionKey();
    if (oldKey.equals(newKey)) return; // Same key: nothing to do.
    const allRefs = [...this.fileRefs.values()].flatMap((v) => v.refs);
    const rotated: EncryptedFileRef[] = [];
    try {
      for (const ref of allRefs) {
        rekeyFile(this.filePathFor(ref), oldKey, newKey);
        rotated.push(ref);
      }
    } catch (e) {
      for (const ref of rotated) {
        try { rekeyFile(this.filePathFor(ref), newKey, oldKey); } catch { /* best effort */ }
      }
      throw e;
    }
    // Files are on the new key; rewrite the sidecar under it.
    const previousProvider = this.keyProvider;
    this.keyProvider = newKeyProvider;
    try {
      this.persist();
    } catch (e) {
      this.keyProvider = previousProvider;
      for (const ref of allRefs) {
        try { rekeyFile(this.filePathFor(ref), newKey, oldKey); } catch { /* best effort */ }
      }
      throw e;
    }
  }

  // MARK: - Encrypted backup (WEZBACKUP v1) — port of VaultBackup.swift
  //
  // A backup is a single JSON file holding ONE AES-256-GCM sealed payload:
  //
  //   BackupPackage (outer, plaintext JSON — metadata only, no secrets):
  //     format          "WEZBACKUP"
  //     version         1
  //     kdfSalt         base64, 16 random bytes, fresh per export
  //     kdfIterations   PBKDF2-HMAC-SHA256 iteration count actually used
  //     sealedPayload   base64 of AES.GCM combined
  //                     (nonce ‖ ciphertext ‖ tag) under the key
  //                     PBKDF2(password UTF-8, kdfSalt, kdfIterations, 32)
  //
  //   BackupPayload (the decrypted plaintext, itself JSON):
  //     manifest        counts + SHA-256 fingerprints
  //     store           the full SidecarStore (emails / TOTPs / file refs)
  //     fileBlobs       [fileId: base64 of the .wzen file bytes AS STORED]
  //                     Blobs stay encrypted under the vault storage key;
  //                     the backup password only wraps the package. After a
  //                     restore, files decrypt with the vault's current
  //                     storage key.
  //
  // Import safety: the package is decrypted and EVERY manifest fingerprint
  // and count is verified before a single byte of current vault state is
  // touched. A wrong password fails at the GCM open step
  // (`backupBadPasswordOrCorrupt`) and the live vault is provably unchanged.

  /** Exports the ENTIRE vault — all accounts' sidecar records plus every
   * referenced encrypted file blob — as one password-encrypted package. */
  exportBackup(password: string, destination: string, iterations: number = LocalDataVault.defaultBackupIterations): void {
    if (!(iterations >= 1)) throw new RangeError("PBKDF2 iterations must be >= 1");
    const store = this.snapshot();
    const blobs = new Map<string, Buffer>();
    for (const entry of store.files) {
      const path = join(this.filesDirectory, `${entry.ref.fileId}.wzen`);
      if (!existsSync(path)) throw new LocalDataVaultError("fileNotFound", entry.ref.fileId);
      try {
        blobs.set(entry.ref.fileId, readFileSync(path));
      } catch (e) {
        throw new LocalDataVaultError("ioError", `cannot read file blob ${entry.ref.fileId}: ${String(e)}`);
      }
    }

    const storeData = Buffer.from(canonicalJSON(storeToJSON(store)), "utf8");
    const fingerprints: Record<string, string> = {};
    for (const [fileId, blob] of blobs) fingerprints[fileId] = sha256Hex(blob);
    const manifest: Record<string, unknown> = {
      formatVersion: LocalDataVault.backupFormatVersion,
      schemaVersion: store.schemaVersion,
      createdAt: iso8601NoFraction(new Date()),
      emailCount: store.emails.length,
      totpCount: store.totps.length,
      fileCount: store.files.length,
      storeSHA256: sha256Hex(storeData),
      fileFingerprints: fingerprints,
    };
    const fileBlobs: Record<string, unknown> = {};
    for (const [fileId, blob] of blobs) fileBlobs[fileId] = blob;
    const payloadData = Buffer.from(
      canonicalJSON({ manifest, store: storeToJSON(store), fileBlobs }),
      "utf8",
    );

    const salt = randomBytes(16);
    const key = deriveKeySHA256(password, salt, iterations, 32);
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const sealed = Buffer.concat([cipher.update(payloadData), cipher.final()]);
    const combined = Buffer.concat([nonce, sealed, cipher.getAuthTag()]);
    const pkg: Record<string, unknown> = {
      format: LocalDataVault.backupFormat,
      version: LocalDataVault.backupFormatVersion,
      kdfSalt: salt,
      kdfIterations: iterations,
      sealedPayload: combined,
    };
    try {
      // Swift writes atomically; write-then-rename mirrors that.
      const tmp = destination + ".tmp-" + randomUUID();
      writeFileSync(tmp, Buffer.from(canonicalJSON(pkg), "utf8"));
      renameSync(tmp, destination);
    } catch (e) {
      throw new LocalDataVaultError("ioError", `cannot write backup: ${String(e)}`);
    }
  }

  /** Restores a package produced by `exportBackup`.
   *
   * Verification order (all BEFORE any mutation of current state):
   * package format -> PBKDF2 + AES-GCM open (wrong password throws
   * `backupBadPasswordOrCorrupt`) -> manifest counts match the payload ->
   * store fingerprint matches -> every blob fingerprint matches ->
   * every file reference has a blob and vice versa -> schema is
   * migratable. Only then are blobs written and records replaced. */
  importBackup(password: string, source: string): void {
    let packageData: Buffer;
    try {
      packageData = readFileSync(source);
    } catch (e) {
      throw new LocalDataVaultError("ioError", `cannot read backup: ${String(e)}`);
    }
    let pkg: Record<string, unknown>;
    try {
      pkg = JSON.parse(packageData.toString("utf8")) as Record<string, unknown>;
    } catch {
      throw new LocalDataVaultError("backupFormatInvalid", "package is not a WEZBACKUP JSON document");
    }
    if (pkg.format !== LocalDataVault.backupFormat || pkg.version !== LocalDataVault.backupFormatVersion) {
      throw new LocalDataVaultError("backupFormatInvalid", "format/version mismatch");
    }
    const kdfIterations = pkg.kdfIterations as number;
    if (!(kdfIterations >= 1)) {
      throw new LocalDataVaultError("backupFormatInvalid", "invalid kdfIterations");
    }
    const kdfSalt = Buffer.from(pkg.kdfSalt as string, "base64");
    const sealedPayload = Buffer.from(pkg.sealedPayload as string, "base64");
    const key = deriveKeySHA256(password, kdfSalt, kdfIterations, 32);
    let payloadData: Buffer;
    try {
      if (sealedPayload.length < 12 + 16) throw new Error("sealed payload too short");
      const nonce = sealedPayload.subarray(0, 12);
      const tag = sealedPayload.subarray(sealedPayload.length - 16);
      const cipher = sealedPayload.subarray(12, sealedPayload.length - 16);
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(nonce));
      decipher.setAuthTag(Buffer.from(tag));
      payloadData = Buffer.concat([decipher.update(Buffer.from(cipher)), decipher.final()]);
    } catch {
      // Wrong password OR any tampering: one error, no information leak.
      throw new LocalDataVaultError("backupBadPasswordOrCorrupt");
    }
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(payloadData.toString("utf8")) as Record<string, unknown>;
    } catch {
      throw new LocalDataVaultError("backupFormatInvalid", "payload undecodable");
    }
    const manifest = payload.manifest as Record<string, unknown>;
    // Swift decodes the payload with the .iso8601 date strategy, so an
    // unparseable manifest.createdAt fails HERE as "payload undecodable",
    // before any fingerprint verification.
    try {
      parseISO8601(manifest.createdAt as string);
    } catch {
      throw new LocalDataVaultError("backupFormatInvalid", "payload undecodable");
    }
    const rawStore = payload.store as Record<string, unknown>;
    const rawBlobs = payload.fileBlobs as Record<string, unknown>;
    const store = storeFromJSON(rawStore);
    const blobs = new Map<string, Buffer>();
    for (const [fileId, b64] of Object.entries(rawBlobs)) {
      blobs.set(fileId, Buffer.from(b64 as string, "base64"));
    }

    // ---- Full verification, still zero mutation ----
    if (manifest.formatVersion !== LocalDataVault.backupFormatVersion) {
      throw new LocalDataVaultError("backupFormatInvalid", "manifest version mismatch");
    }
    if (
      manifest.emailCount !== store.emails.length ||
      manifest.totpCount !== store.totps.length ||
      manifest.fileCount !== store.files.length
    ) {
      throw new LocalDataVaultError("backupFingerprintMismatch", "manifest counts do not match payload");
    }
    const storeData = Buffer.from(canonicalJSON(storeToJSON(store)), "utf8");
    if (sha256Hex(storeData) !== manifest.storeSHA256) {
      throw new LocalDataVaultError("backupFingerprintMismatch", "store fingerprint mismatch");
    }
    const referencedIds = new Set(store.files.map((f) => f.ref.fileId));
    const manifestFingerprints = manifest.fileFingerprints as Record<string, string>;
    const sameSet = (a: ReadonlySet<string>, b: ReadonlySet<string>) =>
      a.size === b.size && [...a].every((x) => b.has(x));
    if (!sameSet(new Set(blobs.keys()), referencedIds) || !sameSet(new Set(Object.keys(manifestFingerprints)), referencedIds)) {
      throw new LocalDataVaultError("backupFingerprintMismatch", "blob set does not match file references");
    }
    for (const [fileId, blob] of blobs) {
      if (manifestFingerprints[fileId] !== sha256Hex(blob)) {
        throw new LocalDataVaultError("backupFingerprintMismatch", `blob fingerprint mismatch for ${fileId}`);
      }
    }
    const migrated = LocalDataVault.migrateStore(store);

    // ---- Verified: apply atomically-ish (blobs first, records last) ----
    for (const [fileId, blob] of blobs) {
      const path = join(this.filesDirectory, `${fileId}.wzen`);
      try {
        const tmp = path + ".tmp-" + randomUUID();
        writeFileSync(tmp, blob);
        renameSync(tmp, path);
      } catch (e) {
        throw new LocalDataVaultError("ioError", `cannot restore file blob ${fileId}: ${String(e)}`);
      }
    }
    const newEmails = new Map<string, { key: VaultRecordKey; email: string }>();
    const newTotps = new Map<string, { key: VaultRecordKey; record: TOTPSecretRecord }>();
    const newFiles = new Map<string, { key: VaultRecordKey; refs: EncryptedFileRef[] }>();
    for (const e of migrated.emails) {
      const key = { accountId: e.accountId, cipherId: e.cipherId };
      newEmails.set(keyId(key), { key, email: e.email });
    }
    for (const t of migrated.totps) {
      const key = { accountId: t.accountId, cipherId: t.cipherId };
      newTotps.set(keyId(key), { key, record: t.record });
    }
    for (const f of migrated.files) {
      const key = { accountId: f.accountId, cipherId: f.cipherId };
      const id = keyId(key);
      const bucket = newFiles.get(id) ?? { key, refs: [] };
      bucket.refs.push(f.ref);
      newFiles.set(id, bucket);
    }
    this.emails = newEmails;
    this.totps = newTotps;
    this.fileRefs = newFiles;
    this.persist();
  }
}
