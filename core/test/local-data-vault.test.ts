import { afterEach, beforeEach, describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  LocalDataVault,
  LocalDataVaultError,
  totpRecordCurrentCode,
  totpSecretRecord,
  type TOTPSecretRecord,
} from "../src/local-data-vault.js";
import {
  encryptFile,
  EncryptedFileError,
  InMemoryKeyProvider,
  rekeyFile,
} from "../src/local-encrypted-storage.js";
import { Base32, OTPGenerator } from "../src/local-totp.js";
import { canonicalJSON } from "../src/canonical-json.js";
import { deriveKeySHA256 } from "../src/pbkdf2.js";

let dir = "";
const keyA = new InMemoryKeyProvider(Buffer.from(Array.from({ length: 32 }, (_, i) => i)));
const keyB = new InMemoryKeyProvider(Buffer.from(Array.from({ length: 32 }, (_, i) => 255 - i)));

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ldv-test-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function makeVault(key: InMemoryKeyProvider = keyA): LocalDataVault {
  return new LocalDataVault(dir, key);
}
function makePlaintext(name: string, contents: string): string {
  const url = join(dir, name);
  writeFileSync(url, Buffer.from(contents, "utf8"));
  return url;
}
const sampleTOTP: TOTPSecretRecord = totpSecretRecord({
  secretBase32: "JBSWY3DPEHPK3PXP",
  issuer: "Example",
  accountName: "user@example.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
});

describe("LocalDataVault", () => {
  it("testEmailSetGetAndPersistenceAcrossReopen", () => {
    const vault = makeVault();
    vault.setEmail("extra@example.com", "acct1", "cipher1");
    assert.equal(vault.email("acct1", "cipher1"), "extra@example.com");
    assert.equal(vault.email("acct1", "other"), null);
    // Re-login / app update simulation: a fresh instance over the same
    // directory must see everything.
    const reopened = makeVault();
    assert.equal(reopened.email("acct1", "cipher1"), "extra@example.com");
    // On-disk sidecar is ciphertext, not JSON: the plaintext email must
    // not appear anywhere in the raw sidecar bytes.
    const raw = readFileSync(join(dir, "vault-sidecar.wzen"));
    assert.equal(raw.toString("utf8").includes("extra@example.com"), false);
  });

  it("testAccountIsolationWithSameCipherId", () => {
    const vault = makeVault();
    vault.setEmail("a@example.com", "A", "shared-id");
    vault.setEmail("b@example.com", "B", "shared-id");
    vault.setTOTP(sampleTOTP, "A", "shared-id");
    assert.equal(vault.email("A", "shared-id"), "a@example.com");
    assert.equal(vault.email("B", "shared-id"), "b@example.com");
    assert.notEqual(vault.totpRecord("A", "shared-id"), null);
    assert.equal(vault.totpRecord("B", "shared-id"), null);
    // Deleting A's cipher must not touch B's records under the same id.
    vault.deleteCipher("A", "shared-id");
    assert.equal(vault.email("A", "shared-id"), null);
    assert.equal(vault.email("B", "shared-id"), "b@example.com");
  });

  it("testTOTPRecordRoundtripAndCodeGeneration", () => {
    const vault = makeVault();
    vault.setTOTP(sampleTOTP, "acct1", "cipher1");
    const reopened = makeVault();
    const record = reopened.totpRecord("acct1", "cipher1");
    assert.deepEqual(record, sampleTOTP);
    // The stored record generates the same code as the raw LocalTOTP API.
    const secret = Base32.decode("JBSWY3DPEHPK3PXP");
    const expected = OTPGenerator.totp(secret, 59_000, 30, 6, "SHA1");
    assert.equal(totpRecordCurrentCode(record as TOTPSecretRecord, 59_000), expected);
    assert.equal(expected.length, 6);
  });

  it("testFileStoreRefFingerprintAndDecrypt", () => {
    const vault = makeVault();
    const plain = makePlaintext("note.txt", "top secret contents");
    const ref = vault.storeFile(plain, "acct1", "cipher1");
    assert.equal(ref.name, "note.txt");
    assert.equal(ref.size, Buffer.from("top secret contents", "utf8").length);
    const expectedSHA = createHash("sha256").update(Buffer.from("top secret contents", "utf8")).digest("hex");
    assert.equal(ref.sha256, expectedSHA);
    assert.deepEqual(vault.fileRefsFor("acct1", "cipher1"), [ref]);
    assert.ok(vault.decryptedData(ref).equals(Buffer.from("top secret contents", "utf8")));
    // The stored file on disk is a WZEN ciphertext container.
    const stored = readFileSync(join(dir, "files", `${ref.fileId}.wzen`));
    assert.ok(stored.subarray(0, 4).equals(Buffer.from("WZEN", "utf8")));
    assert.equal(stored.toString("utf8").includes("top secret"), false);
  });

  it("testDeleteCipherCascadesRecordsAndFiles", () => {
    const vault = makeVault();
    vault.setEmail("x@example.com", "acct1", "c1");
    vault.setTOTP(sampleTOTP, "acct1", "c1");
    const plain = makePlaintext("a.bin", "payload");
    const ref = vault.storeFile(plain, "acct1", "c1");
    const fileOnDisk = join(dir, "files", `${ref.fileId}.wzen`);
    assert.equal(existsSync(fileOnDisk), true);

    vault.deleteCipher("acct1", "c1");
    assert.equal(vault.email("acct1", "c1"), null);
    assert.equal(vault.totpRecord("acct1", "c1"), null);
    assert.deepEqual(vault.fileRefsFor("acct1", "c1"), []);
    assert.equal(existsSync(fileOnDisk), false);
    const counts = vault.counts("acct1");
    assert.deepEqual(counts, { emails: 0, totps: 0, files: 0 });
    // The cascade is persisted, not just in memory.
    const reopened = makeVault();
    assert.equal(reopened.email("acct1", "c1"), null);
  });

  it("testOrphanSweepRemovesOnlyDeadCiphersOfThatAccount", () => {
    const vault = makeVault();
    for (const cid of ["live1", "dead1", "dead2"]) {
      vault.setEmail(`${cid}@example.com`, "acct1", cid);
    }
    vault.setEmail("dead1@b.example", "acct2", "dead1");
    const plain = makePlaintext("s.bin", "sweep me");
    const ref = vault.storeFile(plain, "acct1", "dead2");
    const fileOnDisk = join(dir, "files", `${ref.fileId}.wzen`);

    const swept = vault.orphanSweep("acct1", new Set(["live1"]));
    assert.equal(swept, 2);
    assert.equal(vault.email("acct1", "live1"), "live1@example.com");
    assert.equal(vault.email("acct1", "dead1"), null);
    assert.equal(existsSync(fileOnDisk), false);
    // Account 2's record under an identical cipherId is untouched.
    assert.equal(vault.email("acct2", "dead1"), "dead1@b.example");
    // Sweeping again is a no-op.
    assert.equal(vault.orphanSweep("acct1", new Set(["live1"])), 0);
  });

  it("testUnsupportedSchemaVersionIsRejectedNotDropped", () => {
    const vault = makeVault();
    vault.setEmail("keep@example.com", "acct1", "c1");
    // Hand-craft a sidecar with a future schema version, encrypted with
    // the correct key, and swap it in.
    const future = { schemaVersion: 99, emails: [], totps: [], files: [] };
    const plainTmp = join(dir, "future.json");
    const encTmp = join(dir, "future.wzen");
    writeFileSync(plainTmp, Buffer.from(canonicalJSON(future), "utf8"));
    encryptFile(plainTmp, encTmp, keyA.encryptionKey());
    const sidecar = join(dir, "vault-sidecar.wzen");
    rmSync(sidecar, { force: true });
    copyFileSync(encTmp, sidecar);
    assert.throws(
      () => makeVault(),
      (e: unknown) =>
        e instanceof LocalDataVaultError && e.code === "unsupportedSchemaVersion" && e.detail === 99,
    );
  });

  it("testWrongKeyCannotOpenVault", () => {
    const vault = makeVault();
    vault.setEmail("x@example.com", "acct1", "c1");
    assert.throws(
      () => makeVault(keyB),
      (e: unknown) => e instanceof EncryptedFileError && e.code === "authenticationFailed",
    );
  });

  it("testKeyRotationOldKeyFailsNewKeyReadsEverything", () => {
    const vault = makeVault();
    vault.setEmail("rot@example.com", "acct1", "c1");
    vault.setTOTP(sampleTOTP, "acct1", "c1");
    const plain = makePlaintext("rot.bin", "rotate this payload");
    const ref = vault.storeFile(plain, "acct1", "c1");

    vault.rotateStorageKey(keyB);
    // Same instance now works on the new key.
    assert.ok(vault.decryptedData(ref).equals(Buffer.from("rotate this payload", "utf8")));
    // Old key can no longer open the vault at all.
    assert.throws(() => makeVault(keyA));
    // New key opens it and every record/file survived.
    const rotated = makeVault(keyB);
    assert.equal(rotated.email("acct1", "c1"), "rot@example.com");
    assert.deepEqual(rotated.totpRecord("acct1", "c1"), sampleTOTP);
    assert.ok(rotated.decryptedData(ref).equals(Buffer.from("rotate this payload", "utf8")));
  });

  it("testRekeyFileWithWrongOldKeyLeavesOriginalUntouched", () => {
    const vault = makeVault();
    const plain = makePlaintext("k.bin", "original bytes");
    const ref = vault.storeFile(plain, "acct1", "c1");
    const stored = join(dir, "files", `${ref.fileId}.wzen`);
    const before = readFileSync(stored);
    assert.throws(() =>
      rekeyFile(stored, keyB.encryptionKey(), keyB.encryptionKey()),
    );
    assert.ok(readFileSync(stored).equals(before));
    assert.ok(vault.decryptedData(ref).equals(Buffer.from("original bytes", "utf8")));
  });

  it("testPBKDF2KnownVectors", () => {
    // RFC-style published PBKDF2-HMAC-SHA256 vectors, dkLen 32.
    assert.equal(
      deriveKeySHA256("password", Buffer.from("salt", "utf8"), 1).toString("hex"),
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    );
    assert.equal(
      deriveKeySHA256("password", Buffer.from("salt", "utf8"), 2).toString("hex"),
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
    );
    assert.equal(
      deriveKeySHA256("password", Buffer.from("salt", "utf8"), 4096).toString("hex"),
      "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
    );
  });

  function populate(vault: LocalDataVault) {
    vault.setEmail("backup@example.com", "acct1", "c1");
    vault.setTOTP(sampleTOTP, "acct1", "c1");
    const plain = makePlaintext("doc.txt", "backup file body");
    return vault.storeFile(plain, "acct1", "c1");
  }

  it("testBackupRoundtripAfterFullWipe", () => {
    const vault = makeVault();
    const ref = populate(vault);
    const backupPath = join(dir, "backup.wezbackup");
    vault.exportBackup("correct horse battery staple", backupPath, 1_000);
    // The backup file itself must not leak plaintext records.
    const backupRaw = readFileSync(backupPath);
    assert.equal(backupRaw.toString("utf8").includes("backup@example.com"), false);

    // Full wipe: remove the vault directory contents, recreate fresh.
    const backupCopy = join(tmpdir(), `bk-${Date.now()}-${Math.floor(Math.random() * 1e9)}.wezbackup`);
    copyFileSync(backupPath, backupCopy);
    rmSync(dir, { recursive: true, force: true });
    const fresh = new LocalDataVault(dir, keyA);
    assert.equal(fresh.email("acct1", "c1"), null);
    fresh.importBackup("correct horse battery staple", backupCopy);
    assert.equal(fresh.email("acct1", "c1"), "backup@example.com");
    assert.deepEqual(fresh.totpRecord("acct1", "c1"), sampleTOTP);
    assert.deepEqual(fresh.fileRefsFor("acct1", "c1"), [ref]);
    // The restored blob decrypts with the vault's current storage key.
    assert.ok(fresh.decryptedData(ref).equals(Buffer.from("backup file body", "utf8")));
    // And everything survives a reopen.
    const reopened = makeVault();
    assert.equal(reopened.email("acct1", "c1"), "backup@example.com");
    rmSync(backupCopy, { force: true });
  });

  it("testBackupWrongPasswordFailsAndLeavesCurrentDataUntouched", () => {
    const vault = makeVault();
    populate(vault);
    const backupPath = join(dir, "backup.wezbackup");
    vault.exportBackup("right-password", backupPath, 1_000);
    // Change current data after the export.
    vault.setEmail("current@example.com", "acct9", "c9");

    assert.throws(
      () => vault.importBackup("wrong-password", backupPath),
      (e: unknown) =>
        e instanceof LocalDataVaultError && e.code === "backupBadPasswordOrCorrupt",
    );
    // Nothing was restored, nothing was lost.
    assert.equal(vault.email("acct9", "c9"), "current@example.com");
    assert.equal(vault.email("acct1", "c1"), "backup@example.com");
    assert.equal(vault.counts("acct1").files, 1);
    const reopened = makeVault();
    assert.equal(reopened.email("acct9", "c9"), "current@example.com");
  });
});
