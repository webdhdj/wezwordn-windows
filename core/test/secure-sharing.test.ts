import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import {
  createSharePackage,
  exportSharePackage,
  importSharePackage,
  openSharePackage,
  SecureSharingError,
  shareableItem,
  shareFingerprintIsValid,
} from "../src/secure-sharing.js";
import { generateX25519KeyPair } from "../src/x25519-raw.js";

const sample = shareableItem({
  title: "Example Login",
  username: "wesam",
  email: "wesam@example.com",
  password: "s3cret!",
  notes: "note",
  url: "https://example.com",
});

describe("SecureSharing", () => {
  it("testRoundtrip", () => {
    const recipient = generateX25519KeyPair();
    const pkg = createSharePackage(sample, recipient.publicKey);
    assert.equal(shareFingerprintIsValid(pkg), true);
    assert.equal(pkg.fingerprint.length, 64);
    const opened = openSharePackage(pkg, recipient.privateKey);
    assert.deepEqual(opened, sample);
  });

  it("testExportImportWezshareData", () => {
    const recipient = generateX25519KeyPair();
    // Whole-second date: .wezshare JSON uses ISO-8601 (second precision),
    // so a sub-second createdAt would not compare equal after roundtrip.
    const pkg = createSharePackage(sample, recipient.publicKey, new Date(1_700_000_000_000));
    const data = exportSharePackage(pkg);
    const imported = importSharePackage(data);
    assert.equal(imported.version, pkg.version);
    assert.ok(imported.ephemeralPublicKey.equals(pkg.ephemeralPublicKey));
    assert.ok(imported.salt.equals(pkg.salt));
    assert.ok(imported.nonce.equals(pkg.nonce));
    assert.ok(imported.ciphertext.equals(pkg.ciphertext));
    assert.equal(imported.createdAt.getTime(), pkg.createdAt.getTime());
    assert.equal(imported.fingerprint, pkg.fingerprint);
    assert.deepEqual(openSharePackage(imported, recipient.privateKey), sample);
  });

  it("testTamperFailsFingerprintOrDecryption", () => {
    const recipient = generateX25519KeyPair();
    const pkg = createSharePackage(sample, recipient.publicKey);
    const ct = Buffer.from(pkg.ciphertext);
    ct[ct.length - 1] ^= 0xff;
    const tampered = { ...pkg, ciphertext: ct };
    assert.equal(shareFingerprintIsValid(tampered), false);
    assert.throws(
      () => openSharePackage(tampered, recipient.privateKey),
      (e: unknown) => e instanceof SecureSharingError && e.code === "fingerprintMismatch",
    );
  });

  it("testWrongRecipientFails", () => {
    const recipient = generateX25519KeyPair();
    const stranger = generateX25519KeyPair();
    const pkg = createSharePackage(sample, recipient.publicKey);
    assert.throws(
      () => openSharePackage(pkg, stranger.privateKey),
      (e: unknown) => e instanceof SecureSharingError && e.code === "decryptionFailed",
    );
  });
});
