import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import {
  createRecoveryPackage,
  EmergencyRecoveryError,
  exportRecoveryPackage,
  importRecoveryPackage,
  recoverVaultKey,
} from "../src/emergency-recovery.js";
import { generateX25519KeyPair } from "../src/x25519-raw.js";

describe("EmergencyRecovery", () => {
  it("testRoundtrip", () => {
    const recipient = generateX25519KeyPair();
    const vaultKey = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 7) % 256));
    const pkg = createRecoveryPackage(vaultKey, recipient.publicKey, "Family Emergency Contact");
    assert.equal(pkg.version, 1);
    assert.equal(pkg.ownerLabel, "Family Emergency Contact");
    assert.equal(pkg.ephemeralPublicKey.length, 32);
    assert.equal(pkg.salt.length, 32);
    assert.equal(pkg.nonce.length, 12);
    const recovered = recoverVaultKey(pkg, recipient.privateKey);
    assert.ok(recovered.equals(vaultKey));
  });

  it("testPackageCodableRoundtrip", () => {
    const recipient = generateX25519KeyPair();
    const vaultKey = Buffer.alloc(32, 0xab);
    const pkg = createRecoveryPackage(vaultKey, recipient.publicKey, "x");
    const decoded = importRecoveryPackage(exportRecoveryPackage(pkg));
    assert.equal(decoded.version, pkg.version);
    assert.equal(decoded.ownerLabel, pkg.ownerLabel);
    assert.ok(decoded.ephemeralPublicKey.equals(pkg.ephemeralPublicKey));
    assert.ok(decoded.salt.equals(pkg.salt));
    assert.ok(decoded.nonce.equals(pkg.nonce));
    assert.ok(decoded.ciphertext.equals(pkg.ciphertext));
    assert.equal(decoded.createdAt.getTime(), Math.floor(pkg.createdAt.getTime() / 1000) * 1000);
    assert.ok(recoverVaultKey(decoded, recipient.privateKey).equals(vaultKey));
  });

  it("testWrongPrivateKeyFails", () => {
    const recipient = generateX25519KeyPair();
    const stranger = generateX25519KeyPair();
    const pkg = createRecoveryPackage(Buffer.alloc(32, 1), recipient.publicKey, "x");
    assert.throws(
      () => recoverVaultKey(pkg, stranger.privateKey),
      (e: unknown) => e instanceof EmergencyRecoveryError && e.code === "decryptionFailed",
    );
  });

  it("testTamperedCiphertextFails", () => {
    const recipient = generateX25519KeyPair();
    const pkg = createRecoveryPackage(Buffer.alloc(32, 2), recipient.publicKey, "x");
    const ct = Buffer.from(pkg.ciphertext);
    ct[0] ^= 0xff;
    assert.throws(() => recoverVaultKey({ ...pkg, ciphertext: ct }, recipient.privateKey));
  });
});
