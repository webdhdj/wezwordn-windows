import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { hkdfSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveKeySHA256 } from "../src/pbkdf2.js";
import { OTPGenerator, type OTPAlgorithm } from "../src/local-totp.js";
import { decryptFile, encryptFile } from "../src/local-encrypted-storage.js";
import { privateKeyFromRaw, publicKeyFromRaw, rawPrivateKey, rawPublicKey } from "../src/x25519-raw.js";
import { diffieHellman } from "node:crypto";

interface Vectors {
  pbkdf2HmacSha256: { password: string; saltHex: string; iterations: number; dkLen: number; expectedHex: string }[];
  totpRfc6238: {
    secretAscii: string;
    algorithm: OTPAlgorithm;
    period: number;
    digits: number;
    vectors: { timeSeconds: number; expected: string }[];
  }[];
  x25519Rfc7748: {
    alicePrivateHex: string; alicePublicHex: string;
    bobPrivateHex: string; bobPublicHex: string; sharedSecretHex: string;
  };
  hkdfSha256Rfc5869Case1: { ikmHex: string; saltHex: string; infoHex: string; length: number; okmHex: string };
  wzenV1: {
    name: string; keyHex: string; baseNonceHex: string; chunkSize: number;
    plaintextHex?: string; plaintextPattern?: { kind: string; length: number };
    plaintextSha256: string; fileHex: string; fileSha256: string;
  }[];
}

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const vectors = JSON.parse(
  readFileSync(join(root, "vectors", "cross-platform.json"), "utf8"),
) as Vectors;

describe("CrossPlatformVectors (vectors/cross-platform.json)", () => {
  it("PBKDF2-HMAC-SHA256 vectors", () => {
    for (const v of vectors.pbkdf2HmacSha256) {
      const out = deriveKeySHA256(v.password, Buffer.from(v.saltHex, "hex"), v.iterations, v.dkLen);
      assert.equal(out.toString("hex"), v.expectedHex);
    }
  });

  it("TOTP RFC 6238 vectors", () => {
    for (const set of vectors.totpRfc6238) {
      const secret = Buffer.from(set.secretAscii, "utf8");
      for (const v of set.vectors) {
        assert.equal(
          OTPGenerator.totp(secret, v.timeSeconds * 1000, set.period, set.digits, set.algorithm),
          v.expected,
        );
      }
    }
  });

  it("X25519 RFC 7748 vectors", () => {
    const x = vectors.x25519Rfc7748;
    const alicePriv = privateKeyFromRaw(Buffer.from(x.alicePrivateHex, "hex"));
    const alicePub = publicKeyFromRaw(Buffer.from(x.alicePublicHex, "hex"));
    const bobPriv = privateKeyFromRaw(Buffer.from(x.bobPrivateHex, "hex"));
    const bobPub = publicKeyFromRaw(Buffer.from(x.bobPublicHex, "hex"));
    assert.equal(rawPrivateKey(alicePriv).toString("hex"), x.alicePrivateHex);
    assert.equal(rawPublicKey(alicePub).toString("hex"), x.alicePublicHex);
    assert.equal(rawPublicKey(bobPub).toString("hex"), x.bobPublicHex);
    const shared = diffieHellman({ privateKey: alicePriv, publicKey: bobPub });
    assert.equal(shared.toString("hex"), x.sharedSecretHex);
    const shared2 = diffieHellman({ privateKey: bobPriv, publicKey: alicePub });
    assert.ok(shared2.equals(shared));
  });

  it("HKDF-SHA256 RFC 5869 test case 1", () => {
    const v = vectors.hkdfSha256Rfc5869Case1;
    const okm = hkdfSync(
      "sha256",
      Buffer.from(v.ikmHex, "hex"),
      Buffer.from(v.saltHex, "hex"),
      Buffer.from(v.infoHex, "hex"),
      v.length,
    );
    assert.equal(Buffer.from(okm).toString("hex"), v.okmHex);
  });

  it("WZEN v1 fixed vectors are byte-exact", () => {
    const dir = mkdtempSync(join(tmpdir(), "wzen-vec-"));
    try {
      for (const v of vectors.wzenV1) {
        const key = Buffer.from(v.keyHex, "hex");
        const baseNonce = Buffer.from(v.baseNonceHex, "hex");
        let plaintext: Buffer;
        if (v.plaintextHex !== undefined) {
          plaintext = Buffer.from(v.plaintextHex, "hex");
        } else {
          const len = (v.plaintextPattern as { length: number }).length;
          plaintext = Buffer.alloc(len);
          for (let i = 0; i < len; i++) plaintext[i] = i % 251;
        }
        const src = join(dir, "p.bin");
        const enc = join(dir, "p.wzen");
        const dec = join(dir, "p.out");
        writeFileSync(src, plaintext);
        encryptFile(src, enc, key, { chunkSize: v.chunkSize, baseNonceForTesting: baseNonce });
        assert.equal(readFileSync(enc).toString("hex"), v.fileHex, v.name);
        // And the recorded bytes decrypt back to the recorded plaintext.
        writeFileSync(enc, Buffer.from(v.fileHex, "hex"));
        decryptFile(enc, dec, key);
        assert.ok(readFileSync(dec).equals(plaintext), v.name);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
