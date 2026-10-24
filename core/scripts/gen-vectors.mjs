#!/usr/bin/env node
/**
 * Regenerates vectors/cross-platform.json from the built port (dist/).
 *
 * Every entry is either (a) a published constant (RFC 6238 / RFC 5869 /
 * RFC 7748 / PBKDF2 KATs) that the implementation must reproduce — asserted
 * here before writing — or (b) a WZEN v1 byte-exact vector produced with a
 * fixed key and baseNonce through the test-only baseNonce hook, so any
 * conforming implementation (Swift or TS) can verify byte-for-byte.
 *
 * Run: npm run build && node scripts/gen-vectors.mjs
 */
import { createHash, createHmac, createPublicKey, hkdfSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveKeySHA256 } from "../dist/src/pbkdf2.js";
import { OTPGenerator } from "../dist/src/local-totp.js";
import { encryptFile } from "../dist/src/local-encrypted-storage.js";
import { privateKeyFromRaw, rawPublicKey } from "../dist/src/x25519-raw.js";
import { diffieHellman } from "node:crypto";

const assert = (cond, msg) => {
  if (!cond) throw new Error(`vector assertion failed: ${msg}`);
};
const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");

// ---------- PBKDF2-HMAC-SHA256 KATs ----------
const pbkdf2 = [
  { password: "password", salt: "salt", iterations: 1, expected: "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" },
  { password: "password", salt: "salt", iterations: 2, expected: "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43" },
  { password: "password", salt: "salt", iterations: 4096, expected: "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a" },
];
for (const v of pbkdf2) {
  const out = deriveKeySHA256(v.password, Buffer.from(v.salt, "utf8"), v.iterations, 32).toString("hex");
  assert(out === v.expected, `PBKDF2 c=${v.iterations}`);
}

// ---------- TOTP RFC 6238 ----------
const totpSets = [
  { secretAscii: "12345678901234567890", algorithm: "SHA1", values: [[59, "94287082"], [1111111109, "07081804"], [1111111111, "14050471"], [1234567890, "89005924"], [2000000000, "69279037"], [20000000000, "65353130"]] },
  { secretAscii: "12345678901234567890123456789012", algorithm: "SHA256", values: [[59, "46119246"], [1111111109, "68084774"], [1111111111, "67062674"], [1234567890, "91819424"], [2000000000, "90698825"], [20000000000, "77737706"]] },
  { secretAscii: "1234567890123456789012345678901234567890123456789012345678901234", algorithm: "SHA512", values: [[59, "90693936"], [1111111109, "25091201"], [1111111111, "99943326"], [1234567890, "93441116"], [2000000000, "38618901"], [20000000000, "47863826"]] },
];
for (const s of totpSets) {
  const secret = Buffer.from(s.secretAscii, "utf8");
  for (const [t, expected] of s.values) {
    assert(OTPGenerator.totp(secret, t * 1000, 30, 8, s.algorithm) === expected, `TOTP ${s.algorithm} t=${t}`);
  }
}

// ---------- X25519 RFC 7748 ----------
const x = {
  alicePrivateHex: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  alicePublicHex: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  bobPrivateHex: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  bobPublicHex: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  sharedSecretHex: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
};
{
  const alicePriv = privateKeyFromRaw(Buffer.from(x.alicePrivateHex, "hex"));
  const derivedPub = rawPublicKey(createPublicKey(alicePriv)).toString("hex");
  assert(derivedPub === x.alicePublicHex, "X25519 Alice private->public");
  const bobPriv = privateKeyFromRaw(Buffer.from(x.bobPrivateHex, "hex"));
  assert(rawPublicKey(createPublicKey(bobPriv)).toString("hex") === x.bobPublicHex, "X25519 Bob private->public");
  const { publicKeyFromRaw } = await import("../dist/src/x25519-raw.js");
  const shared = diffieHellman({ privateKey: alicePriv, publicKey: publicKeyFromRaw(Buffer.from(x.bobPublicHex, "hex")) });
  assert(shared.toString("hex") === x.sharedSecretHex, "X25519 shared secret");
}

// ---------- HKDF-SHA256 RFC 5869 test case 1 ----------
// Manual extract+expand cross-check against hkdfSync AND the RFC constant.
const hkdfCase = {
  ikmHex: "0b".repeat(22),
  saltHex: "000102030405060708090a0b0c",
  infoHex: "f0f1f2f3f4f5f6f7f8f9",
  length: 42,
  okmHex: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
};
{
  const ikm = Buffer.from(hkdfCase.ikmHex, "hex");
  const salt = Buffer.from(hkdfCase.saltHex, "hex");
  const info = Buffer.from(hkdfCase.infoHex, "hex");
  const prk = createHmac("sha256", salt).update(ikm).digest();
  const blocks = [];
  let prev = Buffer.alloc(0);
  let produced = 0;
  for (let i = 1; produced < hkdfCase.length; i++) {
    prev = createHmac("sha256", prk).update(Buffer.concat([prev, info, Buffer.from([i])])).digest();
    blocks.push(prev);
    produced += prev.length;
  }
  const manual = Buffer.concat(blocks).subarray(0, hkdfCase.length);
  const viaNode = Buffer.from(hkdfSync("sha256", ikm, salt, info, hkdfCase.length));
  assert(manual.equals(viaNode), "HKDF manual vs hkdfSync");
  assert(manual.toString("hex") === hkdfCase.okmHex, "HKDF RFC 5869 case 1 OKM");
}

// ---------- WZEN v1 fixed vectors ----------
const dir = mkdtempSync(join(tmpdir(), "wzen-gen-"));
const wzen = [];
try {
  const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const baseNonce = Buffer.from("000102030405060708090a0b", "hex");
  const cases = [
    { name: "small-100B-chunk1024", chunkSize: 1024, length: 100, fullHex: true },
    { name: "multi-chunk-10000B-chunk1024", chunkSize: 1024, length: 10000, fullHex: true },
    { name: "empty-chunk1024", chunkSize: 1024, length: 0, fullHex: true },
  ];
  for (const c of cases) {
    const plain = Buffer.alloc(c.length);
    for (let i = 0; i < c.length; i++) plain[i] = i % 251;
    const src = join(dir, "p.bin");
    const enc = join(dir, "p.wzen");
    writeFileSync(src, plain);
    encryptFile(src, enc, key, { chunkSize: c.chunkSize, baseNonceForTesting: baseNonce });
    const fileBytes = readFileSync(enc);
    wzen.push({
      name: c.name,
      keyHex: key.toString("hex"),
      baseNonceHex: baseNonce.toString("hex"),
      chunkSize: c.chunkSize,
      ...(c.length <= 100
        ? { plaintextHex: plain.toString("hex") }
        : { plaintextPattern: { kind: "byte[i] = i % 251", length: c.length } }),
      plaintextSha256: sha256hex(plain),
      fileHex: fileBytes.toString("hex"),
      fileSha256: sha256hex(fileBytes),
    });
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

const out = {
  format: "wezwordn-cross-platform-vectors",
  version: 1,
  generatedBy: "wezwordn-windows/core scripts/gen-vectors.mjs (TypeScript port, Node 24)",
  sourceOfTruth: "WezWordnCore Swift semantics; formats WZEN v1 / WEZBACKUP v1 / .wezshare v1",
  notes: [
    "EmergencyRecovery and SecureSharing packages use ephemeral X25519 keys, so no fixed package bytes exist; they are pinned down by the X25519 + HKDF vectors below plus roundtrip/tamper tests.",
    "WZEN vectors use the test-only baseNonceForTesting hook of the TS port; production encryption always uses a random baseNonce, exactly like Swift.",
    "fileId values inside LocalDataVault are UUIDs (lowercase from Node randomUUID, uppercase from Swift UUID) and are stored, never derived — no vector depends on their case.",
  ],
  pbkdf2HmacSha256: pbkdf2.map((v) => ({
    password: v.password,
    saltHex: Buffer.from(v.salt, "utf8").toString("hex"),
    iterations: v.iterations,
    dkLen: 32,
    expectedHex: v.expected,
  })),
  totpRfc6238: totpSets.map((s) => ({
    secretAscii: s.secretAscii,
    algorithm: s.algorithm,
    period: 30,
    digits: 8,
    vectors: s.values.map(([timeSeconds, expected]) => ({ timeSeconds, expected })),
  })),
  x25519Rfc7748: x,
  hkdfSha256Rfc5869Case1: hkdfCase,
  wzenV1: wzen,
};

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const target = join(root, "vectors", "cross-platform.json");
writeFileSync(target, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${target} (${wzen.length} WZEN vectors, ${totpSets.length * 6} TOTP vectors)`);
