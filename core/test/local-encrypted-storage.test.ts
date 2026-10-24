import { afterEach, beforeEach, describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  decryptFile,
  decryptFileWithProvider,
  encryptFile,
  encryptFileWithProvider,
  EncryptedFileError,
  fileExists,
  InMemoryKeyProvider,
} from "../src/local-encrypted-storage.js";

let dir = "";
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "wzen-test-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function makeFile(name: string, bytes: number): string {
  const url = join(dir, name);
  const data = Buffer.alloc(bytes);
  for (let i = 0; i < bytes; i++) data[i] = i % 251;
  writeFileSync(url, data);
  return url;
}

const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const wrongKey = Buffer.from(Array.from({ length: 32 }, (_, i) => 255 - i));

describe("LocalEncryptedStorage", () => {
  it("testRoundtripLargerThanChunkSize", () => {
    const src = makeFile("plain.bin", 10_000);
    const enc = join(dir, "plain.wzen");
    const dec = join(dir, "out.bin");
    encryptFile(src, enc, key, { chunkSize: 1024 });
    assert.equal(fileExists(enc), true);
    const encData = readFileSync(enc);
    assert.ok(encData.subarray(0, 4).equals(Buffer.from("WZEN", "utf8")));
    decryptFile(enc, dec, key);
    assert.ok(readFileSync(dec).equals(readFileSync(src)));
  });

  it("testRoundtripEmptyAndExactChunk", () => {
    for (const bytes of [0, 1024]) {
      const src = makeFile(`p${bytes}.bin`, bytes);
      const enc = join(dir, `p${bytes}.wzen`);
      const dec = join(dir, `p${bytes}.out`);
      encryptFile(src, enc, key, { chunkSize: 1024 });
      decryptFile(enc, dec, key);
      assert.ok(readFileSync(dec).equals(readFileSync(src)), `bytes=${bytes}`);
    }
  });

  it("testTamperFailsAndOutputRemoved", () => {
    const src = makeFile("plain.bin", 3000);
    const enc = join(dir, "t.wzen");
    encryptFile(src, enc, key, { chunkSize: 1024 });
    const bytes = Buffer.from(readFileSync(enc));
    bytes[bytes.length - 20] ^= 0xff; // flip a byte inside ciphertext/tag region
    writeFileSync(enc, bytes);
    const dec = join(dir, "t.out");
    assert.throws(() => decryptFile(enc, dec, key));
    assert.equal(fileExists(dec), false, "partial plaintext must be deleted on failure");
  });

  it("testWrongKeyFails", () => {
    const src = makeFile("plain.bin", 500);
    const enc = join(dir, "w.wzen");
    encryptFile(src, enc, key, { chunkSize: 1024 });
    const dec = join(dir, "w.out");
    assert.throws(
      () => decryptFile(enc, dec, wrongKey),
      (e: unknown) => e instanceof EncryptedFileError && e.code === "authenticationFailed",
    );
  });

  it("testNoncesDifferBetweenEncryptions", () => {
    const src = makeFile("plain.bin", 500);
    const e1 = join(dir, "1.wzen");
    const e2 = join(dir, "2.wzen");
    encryptFile(src, e1, key, { chunkSize: 1024 });
    encryptFile(src, e2, key, { chunkSize: 1024 });
    const d1 = readFileSync(e1);
    const d2 = readFileSync(e2);
    assert.ok(!d1.equals(d2));
    assert.ok(!d1.subarray(5, 17).equals(d2.subarray(5, 17))); // baseNonce field differs
  });

  it("testKeyProviderRoundtrip", () => {
    const provider = new InMemoryKeyProvider(
      Buffer.from(Array.from({ length: 32 }, (_, i) => i ^ 0x5a)),
    );
    const src = makeFile("plain.bin", 2048);
    const enc = join(dir, "k.wzen");
    const dec = join(dir, "k.out");
    encryptFileWithProvider(src, enc, provider, { chunkSize: 512 });
    decryptFileWithProvider(enc, dec, provider);
    assert.ok(readFileSync(dec).equals(readFileSync(src)));
  });

  it("testTruncatedFileFailsAndOutputRemoved", () => {
    const src = makeFile("plain.bin", 2000);
    const enc = join(dir, "tr.wzen");
    encryptFile(src, enc, key, { chunkSize: 1024 });
    const bytes = readFileSync(enc);
    // Drop the end-of-stream marker and part of the final tag.
    writeFileSync(enc, bytes.subarray(0, bytes.length - 10));
    const dec = join(dir, "tr.out");
    assert.throws(() => decryptFile(enc, dec, key));
    assert.equal(fileExists(dec), false);
  });
});
