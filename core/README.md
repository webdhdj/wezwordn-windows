# WezWordnCore — Windows/TypeScript port

A literal TypeScript port of the Swift `WezWordnCore` package
(`~/workspace/wezwordn/WezWordnCore/Sources/`), for the Windows 11 version of
WezWordn. Formats are **not** re-invented: WZEN v1, WEZBACKUP v1, .wezshare v1
and the EmergencyRecovery package are byte-compatible with the Swift
implementation (see `vectors/cross-platform.json`).

- Runtime: Node.js v24 (developed and tested on v24.22.1)
- Dependencies: **zero**. Only `node:crypto`, `node:fs`, `node:test` (+
  `node:path` / `node:os` / `node:url` in tests) are used.
- Language: TypeScript, compiled with `tsc` fetched on demand via `npx`
  (the package itself installs nothing).

## Run the tests (one command)

```sh
cd ~/workspace/wezwordn-windows/core
npm test
```

`npm test` compiles (`npx -y -p typescript@5 tsc -p tsconfig.json`) and runs
`node --test dist/test/*.test.js`.

**Observed result (2026-10-24, Node v24.22.1, including a clean rebuild after
`rm -rf dist`): 58 tests, 9 suites, 58 pass, 0 fail, 0 skipped.**

Per file:

| Test file | Tests | Mirrors |
|---|---|---|
| extended-login-fields.test.ts | 5 | ExtendedLoginFieldsTests (Swift) |
| local-totp.test.ts | 9 | LocalTOTPTests — incl. all 18 RFC 6238 vectors |
| local-encrypted-storage.test.ts | 7 | LocalEncryptedStorageTests (6) + a truncation case |
| vault-health.test.ts | 7 | VaultHealthTests |
| hibp-client.test.ts | 4 | HIBPClientTests (offline mock transport) |
| emergency-recovery.test.ts | 4 | EmergencyRecoveryTests |
| secure-sharing.test.ts | 4 | SecureSharingTests |
| local-data-vault.test.ts | 13 | LocalDataVaultTests — incl. PBKDF2 KATs (c = 1 / 2 / 4096) |
| cross-platform.test.ts | 5 | Consumes `vectors/cross-platform.json` |

## File structure

```
core/
├── package.json            # zero dependencies; build/test scripts
├── tsconfig.json           # strict, NodeNext ESM, outDir dist/
├── README.md
├── src/
│   ├── index.ts            # barrel export of all modules
│   ├── canonical-json.ts   # Foundation-compatible canonical JSON
│   │                       # (sorted keys, base64 Data, ISO-8601 no fraction)
│   ├── extended-login-fields.ts
│   ├── local-totp.ts       # Base32 RFC 4648; HOTP/TOTP RFC 4226/6238;
│   │                       # OTPAuthParser for otpauth://totp only
│   ├── local-encrypted-storage.ts  # WZEN v1 streaming file encryption
│   ├── vault-health.ts
│   ├── hibp-client.ts      # k-anonymity range client, injected transport
│   ├── x25519-raw.ts       # raw 32-byte X25519 keys via DER prefix/suffix
│   ├── emergency-recovery.ts
│   ├── secure-sharing.ts   # .wezshare v1
│   ├── pbkdf2.ts           # PBKDF2-HMAC-SHA256 via crypto.pbkdf2Sync
│   ├── local-data-vault.ts # sidecar store + WEZBACKUP v1 export/import
│   ├── node-shims.d.ts     # minimal ambient types for node:* (no @types/node)
│   └── globals.d.ts        # minimal Buffer / ImportMeta declarations
├── test/                   # node:test suites listed above
├── vectors/
│   └── cross-platform.json # fixed vectors for CI / cross-platform checks
└── scripts/
    └── gen-vectors.mjs     # regenerates vectors/cross-platform.json
```

## Wire formats (identical to Swift)

- **WZEN v1** — header 21 B: `WZEN` + `0x01` + baseNonce 12 B + chunkSize
  UInt32BE (default 64 KiB, valid 1…16 MiB). Per chunk: plainLen UInt32BE +
  ciphertext + 16 B GCM tag. Chunk nonce = baseNonce bytes [4..12) XOR
  big-endian UInt64 chunk counter. End of stream is a bare plainLen == 0
  (4 bytes, no tag) — exactly as in Swift. Streaming via `node:fs`
  descriptors; the whole file is never loaded. Tamper / wrong key /
  truncation throw and the partial output file is deleted.
- **EmergencyRecovery v1** — X25519 ephemeral key pair, HKDF-SHA256
  (salt 32 B, info `WezWordn-EmergencyRecovery-v1`), AES-256-GCM,
  nonce 12 B, ciphertext‖tag.
- **.wezshare v1 (SecureSharing)** — same construction with info
  `WezWordn-SecureSharing-v1`; fingerprint = lowercase hex
  SHA-256(ephemeralPublicKey‖salt‖nonce‖ciphertext); JSON with sorted keys
  and ISO-8601 dates, base64 fields.
- **WEZBACKUP v1 (LocalDataVault)** — PBKDF2-HMAC-SHA256 (default 210,000
  iterations, salt 16 B) → AES-256-GCM sealed payload; manifest carries
  SHA-256 fingerprints of the store and every file blob; import verifies
  **everything** (format, counts, fingerprints, blob set) before mutating
  any state, and a wrong password fails with `backupBadPasswordOrCorrupt`
  leaving current data untouched.
- **Raw X25519 keys** — Node SPKI DER export is 44 B and PKCS#8 DER is 48 B;
  the raw key is the last 32 B of each (verified in code and by the RFC 7748
  vector: private → public derivation and shared secret both reproduce
  RFC 7748 §6.1 exactly).

## Cross-platform vectors

`vectors/cross-platform.json` contains: 3 PBKDF2-HMAC-SHA256 KATs, the full
RFC 6238 TOTP set (3 algorithms × 6 timestamps), the RFC 7748 X25519
Diffie-Hellman vector, the RFC 5869 HKDF-SHA256 test case 1, and three
byte-exact WZEN v1 files (empty / 100 B / 10,000 B, fixed key and baseNonce).
Regenerate with:

```sh
npm run build && node scripts/gen-vectors.mjs
```

The generator asserts every published constant against the implementation
before writing, and cross-checks `crypto.hkdfSync` against a hand-rolled
HMAC extract/expand. EmergencyRecovery / SecureSharing packages have no fixed
bytes by design (ephemeral keys); they are pinned by the X25519 + HKDF
vectors plus roundtrip/tamper tests.

## Deviations from the Swift semantics (and why)

1. **Dates as epoch milliseconds** in TOTP and VaultHealth APIs
   (`dateMs`, `updatedAtMs`, `nowMs`) instead of `Date` objects; all
   arithmetic (counters, age thresholds, scores) is identical. Package
   `createdAt` fields (Emergency/SecureSharing) remain JS `Date`s and are
   serialized as ISO-8601 with second precision, like Swift.
2. `TOTPSecretRecord.currentCode(at:)` (a Swift method) is the free function
   `totpRecordCurrentCode(record, dateMs)` — JS interfaces carry no methods.
3. **No lock**: Swift guards the vault with `NSLock`; Node's synchronous
   execution makes each method atomic, so a lock would be dead code. This is
   documented in the `local-data-vault.ts` header, not faked.
4. Swift `precondition` failures in PBKDF2 throw `RangeError` instead of
   trapping the process.
5. EmergencyRecovery: Swift defines only the `Codable` struct, no export
   helper. The port's JSON export/import helpers use the same canonical
   encoding as .wezshare (sorted keys, base64, ISO-8601).
6. SecureSharing payload: Swift encodes the item with a plain `JSONEncoder`;
   the port uses canonical sorted-keys JSON. The bytes can differ; the JSON
   is decoder-equivalent for any conforming reader.
7. `fileId` case: Node `randomUUID()` is lowercase, Swift
   `UUID().uuidString` is uppercase. Ids are stored in the sidecar, never
   derived, so this has no functional impact.
8. HIBP: Swift's production `URLSession` transport is not ported (it is also
   excluded from Swift's own tests). The client takes an injected synchronous
   transport; the host application supplies the network implementation.
9. OTPAuthParser with duplicate query keys: Swift
   `Dictionary(uniqueKeysWithValues:)` traps; the JS `Map` keeps the last
   value. Malformed URIs still throw as in Swift.
10. VaultHealth counts characters as JS code points (`[...str]`); Swift
    counts grapheme clusters. Only exotic combining-emoji passwords could
    differ.
11. `encryptFile` accepts a test-only `baseNonceForTesting` option so the
    WZEN vectors can be byte-exact. Swift exposes no such parameter;
    production calls always use a random baseNonce, exactly like Swift.
12. Because the package is zero-dependency, minimal ambient type declarations
    for the used `node:*` surface live in `src/node-shims.d.ts` and
    `src/globals.d.ts` instead of `@types/node`.

## Build notes

- `dist/` is pure build output; deleting it and re-running `npm test`
  reproduces the green run.
- This environment's content filter rewrote credential-shaped tokens
  (`password` / `secret` assignments) inside source files during authoring;
  the affected lines were repaired byte-exactly and the final tree was
  verified by a clean compile + full test pass. If a future edit shows
  `<redacted>` inside a `.ts` file, that is the filter, not the code.
