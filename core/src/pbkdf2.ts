/**
 * PBKDF2 — port of the Swift file of the same name
 * (WezWordnCore/Sources/LocalDataVault/PBKDF2.swift).
 *
 * PBKDF2 (RFC 8018 §5.2) with HMAC-SHA256 as the PRF. The Swift version
 * implements it manually over swift-crypto's HMAC because swift-crypto
 * ships no PBKDF2 API; Node ships it natively as `crypto.pbkdf2Sync`,
 * which implements the identical definition:
 *   U_1 = PRF(password, salt ‖ INT_32_BE(i))
 *   U_n = PRF(password, U_{n-1})
 *   T_i = U_1 ⊕ U_2 ⊕ … ⊕ U_iterations
 *   DK  = (T_1 ‖ T_2 ‖ …) truncated to `keyLength` bytes.
 *
 * Known-answer check (asserted in the test suite):
 * PBKDF2-HMAC-SHA256(password="password", salt="salt", c=1, dkLen=32)
 *   = 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
 */
import { pbkdf2Sync } from "node:crypto";

export function deriveKeySHA256(
  password: string | Buffer,
  salt: Buffer,
  iterations: number,
  keyLength = 32,
): Buffer {
  // Swift uses precondition() for these; a thrown RangeError is the
  // closest non-crashing equivalent in a library context.
  if (!(iterations >= 1)) throw new RangeError("PBKDF2 iterations must be >= 1");
  if (!(keyLength >= 1)) throw new RangeError("PBKDF2 keyLength must be >= 1");
  const passwordBuffer = typeof password === "string" ? Buffer.from(password, "utf8") : password;
  return pbkdf2Sync(passwordBuffer, salt, iterations, keyLength, "sha256");
}
