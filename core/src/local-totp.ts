/**
 * LocalTOTP — literal port of the Swift module of the same name
 * (WezWordnCore/Sources/LocalTOTP): Base32 (RFC 4648), HOTP (RFC 4226),
 * TOTP (RFC 6238), and the otpauth:// URI parser.
 */
import { createHmac } from "node:crypto";

export type TOTPErrorCode =
  | "invalidBase32"
  | "invalidDigits"
  | "invalidPeriod"
  | "invalidURI"
  | "missingSecret";

export class TOTPError extends Error {
  readonly code: TOTPErrorCode;
  readonly detail: string | null;
  constructor(code: TOTPErrorCode, detail: string | null = null) {
    super(detail === null ? code : `${code}: ${detail}`);
    this.code = code;
    this.detail = detail;
  }
}

export type OTPAlgorithm = "SHA1" | "SHA256" | "SHA512";

// MARK: - Base32 (RFC 4648)

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export const Base32 = {
  /** Decodes RFC 4648 Base32. Accepts input with or without '=' padding,
   * ignores whitespace, and is case-insensitive. Throws on invalid
   * characters or an impossible length. */
  decode(input: string): Buffer {
    const cleaned = input
      .toUpperCase()
      .split("")
      .filter((ch) => !/\s/.test(ch) && ch !== "=" && ch !== "-")
      .join("");
    if (cleaned.length === 0) throw new TOTPError("invalidBase32");
    let buffer = 0;
    let bits = 0;
    const out: number[] = [];
    for (const ch of cleaned) {
      const idx = BASE32_ALPHABET.indexOf(ch);
      if (idx === -1) throw new TOTPError("invalidBase32");
      buffer = ((buffer << 5) | idx) >>> 0;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.push((buffer >>> bits) & 0xff);
        buffer = bits === 0 ? 0 : buffer & ((1 << bits) - 1);
      }
    }
    return Buffer.from(out);
  },

  encode(data: Buffer): string {
    if (data.length === 0) return "";
    let result = "";
    let buffer = 0;
    let bits = 0;
    for (const byte of data) {
      buffer = ((buffer << 8) | byte) >>> 0;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        result += BASE32_ALPHABET[(buffer >>> bits) & 0x1f];
      }
      buffer = bits === 0 ? 0 : buffer & ((1 << bits) - 1);
    }
    if (bits > 0) {
      result += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
    }
    while (result.length % 8 !== 0) result += "=";
    return result;
  },
};

// MARK: - HOTP (RFC 4226) / TOTP (RFC 6238)

function hmacDigest(algorithm: OTPAlgorithm, key: Buffer, data: Buffer): Buffer {
  const name = algorithm === "SHA1" ? "sha1" : algorithm === "SHA256" ? "sha256" : "sha512";
  return createHmac(name, key).update(data).digest();
}

export const OTPGenerator = {
  /** HOTP: HMAC over the 8-byte big-endian counter, dynamic truncation
   * (RFC 4226 §5.3). */
  hotp(secret: Buffer, counter: bigint | number, digits = 6, algorithm: OTPAlgorithm = "SHA1"): string {
    if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new TOTPError("invalidDigits");
    const counterData = Buffer.alloc(8);
    counterData.writeBigUInt64BE(BigInt(counter));
    const mac = hmacDigest(algorithm, secret, counterData);
    const offset = mac[mac.length - 1] & 0x0f;
    const binary =
      ((mac[offset] & 0x7f) << 24) |
      (mac[offset + 1] << 16) |
      (mac[offset + 2] << 8) |
      mac[offset + 3];
    let modulus = 1;
    for (let i = 0; i < digits; i++) modulus *= 10;
    const code = (binary >>> 0) % modulus;
    return String(code).padStart(digits, "0");
  },

  /** TOTP: counter = floor(unixTime / period) (RFC 6238 §4).
   * `date` is milliseconds since the Unix epoch (JS Date convention);
   * the Swift API takes a Date — the counter maths is identical. */
  totp(secret: Buffer, dateMs: number, period = 30, digits = 6, algorithm: OTPAlgorithm = "SHA1"): string {
    if (!(period > 0)) throw new TOTPError("invalidPeriod");
    const counter = Math.floor(dateMs / 1000 / period);
    return OTPGenerator.hotp(secret, counter, digits, algorithm);
  },

  /** Seconds remaining in the current TOTP window. */
  remainingSeconds(dateMs: number, period = 30): number {
    if (!(period > 0)) return 0;
    const t = Math.floor(dateMs / 1000);
    const rem = t % period;
    return rem === 0 ? period : period - rem;
  },
};

// MARK: - otpauth:// URI parsing

export interface OTPAuthEntry {
  issuer: string | null;
  account: string;
  secret: Buffer;
  secretBase32: string;
  algorithm: OTPAlgorithm;
  digits: number;
  period: number;
}

function percentDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export const OTPAuthParser = {
  /** Parses `otpauth://totp/[Issuer:]account?secret=...&issuer=...`.
   * Rejects non-otpauth schemes, non-TOTP types, missing/invalid secrets,
   * unsupported algorithms, digits outside 6...8 and non-positive periods.
   * Only the `totp` type is supported — an `otpauth://hotp/...` URI is
   * rejected, exactly like the Swift parser (the bare `hotp()` function
   * exists; its URI form does not). */
  parse(uri: string): OTPAuthEntry {
    const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(uri);
    if (schemeMatch === null || schemeMatch[1].toLowerCase() !== "otpauth") {
      throw new TOTPError("invalidURI", "scheme must be otpauth");
    }
    const rest = uri.slice(schemeMatch[0].length);
    const qIndex = rest.indexOf("?");
    const hostAndPath = qIndex === -1 ? rest : rest.slice(0, qIndex);
    const queryString = qIndex === -1 ? "" : rest.slice(qIndex + 1);
    const slash = hostAndPath.indexOf("/");
    const host = (slash === -1 ? hostAndPath : hostAndPath.slice(0, slash)).toLowerCase();
    if (host !== "totp") throw new TOTPError("invalidURI", "only totp is supported");
    // Label: path without leading '/', percent-decoded.
    const rawLabel = slash === -1 ? "" : hostAndPath.slice(slash + 1);
    const label = percentDecode(rawLabel);
    let labelIssuer: string | null = null;
    let account = label;
    const colon = label.indexOf(":");
    if (colon !== -1) {
      labelIssuer = label.slice(0, colon);
      account = label.slice(colon + 1);
    }
    if (account.length === 0) throw new TOTPError("invalidURI", "empty account label");

    // Query items: names lowercased (mirrors the Swift parser), values
    // percent-decoded. '+' is left literal, like URLComponents.
    const query = new Map<string, string>();
    if (queryString.length > 0) {
      for (const pair of queryString.split("&")) {
        if (pair.length === 0) continue;
        const eq = pair.indexOf("=");
        const name = (eq === -1 ? pair : pair.slice(0, eq)).toLowerCase();
        const value = eq === -1 ? "" : percentDecode(pair.slice(eq + 1));
        query.set(percentDecode(name), value);
      }
    }

    const secretStr = query.get("secret");
    if (secretStr === undefined || secretStr.length === 0) throw new TOTPError("missingSecret");
    let secret: Buffer;
    try {
      secret = Base32.decode(secretStr);
    } catch {
      throw new TOTPError("invalidURI", "secret is not valid Base32");
    }
    if (secret.length === 0) throw new TOTPError("missingSecret");

    const issuer = query.get("issuer") ?? labelIssuer;

    let algorithm: OTPAlgorithm = "SHA1";
    const rawAlgorithm = query.get("algorithm");
    if (rawAlgorithm !== undefined) {
      const upper = rawAlgorithm.toUpperCase();
      if (upper !== "SHA1" && upper !== "SHA256" && upper !== "SHA512") {
        throw new TOTPError("invalidURI", `unsupported algorithm: ${rawAlgorithm}`);
      }
      algorithm = upper;
    }

    let digits = 6;
    const rawDigits = query.get("digits");
    if (rawDigits !== undefined) {
      const v = Number(rawDigits);
      if (!Number.isInteger(v) || v < 6 || v > 8) throw new TOTPError("invalidDigits");
      digits = v;
    }

    let period = 30;
    const rawPeriod = query.get("period");
    if (rawPeriod !== undefined) {
      const v = Number(rawPeriod);
      if (!Number.isInteger(v) || !(v > 0)) throw new TOTPError("invalidPeriod");
      period = v;
    }

    return { issuer, account, secret, secretBase32: secretStr, algorithm, digits, period };
  },
};
