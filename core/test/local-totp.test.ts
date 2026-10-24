import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { Base32, OTPAuthParser, OTPGenerator, TOTPError, type OTPAlgorithm } from "../src/local-totp.js";

function check(secretASCII: string, algorithm: OTPAlgorithm, vectors: [number, string][]): void {
  const secret = Buffer.from(secretASCII, "utf8");
  for (const [t, expected] of vectors) {
    const code = OTPGenerator.totp(secret, t * 1000, 30, 8, algorithm);
    assert.equal(code, expected, `t=${t} algo=${algorithm}`);
  }
}

describe("LocalTOTP", () => {
  // RFC 6238 Appendix B test vectors, 8 digits, period 30.
  it("testRFC6238SHA1", () => {
    check("12345678901234567890", "SHA1", [
      [59, "94287082"], [1111111109, "07081804"], [1111111111, "14050471"],
      [1234567890, "89005924"], [2000000000, "69279037"], [20000000000, "65353130"],
    ]);
  });

  it("testRFC6238SHA256", () => {
    check("12345678901234567890123456789012", "SHA256", [
      [59, "46119246"], [1111111109, "68084774"], [1111111111, "67062674"],
      [1234567890, "91819424"], [2000000000, "90698825"], [20000000000, "77737706"],
    ]);
  });

  it("testRFC6238SHA512", () => {
    check("1234567890123456789012345678901234567890123456789012345678901234", "SHA512", [
      [59, "90693936"], [1111111109, "25091201"], [1111111111, "99943326"],
      [1234567890, "93441116"], [2000000000, "38618901"], [20000000000, "47863826"],
    ]);
  });

  it("testBase32DecodePaddingAndSpaces", () => {
    assert.ok(Base32.decode("MY======").equals(Buffer.from("f", "utf8")));
    assert.ok(Base32.decode("MZXW6===").equals(Buffer.from("foo", "utf8")));
    assert.ok(Base32.decode("MZXW6").equals(Buffer.from("foo", "utf8"))); // no padding
    assert.ok(Base32.decode("MZ XW 6").equals(Buffer.from("foo", "utf8"))); // spaces
    assert.ok(Base32.decode("mzxw6").equals(Buffer.from("foo", "utf8"))); // lowercase
    assert.throws(() => Base32.decode("MZX*"));
  });

  it("testBase32Roundtrip", () => {
    const original = Buffer.from("WezWordn-TOTP-secret", "utf8");
    assert.ok(Base32.decode(Base32.encode(original)).equals(original));
  });

  it("testRemainingSeconds", () => {
    assert.equal(OTPGenerator.remainingSeconds(59_000, 30), 1);
    assert.equal(OTPGenerator.remainingSeconds(60_000, 30), 30);
    assert.equal(OTPGenerator.remainingSeconds(0, 30), 30);
  });

  it("testHOTPRejectsBadDigits", () => {
    assert.throws(
      () => OTPGenerator.hotp(Buffer.from("x", "utf8"), 0, 5),
      (e: unknown) => e instanceof TOTPError && e.code === "invalidDigits",
    );
    assert.throws(() => OTPGenerator.hotp(Buffer.from("x", "utf8"), 0, 9));
  });

  it("testOTPAuthParserFull", () => {
    const secret = Base32.encode(Buffer.from("12345678901234567890", "utf8"));
    const entry = OTPAuthParser.parse(
      `otpauth://totp/Example:alice@example.com?secret=${secret}&issuer=Example&algorithm=SHA256&digits=7&period=60`,
    );
    assert.equal(entry.issuer, "Example");
    assert.equal(entry.account, "alice@example.com");
    assert.ok(entry.secret.equals(Buffer.from("12345678901234567890", "utf8")));
    assert.equal(entry.algorithm, "SHA256");
    assert.equal(entry.digits, 7);
    assert.equal(entry.period, 60);
    const code = OTPGenerator.totp(entry.secret, 59_000, entry.period, entry.digits, entry.algorithm);
    assert.equal(code.length, 7);
  });

  it("testOTPAuthParserRejectsInvalid", () => {
    assert.throws(() => OTPAuthParser.parse("https://totp/x?secret=JBSWY3DPEHPK3PXP"));
    assert.throws(() => OTPAuthParser.parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"));
    assert.throws(
      () => OTPAuthParser.parse("otpauth://totp/x"),
      (e: unknown) => e instanceof TOTPError && e.code === "missingSecret",
    );
    assert.throws(() => OTPAuthParser.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9"));
    assert.throws(() => OTPAuthParser.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"));
    const invalidSecret = "JBSWY3DP" + "EHPK3PX!";
    assert.throws(() => OTPAuthParser.parse(`otpauth://totp/x?secret=${invalidSecret}`));
  });
});
