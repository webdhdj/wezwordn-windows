import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { ExtendedLogin, LegacyLogin, migrateLegacyLogin } from "../src/extended-login-fields.js";
import { canonicalJSON } from "../src/canonical-json.js";

describe("ExtendedLoginFields", () => {
  it("testSeparateFieldsRoundtripCodable", () => {
    const item = new ExtendedLogin("wesam", "wesam@example.com", "s3cret!");
    const decoded = ExtendedLogin.fromJSON(
      JSON.parse(canonicalJSON(item.toJSON())) as Record<string, unknown>,
    );
    assert.ok(decoded.equals(item));
    assert.notEqual(decoded.username, decoded.email);
  });

  it("testMigrationEmailShapedUsernameCopiesAndKeepsUsername", () => {
    const migrated = migrateLegacyLogin(new LegacyLogin("user@example.com", "pw"));
    assert.equal(migrated.email, "user@example.com");
    assert.equal(migrated.username, "user@example.com"); // kept for AutoFill compatibility
    assert.equal(migrated.password, "pw");
  });

  it("testMigrationNonEmailUsernameLeavesEmailNil", () => {
    const migrated = migrateLegacyLogin(new LegacyLogin("plainuser", "pw"));
    assert.equal(migrated.email, null);
    assert.equal(migrated.username, "plainuser");
  });

  it("testMatchesSearchesBothFieldsCaseInsensitively", () => {
    const item = new ExtendedLogin("Alice", "Bob@Example.com", "x");
    assert.equal(item.matches("alice"), true);
    assert.equal(item.matches("BOB@exam"), true);
    assert.equal(item.matches(""), true);
    assert.equal(item.matches("charlie"), false);
  });

  it("testEmailValidation", () => {
    assert.equal(ExtendedLogin.isValidEmail("a.b+tag@sub.example.co"), true);
    assert.equal(ExtendedLogin.isValidEmail("not-an-email"), false);
    assert.equal(ExtendedLogin.isValidEmail("a@b"), false);
    assert.equal(ExtendedLogin.isValidEmail("a b@example.com"), false);
    assert.equal(ExtendedLogin.isValidEmail("@example.com"), false);
  });
});
