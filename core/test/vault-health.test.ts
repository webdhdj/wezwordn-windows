import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { analyzeVaultHealth, isWeak, type VaultHealthItem } from "../src/vault-health.js";

const NOW = 1_700_000_000_000;
function item(
  id: string,
  password: string,
  opts: Partial<VaultHealthItem> = {},
): VaultHealthItem {
  return {
    id,
    domain: opts.domain ?? "example.com",
    username: opts.username !== undefined ? opts.username : "user",
    email: opts.email !== undefined ? opts.email : "user@example.com",
    password,
    updatedAtMs: opts.updatedAtMs ?? NOW - 10 * 86400_000,
    hasTOTP: opts.hasTOTP ?? true,
  };
}
function aged(id: string, password: string, ageDays: number, opts: Partial<VaultHealthItem> = {}): VaultHealthItem {
  return { ...item(id, password, opts), updatedAtMs: NOW - ageDays * 86400_000 };
}

// Strong synthetic password: 20 chars, mixed classes, not common.
const strong = "X9$kQ2!mZp7#LwR4&vN8";

describe("VaultHealth", () => {
  it("testWeakDetection", () => {
    assert.equal(analyzeVaultHealth([item("a", "short")], NOW).weakCount, 1);
    // A >=12-char single-class password is weak via entropy (<45 bits).
    assert.equal(analyzeVaultHealth([item("b", "aaaaaaaaaaaaaa")], NOW).weakCount, 1);
    assert.equal(analyzeVaultHealth([item("c", strong)], NOW).weakCount, 0);
    assert.equal(isWeak("password"), true); // common list, also short
  });

  it("testReusedDetection", () => {
    const items = [
      item("a", strong),
      item("b", strong, { domain: "other.com", username: "u2" }),
      item("c", strong + "Zz9!", { domain: "third.com", username: "u3" }),
    ];
    assert.equal(analyzeVaultHealth(items, NOW).reusedCount, 2);
  });

  it("testOldDetection", () => {
    const report = analyzeVaultHealth(
      [aged("a", strong, 400), aged("b", strong + "Aa1!", 10, { domain: "b.com", username: "u2" })],
      NOW,
    );
    assert.equal(report.oldCount, 1);
  });

  it("testDuplicateAccountDetection", () => {
    const items = [item("a", strong), item("b", strong + "Aa1!")]; // same domain+username
    assert.equal(analyzeVaultHealth(items, NOW).duplicateAccountCount, 2);
  });

  it("testMissingTOTPAndIdentity", () => {
    const report = analyzeVaultHealth(
      [item("a", strong, { username: null, email: null, hasTOTP: false })],
      NOW,
    );
    assert.equal(report.missingTOTPCount, 1);
    assert.equal(report.missingIdentityCount, 1);
  });

  it("testScorePerfectAndWorst", () => {
    const perfect = analyzeVaultHealth(
      [item("a", strong), item("b", strong + "Qq7!", { domain: "x.com", username: "u9" })],
      NOW,
    );
    assert.equal(perfect.score, 100);
    assert.equal(perfect.highRiskCount, 0);
    // Single weak, reused-not-possible, no TOTP, old, missing identity:
    // deductions 30 (weak) + 20 (totp) + 15 (old) = 65 -> score 35.
    const bad = analyzeVaultHealth(
      [aged("a", "short", 900, { username: null, email: null, hasTOTP: false })],
      NOW,
    );
    assert.equal(bad.score, 35);
    // Empty vault: documented score 100, all zero.
    const empty = analyzeVaultHealth([], NOW);
    assert.equal(empty.score, 100);
    assert.equal(empty.totalCount, 0);
  });

  it("testHighRiskWeakPlusReused", () => {
    const items = [
      item("a", "short"),
      item("b", "short", { domain: "o.com", username: "u2" }),
    ];
    assert.equal(analyzeVaultHealth(items, NOW).highRiskCount, 2);
  });
});
