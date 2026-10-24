/**
 * VaultHealth — literal port of the Swift module of the same name
 * (WezWordnCore/Sources/VaultHealth). Pure analysis over in-memory,
 * already-decrypted items: no storage, no network.
 */

export interface VaultHealthItem {
  id: string;
  domain: string;
  username: string | null;
  email: string | null;
  password: string;
  /** Milliseconds since the Unix epoch (JS Date convention). */
  updatedAtMs: number;
  hasTOTP: boolean;
}

export type HealthIssueKind =
  | "weak"
  | "reused"
  | "old"
  | "duplicateAccount"
  | "missingTOTP"
  | "missingIdentity";

export interface HealthIssue {
  itemID: string;
  kind: HealthIssueKind;
  detail: string;
}

export interface HealthReport {
  totalCount: number;
  weakCount: number;
  reusedCount: number;
  oldCount: number;
  duplicateAccountCount: number;
  missingTOTPCount: number;
  missingIdentityCount: number;
  /** weak AND (reused OR in a duplicate group) — documented heuristic. */
  highRiskCount: number;
  /** 0...100, see scoreFormula documentation on analyze(). */
  score: number;
  issues: HealthIssue[];
}

/** Small built-in common-password list (offline; intentionally tiny and
 * documented as such — it is a heuristic signal, not a breach corpus). */
const COMMON_PASSWORDS = new Set([
  "password", "password1", "123456", "12345678", "123456789", "12345",
  "qwerty", "qwerty123", "letmein", "admin", "welcome", "iloveyou",
  "football", "monkey", "dragon", "master", "sunshine", "princess",
  "passw0rd", "shadow", "superman", "trustno1",
]);

/** Estimated entropy in bits: length * log2(poolSize), where poolSize is
 * summed from present character classes (lower 26, upper 26, digits 10,
 * symbols 33, other/unicode 100). Documented estimate, not a strength
 * proof. Character classification mirrors Swift's unicode-scalar ranges. */
export function estimatedEntropyBits(password: string): number {
  const chars = [...password];
  if (chars.length === 0) return 0;
  let pool = 0;
  let hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false, hasOther = false;
  for (const ch of chars) {
    const v = ch.codePointAt(0) as number;
    if (v >= 97 && v <= 122) hasLower = true;
    else if (v >= 65 && v <= 90) hasUpper = true;
    else if (v >= 48 && v <= 57) hasDigit = true;
    else if ((v >= 33 && v <= 47) || (v >= 58 && v <= 64) || (v >= 91 && v <= 96) || (v >= 123 && v <= 126)) hasSymbol = true;
    else hasOther = true;
  }
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSymbol) pool += 33;
  if (hasOther) pool += 100;
  if (pool <= 1) return 0;
  return chars.length * Math.log2(pool);
}

/** Weak iff: length < 12, OR lowercased password is in the common list,
 * OR estimated entropy < 45 bits, OR it uses 3 or fewer distinct
 * characters (e.g. "aaaaaaaaaaaaaa" — the pool-based entropy estimate
 * alone overrates such passwords, so this rule is explicit).
 * (Any one condition suffices.) */
export function isWeak(password: string): boolean {
  if ([...password].length < 12) return true;
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return true;
  if (estimatedEntropyBits(password) < 45) return true;
  if (new Set([...password]).size <= 3) return true;
  return false;
}

/** Score formula (documented): start at 100 and subtract, proportionally
 * to the share of affected items: weak 30 * weakRatio, reused 25 *
 * reusedRatio, missingTOTP 20 * missingTOTPRatio, old 15 * oldRatio,
 * duplicateAccount 10 * duplicateRatio. Result is rounded and clamped
 * to 0...100. An empty vault scores 100 (nothing at risk). */
export function analyzeVaultHealth(items: VaultHealthItem[], nowMs: number = Date.now()): HealthReport {
  const issues: HealthIssue[] = [];
  const total = items.length;
  if (total === 0) {
    return {
      totalCount: 0, weakCount: 0, reusedCount: 0, oldCount: 0,
      duplicateAccountCount: 0, missingTOTPCount: 0, missingIdentityCount: 0,
      highRiskCount: 0, score: 100, issues: [],
    };
  }
  // Reuse: identical non-empty passwords shared by >1 item.
  const byPassword = new Map<string, string[]>();
  for (const item of items) {
    if (item.password.length === 0) continue;
    const list = byPassword.get(item.password) ?? [];
    list.push(item.id);
    byPassword.set(item.password, list);
  }
  const reusedIDs = new Set<string>();
  for (const ids of byPassword.values()) if (ids.length > 1) for (const id of ids) reusedIDs.add(id);
  // Duplicates: same normalised domain+username in >1 item.
  const byAccount = new Map<string, string[]>();
  for (const item of items) {
    const key = item.domain.toLowerCase() + "|" + (item.username ?? "").toLowerCase();
    if ((item.username ?? "").length === 0) continue;
    const list = byAccount.get(key) ?? [];
    list.push(item.id);
    byAccount.set(key, list);
  }
  const dupIDs = new Set<string>();
  for (const ids of byAccount.values()) if (ids.length > 1) for (const id of ids) dupIDs.add(id);

  let weak = 0, reused = 0, old = 0, dup = 0, noTOTP = 0, noIdentity = 0, highRisk = 0;
  const oldThreshold = nowMs - 365 * 24 * 3600 * 1000;
  for (const item of items) {
    const weakFlag = isWeak(item.password);
    const reusedFlag = reusedIDs.has(item.id);
    if (weakFlag) { weak += 1; issues.push({ itemID: item.id, kind: "weak", detail: "Weak password (length/common/entropy heuristic)" }); }
    if (reusedFlag) { reused += 1; issues.push({ itemID: item.id, kind: "reused", detail: "Password reused across multiple items" }); }
    if (item.updatedAtMs < oldThreshold) { old += 1; issues.push({ itemID: item.id, kind: "old", detail: "Not updated in over 365 days" }); }
    if (dupIDs.has(item.id)) { dup += 1; issues.push({ itemID: item.id, kind: "duplicateAccount", detail: "Same domain+username as another item" }); }
    if (!item.hasTOTP) { noTOTP += 1; issues.push({ itemID: item.id, kind: "missingTOTP", detail: "No TOTP configured" }); }
    if ((item.username ?? "").length === 0 && (item.email ?? "").length === 0) {
      noIdentity += 1; issues.push({ itemID: item.id, kind: "missingIdentity", detail: "Both username and email are missing" });
    }
    if (weakFlag && (reusedFlag || dupIDs.has(item.id))) highRisk += 1;
  }
  const ratio = (n: number) => n / total;
  const raw = 100 - 30 * ratio(weak) - 25 * ratio(reused) - 20 * ratio(noTOTP) - 15 * ratio(old) - 10 * ratio(dup);
  const score = Math.max(0, Math.min(100, Math.round(raw)));
  return {
    totalCount: total, weakCount: weak, reusedCount: reused, oldCount: old,
    duplicateAccountCount: dup, missingTOTPCount: noTOTP, missingIdentityCount: noIdentity,
    highRiskCount: highRisk, score, issues,
  };
}
