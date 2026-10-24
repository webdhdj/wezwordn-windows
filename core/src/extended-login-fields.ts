/**
 * ExtendedLoginFields — literal port of the Swift module of the same name
 * (WezWordnCore/Sources/ExtendedLoginFields).
 *
 * A login item whose username, email and password are fully independent
 * fields. Bitwarden's legacy `Login.username` is routinely (ab)used to store
 * an email address; keeping a separate `email` field avoids overloading
 * `username`, keeps AutoFill semantics intact, and lets search / copy act on
 * each value individually.
 */

export class ExtendedLogin {
  username: string | null;
  email: string | null;
  password: string | null;

  constructor(username: string | null = null, email: string | null = null, password: string | null = null) {
    this.username = username;
    this.email = email;
    this.password = password;
  }

  /** Case-insensitive substring search over BOTH username and email.
   * An empty / whitespace-only query matches everything (caller is listing). */
  matches(query: string): boolean {
    const q = query.trim().toLowerCase();
    if (q.length === 0) return true;
    if (this.username !== null && this.username.toLowerCase().includes(q)) return true;
    if (this.email !== null && this.email.toLowerCase().includes(q)) return true;
    return false;
  }

  /** Deliberately simple, documented email format check (not full RFC 5322):
   * exactly one '@', non-empty local part, domain containing at least one
   * dot with non-empty labels, and no whitespace anywhere. */
  static isValidEmail(value: string): boolean {
    const pattern = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
    return pattern.test(value) && !value.includes(" ");
  }

  get emailIsValid(): boolean {
    if (this.email === null || this.email.length === 0) return false;
    return ExtendedLogin.isValidEmail(this.email);
  }

  /** Codable mirror: optionals are omitted when null (encodeIfPresent). */
  toJSON(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    if (this.username !== null) out.username = this.username;
    if (this.email !== null) out.email = this.email;
    if (this.password !== null) out.password = this.password;
    return out;
  }

  static fromJSON(data: Record<string, unknown>): ExtendedLogin {
    return new ExtendedLogin(
      (data.username as string | undefined) ?? null,
      (data.email as string | undefined) ?? null,
      (data.password as string | undefined) ?? null,
    );
  }

  equals(other: ExtendedLogin): boolean {
    return this.username === other.username && this.email === other.email && this.password === other.password;
  }
}

/** The legacy (pre-extension) login shape: a single username field only. */
export class LegacyLogin {
  username: string | null;
  password: string | null;

  constructor(username: string | null = null, password: string | null = null) {
    this.username = username;
    this.password = password;
  }
}

/**
 * Migration from the legacy model.
 *
 * Decision (documented in Swift, kept verbatim): if the legacy `username`
 * is email-shaped and no email exists yet, we COPY it into `email` and KEEP
 * `username` unchanged. We do not clear/move it out of `username`, because
 * existing AutoFill rules, URI matching and synced Bitwarden data key off
 * `username`; clearing it would silently break AutoFill for migrated items
 * and would diverge from the server-side record. Duplication is harmless:
 * the user can clear `username` explicitly in the editor if it was only an
 * email. No data is ever dropped by this migration.
 */
export function migrateLegacyLogin(legacy: LegacyLogin): ExtendedLogin {
  let email: string | null = null;
  if (legacy.username !== null && ExtendedLogin.isValidEmail(legacy.username)) {
    email = legacy.username;
  }
  return new ExtendedLogin(legacy.username, email, legacy.password);
}
