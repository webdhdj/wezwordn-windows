/**
 * HIBPClient — literal port of the Swift module of the same name
 * (WezWordnCore/Sources/HIBPClient).
 *
 * Have I Been Pwned password check using k-anonymity only: SHA1(password)
 * is computed locally, only the first 5 hex characters are sent to the
 * range endpoint, and the returned suffix list is matched locally. The full
 * hash and the password itself never leave the device through this client.
 * Transport is injectable so tests run fully offline.
 *
 * The Swift transport protocol is synchronous (`fetchRange(prefix) throws
 * -> String`); this port keeps the same synchronous shape. The production
 * URLSession transport from Swift is NOT ported (it is excluded from the
 * Swift tests too) — a host application supplies its own transport.
 */
import { createHash } from "node:crypto";

export interface HIBPTransport {
  fetchRange(prefix: string): string;
}

export class HIBPError extends Error {
  readonly code = "malformedResponse";
  readonly line: string;
  constructor(line: string) {
    super(`malformedResponse: ${line}`);
    this.line = line;
  }
}

export class HIBPClient {
  readonly transport: HIBPTransport;

  constructor(transport: HIBPTransport) {
    this.transport = transport;
  }

  static sha1Hex(ofPassword: string): string {
    return createHash("sha1").update(Buffer.from(ofPassword, "utf8")).digest("hex").toUpperCase();
  }

  static splitHash(hex: string): { prefix: string; suffix: string } {
    return { prefix: hex.slice(0, 5), suffix: hex.slice(5) };
  }

  /** Parses a range response body: one `SUFFIX:count` per line. */
  static parseResponse(body: string): Map<string, number> {
    const out = new Map<string, number>();
    for (const rawLine of body.split("\n")) {
      const line = rawLine.trim();
      if (line.length === 0) continue;
      const colon = line.indexOf(":");
      if (colon === -1) throw new HIBPError(line);
      const countText = line.slice(colon + 1).trim();
      const count = Number(countText);
      if (countText.length === 0 || !Number.isInteger(count)) throw new HIBPError(line);
      out.set(line.slice(0, colon).toUpperCase(), count);
    }
    return out;
  }

  /** Returns the breach count for `password`, or 0 if its suffix is absent. */
  pwnedCount(forPassword: string): number {
    const hex = HIBPClient.sha1Hex(forPassword);
    const { prefix, suffix } = HIBPClient.splitHash(hex);
    const body = this.transport.fetchRange(prefix);
    const table = HIBPClient.parseResponse(body);
    return table.get(suffix.toUpperCase()) ?? 0;
  }

  isPwned(password: string): boolean {
    return this.pwnedCount(password) > 0;
  }
}
