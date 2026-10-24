/**
 * Canonical JSON encoding mirroring Foundation's JSONEncoder with
 * `.sortedKeys` output formatting, as used by the Swift WezWordnCore for
 * every serialised structure whose bytes are fingerprinted or exchanged
 * (SidecarStore, backup payload/package, .wezshare export).
 *
 * Mirrored Foundation behaviours:
 *  - object keys sorted lexicographically, recursively; no whitespace;
 *  - `Data` values encoded as base64 strings (pass Buffers);
 *  - optional (nil) values omitted — builders must omit undefined fields,
 *    exactly like Swift's synthesised `encodeIfPresent`;
 *  - string escaping follows Foundation: `"` and `\` escaped, control
 *    characters as \b \t \n \f \r or \u00XX, and `/` escaped as `\/`;
 *    non-ASCII is emitted as raw UTF-8 (Foundation does not escape it).
 */

function encodeString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const code = ch.codePointAt(0) as number;
    switch (ch) {
      case '"': out += '\\"'; break;
      case "\\": out += "\\\\"; break;
      case "/": out += "\\/"; break;
      case "\b": out += "\\b"; break;
      case "\t": out += "\\t"; break;
      case "\n": out += "\\n"; break;
      case "\f": out += "\\f"; break;
      case "\r": out += "\\r"; break;
      default:
        if (code < 0x20) {
          out += "\\u" + code.toString(16).padStart(4, "0");
        } else {
          out += ch;
        }
    }
  }
  return out + '"';
}

export function canonicalJSON(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonicalJSON: non-finite number");
    return String(value);
  }
  if (typeof value === "string") return encodeString(value);
  if (Buffer.isBuffer(value)) return encodeString(value.toString("base64"));
  if (Array.isArray(value)) {
    return "[" + value.map((entry) => canonicalJSON(entry)).join(",") + "]";
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort();
    const parts = keys.map((key) => encodeString(key) + ":" + canonicalJSON(record[key]));
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`canonicalJSON: unsupported type ${typeof value}`);
}

/** ISO-8601 without fractional seconds, matching Foundation's `.iso8601`
 * date encoding strategy (e.g. "2026-10-24T12:34:56Z"). */
export function iso8601NoFraction(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Parses an ISO-8601 string the way Foundation's `.iso8601` decoding
 * strategy accepts (with or without fractional seconds). */
export function parseISO8601(value: string): Date {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error(`invalid ISO-8601 date: ${value}`);
  return date;
}

/** Recursive key-sorting parser helper: parses JSON text into plain data.
 * Dates and Data are NOT auto-converted here — each module decodes its own
 * fields explicitly, mirroring Swift's typed Decodable structs. */
export function parseJSON(text: string): unknown {
  return JSON.parse(text);
}
