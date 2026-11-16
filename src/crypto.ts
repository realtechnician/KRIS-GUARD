/**
 * Small cryptography helpers. Everything here uses Node's built-in `crypto`
 * module; we do not invent our own algorithms.
 *
 * Two words used throughout KRIS Guard:
 *
 *  - HASH (SHA-256): a fingerprint of some data. Anyone can compute it. If the
 *    data changes by one character, the fingerprint changes completely.
 *
 *  - HMAC: a fingerprint that also needs a SECRET KEY. Only someone holding
 *    the key can produce the right value, so it works like a signature.
 */
import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

export function hmacHex(key: string | Buffer, data: string): string {
  return createHmac("sha256", key).update(data, "utf8").digest("hex");
}

export function hmacBytes(key: string | Buffer, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

/**
 * Derive a separate key for one purpose from the main server secret.
 * This way the key that protects API-key hashes is different from the key
 * that makes placeholders, even though both come from one environment
 * variable. A weakness in one use cannot spill into the other.
 */
export function deriveKey(secret: string, purpose: string): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, "kris-guard", purpose, 32));
}

/** Compare two hex strings without leaking, through timing, where they differ. */
export function safeEqualHex(a: string, b: string): boolean {
  const ab = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ab.length !== bb.length || ab.length === 0) return false;
  return timingSafeEqual(ab, bb);
}

export function randomHex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}

const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/**
 * Turn bytes into capital letters only (A-Z).
 *
 * Placeholders use letters only, with no digits, so that a placeholder can
 * never look like a phone number or an ID to our own detectors.
 * Bytes >= 234 are skipped so every letter is equally likely (234 = 9 * 26).
 */
export function lettersFromBytes(bytes: Uint8Array, length: number): string {
  let out = "";
  for (const b of bytes) {
    if (b >= 234) continue;
    out += LETTERS[b % 26];
    if (out.length === length) return out;
  }
  return out; // may be shorter than requested; callers must check
}

export function randomLetters(length: number): string {
  let out = "";
  while (out.length < length) {
    out += lettersFromBytes(randomBytes(length * 2), length - out.length);
  }
  return out;
}

/**
 * Stable JSON: the same data always produces the same text, whatever order
 * the keys were added in. Needed because we hash and sign JSON, and a
 * signature must not change just because a key moved.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const s = JSON.stringify(value);
    return s === undefined ? "null" : s;
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}
