/**
 * Tools for walking through a request and treating every piece of text in one
 * of four ways. Every string in a request must end up in exactly one of them:
 *
 *   MASK      Free text (a message, a description, a tool result). Personal
 *             data is replaced with placeholders.
 *
 *   FREEFORM  Arbitrary data (a tool's input, a JSON schema, metadata). Every
 *             string inside it, at any depth, is masked. So are the property
 *             names, and long numbers.
 *
 *   CHECK     A field whose exact value matters to the provider (a model
 *             name, a tool name, an id). We cannot replace it with a
 *             placeholder without breaking the request, so if it contains
 *             personal data the whole request is BLOCKED.
 *
 *   OPAQUE    Sealed data we cannot read and must not change (an encrypted
 *             signature). Passed through untouched.
 *
 * Fields that KRIS Guard does not recognise are handled as CHECK or FREEFORM,
 * never skipped. A new API feature is therefore scanned from day one.
 */
import { GuardError } from "../errors.js";
import type { Masker } from "./masker.js";

export interface Attachment {
  /** Where it is in the request, e.g. "messages[0].content[1]". */
  path: string;
  /** What kind of thing it is, e.g. "image", "document". */
  kind: string;
}

export interface WalkContext {
  masker: Masker;
  attachments: Attachment[];
  /**
   * Planted-instruction screening (see src/injection/). Called on every
   * piece of UNTRUSTED text before it is masked; returns the text to use.
   * Absent means screening is off.
   */
  screen?: (text: string) => string;
  /** Above zero while walking text that came from outside: tool results, documents, search results. */
  untrustedDepth?: number;
  /** Also treat what the user typed as untrusted (a per-client choice). */
  screenUserMessages?: boolean;
}

/** Run `fn` with everything it walks marked as untrusted text. */
export function untrusted<T>(ctx: WalkContext, fn: () => T): T {
  ctx.untrustedDepth = (ctx.untrustedDepth ?? 0) + 1;
  try {
    return fn();
  } finally {
    ctx.untrustedDepth -= 1;
  }
}

function screened(ctx: WalkContext, text: string): string {
  return ctx.screen && (ctx.untrustedDepth ?? 0) > 0 ? ctx.screen(text) : text;
}

const MAX_DEPTH = 100;

/** Sealed values that cannot be read and must be passed back exactly. */
const OPAQUE_KEYS = new Set(["signature", "encrypted_content", "encrypted_index", "authorization_token"]);

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Set a property so that it is always an ordinary property, even when the
 * name is "__proto__". (Assigning to "__proto__" the normal way would quietly
 * change the object's behaviour instead of storing the value.)
 */
export function setOwn(obj: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

function joinPath(path: string, key: string): string {
  return path === "" ? key : `${path}.${key}`;
}

/**
 * Does this string look like encoded binary data (a file squeezed into text)?
 * Such data cannot be scanned, and replacing "digits" inside it would corrupt
 * the file. It is treated as an attachment.
 */
export function looksLikeBinary(s: string): boolean {
  if (s.startsWith("data:") && s.slice(0, 200).includes(";base64,")) return true;
  return s.length >= 256 && /^[A-Za-z0-9+/_\-]+={0,2}$/.test(s);
}

function blockUnmaskable(path: string): never {
  throw new GuardError(
    "unmaskable_personal_data",
    `KRIS Guard found personal data in a field that cannot be hidden (${path}). ` +
      "Names of models and tools, and ids, must not contain personal data. The request was blocked.",
  );
}

function tooDeep(): never {
  throw new GuardError("invalid_request", "KRIS Guard: the request is nested too deeply to be checked.");
}

/**
 * Numbers can be personal data too: {"phone": 250788123456}.
 * Short numbers are skipped (nothing we detect has fewer than 9 digits).
 * A 13-digit whole number in the range used for "milliseconds since 1970"
 * timestamps (years 2001 to 2039) is also skipped; those are everywhere in
 * tool data, and bank accounts are normally stored as text, not numbers.
 */
function numberNeedsCheck(n: number): boolean {
  if (!Number.isFinite(n) || !Number.isInteger(n)) return false;
  const abs = Math.abs(n);
  if (abs < 100_000_000) return false;
  if (abs >= 1_000_000_000_000 && abs < 2_200_000_000_000) return false;
  return true;
}

/** MASK: hide personal data in one text. */
export function maskText(ctx: WalkContext, value: unknown, path: string): unknown {
  if (typeof value === "string") return ctx.masker.mask(screened(ctx, value));
  // Not a string where a string was expected: fall back to the safest generic handling.
  return maskFreeform(ctx, value, path, 0);
}

/** FREEFORM: hide personal data everywhere inside arbitrary data. */
export function maskFreeform(ctx: WalkContext, value: unknown, path: string, depth = 0): unknown {
  if (depth > MAX_DEPTH) tooDeep();
  if (typeof value === "string") {
    if (looksLikeBinary(value)) {
      ctx.attachments.push({ path, kind: "embedded file data" });
      return value;
    }
    return ctx.masker.mask(screened(ctx, value));
  }
  if (typeof value === "number") {
    if (!numberNeedsCheck(value)) return value;
    const asText = String(value);
    const masked = ctx.masker.mask(asText);
    return masked === asText ? value : masked;
  }
  if (Array.isArray(value)) {
    return value.map((v, i) => maskFreeform(ctx, v, `${path}[${i}]`, depth + 1));
  }
  if (isObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (OPAQUE_KEYS.has(k)) {
        setOwn(out, k, v);
        continue;
      }
      // Property names are data too: {"0788123456": "balance"}.
      const safeKey = ctx.masker.mask(k);
      // The path shown in errors uses "*" instead of the real name, which could itself be personal data.
      setOwn(out, safeKey, maskFreeform(ctx, v, `${path}.*`, depth + 1));
    }
    return out;
  }
  return value;
}

/** CHECK: verify there is no personal data; block the request if there is. */
export function checkOnly(ctx: WalkContext, value: unknown, path: string, depth = 0): void {
  if (depth > MAX_DEPTH) tooDeep();
  if (typeof value === "string") {
    if (looksLikeBinary(value)) {
      ctx.attachments.push({ path, kind: "embedded file data" });
      return;
    }
    if (ctx.masker.find(value).length > 0) blockUnmaskable(path);
    return;
  }
  if (typeof value === "number") {
    if (numberNeedsCheck(value) && ctx.masker.find(String(value)).length > 0) blockUnmaskable(path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => checkOnly(ctx, v, `${path}[${i}]`, depth + 1));
    return;
  }
  if (isObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (OPAQUE_KEYS.has(k)) continue;
      if (ctx.masker.find(k).length > 0) blockUnmaskable(joinPath(path, "*"));
      checkOnly(ctx, v, joinPath(path, safePathKey(k)), depth + 1);
    }
  }
}

/** Only plain identifier-like names are echoed in error paths. */
function safePathKey(k: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]{0,40}$/.test(k) ? k : "*";
}

/**
 * Walk an object field by field. `handlers` says what to do with the fields
 * we know; every other field gets `fallback` (CHECK unless stated otherwise).
 */
export function walkFields(
  ctx: WalkContext,
  obj: Record<string, unknown>,
  path: string,
  handlers: Record<string, (value: unknown, path: string) => unknown>,
  fallback: "check" | "freeform" = "check",
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    const p = joinPath(path, safePathKey(k));
    const handler = Object.hasOwn(handlers, k) ? handlers[k] : undefined;
    if (handler) {
      setOwn(out, k, handler(v, p));
    } else if (OPAQUE_KEYS.has(k)) {
      setOwn(out, k, v);
    } else if (fallback === "freeform") {
      if (ctx.masker.find(k).length > 0) blockUnmaskable(joinPath(path, "*"));
      setOwn(out, k, maskFreeform(ctx, v, p));
    } else {
      if (ctx.masker.find(k).length > 0) blockUnmaskable(joinPath(path, "*"));
      checkOnly(ctx, v, p);
      setOwn(out, k, v);
    }
  }
  return out;
}

/** Handler helpers, so the walkers read like a table. */
export const keep = (v: unknown): unknown => v;
export const check =
  (ctx: WalkContext) =>
  (v: unknown, p: string): unknown => {
    checkOnly(ctx, v, p);
    return v;
  };
export const mask =
  (ctx: WalkContext) =>
  (v: unknown, p: string): unknown =>
    maskText(ctx, v, p);
export const freeform =
  (ctx: WalkContext) =>
  (v: unknown, p: string): unknown =>
    maskFreeform(ctx, v, p);

/**
 * Deep-restore: put real values back everywhere inside a piece of data
 * (used on answers). `skip` lets a caller leave some objects untouched.
 */
export function restoreDeep(
  masker: Masker,
  value: unknown,
  skip?: (obj: Record<string, unknown>) => boolean,
  depth = 0,
): unknown {
  if (depth > MAX_DEPTH) return value;
  if (typeof value === "string") return masker.restore(value);
  if (Array.isArray(value)) return value.map((v) => restoreDeep(masker, v, skip, depth + 1));
  if (isObject(value)) {
    if (skip?.(value)) return value;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (OPAQUE_KEYS.has(k)) {
        setOwn(out, k, v);
        continue;
      }
      setOwn(out, masker.restore(k), restoreDeep(masker, v, skip, depth + 1));
    }
    return out;
  }
  return value;
}
