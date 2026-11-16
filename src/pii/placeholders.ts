/**
 * Placeholders: the stand-ins the AI provider sees instead of personal data.
 *
 * A placeholder looks like this:
 *
 *     [[KG-PHONE-QZKWMXRTPLANBVCD]]
 *       │  │     └─ 16 random capital letters (about 75 bits of randomness)
 *       │  └─────── what kind of data it stands for
 *       └────────── "KRIS Guard"
 *
 * Why this shape:
 *  - The double brackets and "KG-" make it unlike anything in normal writing.
 *  - The kind (PHONE, EMAIL...) lets the AI still write a sensible sentence
 *    ("I will call [[KG-PHONE-...]]") without knowing the number.
 *  - Letters only, no digits: a placeholder can never itself look like a
 *    phone number or ID to our detectors.
 *  - Only characters that survive JSON, Markdown and HTML unchanged, so the
 *    AI can copy it back exactly.
 *
 * Two ways to choose the 16 letters (set per client in the policy file):
 *
 *  - "random" (default): fresh random letters for every request. The same
 *    phone number gets a different placeholder each time, so the provider
 *    cannot link two requests through it.
 *
 *  - "stable": the letters are computed from the value with a secret key that
 *    is specific to the client. The same value always gets the same
 *    placeholder for that client. The provider can then tell that two requests
 *    mention the same (unknown) value, but long conversations stay
 *    byte-for-byte identical between turns, which the provider's prompt cache
 *    and its "thinking" feature both require. See README, "Honest limits".
 *
 * In both modes the list of "placeholder = real value" exists ONLY in this
 * object, in memory, for one request. It is never saved or logged.
 */
import { hmacBytes, lettersFromBytes, randomLetters } from "../crypto.js";
import type { PiiType } from "./types.js";

export const TOKEN_LENGTH = 16;

const LABELS: Record<PiiType, string> = {
  NATIONAL_ID: "ID",
  PHONE: "PHONE",
  EMAIL: "EMAIL",
  TIN: "TIN",
  BANK_ACCOUNT: "ACCOUNT",
  NAME: "NAME",
};

/** Matches any well-formed KRIS Guard placeholder. */
export const PLACEHOLDER_RE = /\[\[KG-(?:ID|PHONE|EMAIL|TIN|ACCOUNT|NAME)-[A-Z]{16}\]\]/g;

/** Every placeholder starts with this; used to spot one being cut in half by streaming. */
export const PLACEHOLDER_START = "[[KG-";

/** The longest a placeholder can be, in characters. */
export const MAX_PLACEHOLDER_LENGTH = "[[KG-ACCOUNT-".length + TOKEN_LENGTH + 2;

export type PlaceholderMode = { kind: "random" } | { kind: "stable"; key: Buffer };

export class PlaceholderMap {
  private readonly byValue = new Map<string, string>();
  private readonly byPlaceholder = new Map<string, string>();
  private readonly mode: PlaceholderMode;
  /** True if the request text already contains something shaped like a placeholder. */
  private readonly avoidText: string | null;

  /**
   * @param requestText the raw request, used in "random" mode to make sure a
   *   new placeholder does not already appear somewhere in the request.
   */
  constructor(mode: PlaceholderMode, requestText: string) {
    this.mode = mode;
    this.avoidText = mode.kind === "random" && requestText.includes(PLACEHOLDER_START) ? requestText : null;
  }

  /** Get (or create) the placeholder for one real value. */
  placeholderFor(type: PiiType, value: string): string {
    const key = `${type}\u0000${value}`;
    const existing = this.byValue.get(key);
    if (existing) return existing;

    const label = LABELS[type];
    let placeholder: string;

    if (this.mode.kind === "random") {
      // Try again in the (astronomically unlikely) event of a clash.
      do {
        placeholder = `[[KG-${label}-${randomLetters(TOKEN_LENGTH)}]]`;
      } while (this.byPlaceholder.has(placeholder) || (this.avoidText?.includes(placeholder) ?? false));
    } else {
      let token = "";
      for (let round = 0; token.length < TOKEN_LENGTH && round < 8; round++) {
        token += lettersFromBytes(hmacBytes(this.mode.key, `${round}\u0000${key}`), TOKEN_LENGTH - token.length);
      }
      placeholder = `[[KG-${label}-${token}]]`;
      const clash = this.byPlaceholder.get(placeholder);
      if (token.length !== TOKEN_LENGTH || (clash !== undefined && clash !== value)) {
        // Two different values must never share a placeholder. Refuse rather than risk a mix-up.
        throw new Error("placeholder collision");
      }
    }

    this.byValue.set(key, placeholder);
    this.byPlaceholder.set(placeholder, value);
    return placeholder;
  }

  /** The real value for a placeholder, or undefined if we did not create it. */
  valueFor(placeholder: string): string | undefined {
    return this.byPlaceholder.get(placeholder);
  }

  get size(): number {
    return this.byPlaceholder.size;
  }

  /** Every placeholder this request created (no real values). */
  placeholders(): string[] {
    return [...this.byPlaceholder.keys()];
  }

  /**
   * Put real values back into a text.
   *
   * Only an EXACT placeholder that this request created is replaced. If the
   * AI altered one (dropped a bracket, changed a letter), it matches nothing
   * and stays as it is. We never guess which value was meant.
   */
  restore(text: string): string {
    if (this.byPlaceholder.size === 0 || !text.includes(PLACEHOLDER_START)) return text;
    return text.replace(PLACEHOLDER_RE, (ph) => this.byPlaceholder.get(ph) ?? ph);
  }
}

/** Count placeholders still present in a text (after restoring, these are ones we could not restore). */
export function countPlaceholders(text: string): number {
  if (!text.includes(PLACEHOLDER_START)) return 0;
  let n = 0;
  for (const _ of text.matchAll(PLACEHOLDER_RE)) n++;
  return n;
}
