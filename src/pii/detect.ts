/**
 * Runs every detector over a text and combines what they found into one
 * clean list of "hide this" spans.
 */
import { detectBankAccount } from "./detectors/bank-account.js";
import { detectEmail } from "./detectors/email.js";
import { detectNationalId } from "./detectors/national-id.js";
import { detectPhone } from "./detectors/phone.js";
import { detectTin } from "./detectors/tin.js";
import { PLACEHOLDER_RE } from "./placeholders.js";
import type { Detector, PiiMatch } from "./types.js";

/** The detectors that need no configuration. */
export const BUILT_IN_DETECTORS: readonly Detector[] = [
  detectEmail,
  detectNationalId,
  detectPhone,
  detectTin,
  detectBankAccount,
];

/**
 * Find all personal data in `text`.
 *
 * Two clean-up steps:
 *
 * 1. Anything inside one of OUR placeholders is ignored. A placeholder such as
 *    [[KG-PHONE-ABCD...]] is not personal data, even if a client happens to
 *    list "Phone" as a name.
 *
 * 2. Overlapping findings are MERGED into one span. If one detector says
 *    characters 10-20 are a phone number and another says 10-27 are a bank
 *    account, we hide 10-27. Hiding slightly too much is safe; hiding too
 *    little is a leak. The label comes from the most confident detector.
 */
export function detectAll(text: string, detectors: readonly Detector[]): PiiMatch[] {
  if (text.length === 0) return [];

  let found: PiiMatch[] = [];
  for (const detect of detectors) {
    for (const m of detect(text)) found.push(m);
  }
  if (found.length === 0) return [];

  if (text.includes("[[KG-")) {
    const protectedSpans: Array<[number, number]> = [];
    for (const m of text.matchAll(PLACEHOLDER_RE)) {
      protectedSpans.push([m.index, m.index + m[0].length]);
    }
    if (protectedSpans.length > 0) {
      found = found.filter((f) => !protectedSpans.some(([s, e]) => f.start < e && f.end > s));
    }
  }

  found.sort((a, b) => a.start - b.start || b.end - a.end);

  const merged: PiiMatch[] = [];
  for (const m of found) {
    const last = merged[merged.length - 1];
    if (last && m.start < last.end) {
      if (m.end > last.end) last.end = m.end;
      if (m.priority > last.priority) {
        last.priority = m.priority;
        last.type = m.type;
      }
    } else {
      merged.push({ ...m });
    }
  }
  return merged;
}
