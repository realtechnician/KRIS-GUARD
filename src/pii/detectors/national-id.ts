/**
 * Rwandan national ID numbers.
 *
 * What is certain: the number has 16 digits (required by the 2008 law on
 * national identity cards).
 *
 * [VERIFY] The reported layout, from a news report and not from an official
 * NIDA specification, is:
 *
 *     1 1990 8 0012345 0 67
 *     │ │    │ │       │ └─ 2 check digits
 *     │ │    │ │       └─── how many times the card was issued
 *     │ │    │ └─────────── birth order number (7 digits)
 *     │ │    └───────────── sex: 8 = male, 7 = female
 *     │ └────────────────── year of birth
 *     └──────────────────── status: 1 citizen, 2 refugee, 3 foreigner
 *
 * Because that layout is not confirmed, this detector relies ONLY on:
 *   - exactly 16 digits (written together, or with spaces/dots/hyphens), and
 *   - digits 2 to 5 forming a believable year of birth (1900 to this year).
 *
 * It deliberately does NOT require the status digit to be 1-3 or the sex
 * digit to be 7 or 8. If those details turn out to be wrong, we still catch
 * the number. The price is the occasional false alarm (for example a 16-digit
 * card number whose digits happen to look like a year), which is harmless:
 * the value is hidden and then put back in the answer.
 */
import { SEP, digitsOnly, scan, type Detector, type PiiMatch } from "../types.js";

const RE = new RegExp(`(?<!\\d)\\d(?:${SEP}?\\d){15}(?!\\d)`, "g");

export const detectNationalId: Detector = (text) => {
  const thisYear = new Date().getUTCFullYear();
  return scan(RE, text, (m) => {
    const digits = digitsOnly(m[0]);
    if (digits.length !== 16) return null;
    const year = Number(digits.slice(1, 5));
    if (year < 1900 || year > thisYear) return null;
    return { start: m.index, end: m.index + m[0].length };
  }).map((s): PiiMatch => ({ ...s, type: "NATIONAL_ID", priority: 90 }));
};
