/**
 * Rwandan phone numbers and MoMo numbers.
 *
 * A MoMo (Mobile Money) number IS a mobile phone number, so one detector
 * covers both.
 *
 * Rwanda's country code is +250. A mobile number has 9 digits after it, and
 * is written locally with a leading 0, for example:
 *
 *     +250 788 123 456     250788123456     00250 788 123 456
 *     0788 123 456         0788-123-456     078 812 3456
 *
 * [VERIFY] Mobile prefixes reported today: 078 and 079 (MTN), 072 and 073
 * (Airtel). The published RURA numbering plan is older than these
 * assignments. So that a newly assigned prefix is not missed, this detector
 * treats ANY 10-digit number starting with "07" as a phone number.
 *
 * [VERIFY] Landlines appear to be written 0252 xxx xxx or 0222 xxx xxx
 * (+250 252 ...). Sources disagree, so the local landline rule (025x, 022x,
 * 028x) is a best guess. Any number written with +250 is caught regardless of
 * its prefix.
 *
 * NOT covered: MoMoPay merchant codes (short codes used to pay a shop). They
 * identify a business, not a person, and their format is not documented.
 */
import { SEP, digitsOnly, scan, type Detector, type PiiMatch } from "../types.js";

const PATTERNS: Array<{ re: RegExp; digits: [number, number] }> = [
  // +250 / 00250, optional ")" for "(+250)", then 9 digits (optionally "(0)" first).
  {
    re: new RegExp(
      `(?<![\\d+])(?:\\+ ?|00)250\\)?${SEP}?(?:\\(0\\)${SEP}?)?\\d(?:${SEP}?\\d){8}(?!\\d)`,
      "g",
    ),
    digits: [12, 15],
  },
  // 250 7xx xxx xxx without the plus sign.
  { re: new RegExp(`(?<!\\d)250${SEP}?7\\d(?:${SEP}?\\d){7}(?!\\d)`, "g"), digits: [12, 12] },
  // Local mobile: 07x xxx xxxx (10 digits).
  { re: new RegExp(`(?<!\\d)07\\d(?:${SEP}?\\d){7}(?!\\d)`, "g"), digits: [10, 10] },
  // Local landline [VERIFY]: 025x / 022x / 028x xxx xxx (10 digits).
  { re: new RegExp(`(?<!\\d)02[258]\\d(?:${SEP}?\\d){6}(?!\\d)`, "g"), digits: [10, 10] },
  // Any other international number written with a plus sign: + and 8 to 15 digits.
  {
    re: new RegExp(`(?<![\\d+\\p{L}])\\+\\d(?:${SEP}?\\d){7,14}(?!\\d)`, "gu"),
    digits: [8, 15],
  },
];

export const detectPhone: Detector = (text) => {
  const out: PiiMatch[] = [];
  for (const { re, digits } of PATTERNS) {
    for (const span of scan(re, text, (m) => {
      const n = digitsOnly(m[0]).length;
      if (n < digits[0] || n > digits[1]) return null;
      return { start: m.index, end: m.index + m[0].length };
    })) {
      out.push({ ...span, type: "PHONE", priority: 80 });
    }
  }
  return out;
};
