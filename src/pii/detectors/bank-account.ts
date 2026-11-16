/**
 * Bank account numbers.
 *
 * THIS IS THE WEAKEST DETECTOR. Rwanda has no single national account-number
 * format and does not use IBAN, so each bank has its own layout and length.
 * [VERIFY] the formats of the banks your clients actually use, and add them.
 *
 * Four rules, from most to least certain:
 *
 *  1. IBAN (foreign accounts): has a built-in checksum, so it is reliable.
 *  2. A number of 9 to 20 digits shortly after a banking word ("account",
 *     "konti", "compte", "A/C") or a bank's name.
 *  3. Three groups of digits joined by hyphens, like 00040-06945754-07
 *     [VERIFY: a layout seen on Bank of Kigali accounts].
 *  4. Any unbroken run of 11 to 20 digits. Numbers that long are almost never
 *     amounts of money, so we hide them to be safe.
 *
 * Expect both misses (a short account number with no banking word near it)
 * and false alarms (a long order number hidden as if it were an account).
 * A false alarm is harmless: the value is hidden, then put back in the answer.
 */
import { digitsOnly, scan, type Detector, type PiiMatch } from "../types.js";

const WORDS = [
  "accounts?",
  "acct\\.?",
  "a\\/c",
  "acc\\.?\\s*(?:no|number|#)",
  "konti",
  "compte",
  "bank",
  "banki",
  "banque",
  "equity",
  "cogebanque",
  "ecobank",
  "urwego",
  "unguka",
  "zigama",
  "umwalimu",
  "sacco",
  "i\\s?&\\s?m",
].join("|");

// Short bank names are only matched in capitals, so the English words "bk"
// or "boa" in lower case do not count.
const ACRONYMS = ["BK", "BPR", "KCB", "BOA", "NCBA", "GTB", "GT\\s?Bank", "AB\\s?Bank", "BNR"].join("|");

// The account number itself: digits in one block, or in groups joined by ONE
// kind of separator (all spaces, or all hyphens). Mixing is not allowed, so a
// date and time such as "2021-03-12 14:30" is not mistaken for an account.
// Group 1 is the whole number; group 2 is the separator (used by "\\2").
const NUMBER = "(\\d{1,20}(?:([ \\u00A0\\-])\\d{1,20}(?:\\2\\d{1,20}){0,6})?)(?!\\d)";
const GAP = "[^\\d\\n]{0,30}?";

const RE_WORD_CONTEXT = new RegExp(`(?<![\\p{L}\\p{N}])(?:${WORDS})(?![\\p{L}])${GAP}${NUMBER}`, "giud");
const RE_ACRONYM_CONTEXT = new RegExp(`(?<![\\p{L}\\p{N}])(?:${ACRONYMS})(?![\\p{L}])${GAP}${NUMBER}`, "gud");
const RE_HYPHEN_GROUPS = /(?<![\d\-])\d{3,6}-\d{5,12}-\d{2,3}(?![\d\-])/g;
const RE_LONG_RUN = /(?<!\d)\d{11,20}(?!\d)/g;
const RE_IBAN = /(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])/g;

/** The standard IBAN checksum (ISO 13616, "mod 97"). */
function ibanIsValid(candidate: string): boolean {
  const s = candidate.replace(/ /g, "");
  if (s.length < 15 || s.length > 34) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const value = code >= 65 ? String(code - 55) : ch; // A=10 ... Z=35
    for (const d of value) remainder = (remainder * 10 + Number(d)) % 97;
  }
  return remainder === 1;
}

/**
 * Words that, between the banking word and the number, show the number is an
 * AMOUNT of money and not an account: "bank balance 150000000".
 */
const AMOUNT_WORDS =
  /\b(?:balance|solde|amount|montant|total|sum|deposit(?:ed)?|paid|pay(?:ment)?|fee|frais|amafaranga|frw|rwf|usd|eur)\b/i;
const CURRENCY_AFTER = /^\s?(?:rwf|frw|usd|eur|francs?|\$|€)/i;

function contextMatches(re: RegExp, text: string): PiiMatch[] {
  return scan(re, text, (m) => {
    const group = m.indices?.[1];
    if (!group) return null;
    const n = digitsOnly(text.slice(group[0], group[1])).length;
    if (n < 9 || n > 20) return null;
    // Long numbers are hidden whatever the wording (rule 4). For shorter ones,
    // skip those that are clearly amounts of money.
    if (n < 11) {
      if (AMOUNT_WORDS.test(text.slice(m.index, group[0]))) return null;
      if (CURRENCY_AFTER.test(text.slice(group[1], group[1] + 8))) return null;
    }
    return { start: group[0], end: group[1] };
  }).map((s): PiiMatch => ({ ...s, type: "BANK_ACCOUNT", priority: 60 }));
}

export const detectBankAccount: Detector = (text) => {
  const out: PiiMatch[] = [];

  for (const s of scan(RE_IBAN, text, (m) =>
    ibanIsValid(m[0]) ? { start: m.index, end: m.index + m[0].length } : null,
  )) {
    out.push({ ...s, type: "BANK_ACCOUNT", priority: 95 });
  }

  out.push(...contextMatches(RE_WORD_CONTEXT, text));
  out.push(...contextMatches(RE_ACRONYM_CONTEXT, text));

  for (const s of scan(RE_HYPHEN_GROUPS, text, (m) => ({ start: m.index, end: m.index + m[0].length }))) {
    out.push({ ...s, type: "BANK_ACCOUNT", priority: 50 });
  }
  for (const s of scan(RE_LONG_RUN, text, (m) => ({ start: m.index, end: m.index + m[0].length }))) {
    out.push({ ...s, type: "BANK_ACCOUNT", priority: 40 });
  }
  return out;
};
