/**
 * TIN: the Taxpayer Identification Number issued by the Rwanda Revenue
 * Authority (RRA).
 *
 * [VERIFY] Third-party guides agree a TIN is 9 digits. I found no RRA page
 * that states the format directly.
 *
 * A bare 9-digit number is far too ordinary to treat as a TIN on its own:
 * "150000000" is also 150 million francs. Hiding every 9-digit number would
 * stop the AI doing sums. So a 9-digit number is treated as a TIN ONLY when a
 * word such as "TIN" or "NIF" appears shortly before it.
 *
 * LIMIT: a TIN written with no such word nearby is NOT detected.
 *
 * [VERIFY] "nimero iranga usora" is my understanding of the Kinyarwanda
 * phrase RRA uses for TIN.
 */
import { SEP, scan, type Detector, type PiiMatch } from "../types.js";

const KEYWORDS = [
  "T\\.?I\\.?N\\.?",
  "NIF",
  "VAT\\s+(?:reg(?:istration)?\\.?\\s+)?(?:number|no\\.?|nr\\.?)",
  "num[ée]ro\\s+(?:de\\s+)?TVA",
  "tax(?:payer)?\\s+id(?:entification)?(?:\\s+(?:number|no\\.?|nr\\.?))?",
  "taxpayer\\s+number",
  "nimero\\s+iranga\\s+usora",
  "num[ée]ro\\s+d[’']identification\\s+fiscale",
].join("|");

// keyword, then up to 25 characters that are not digits or a new line
// (": ", " number is ", " (RRA) "), then exactly 9 digits.
const RE = new RegExp(
  `(?<![\\p{L}\\p{N}])(?:${KEYWORDS})(?![\\p{L}])[^\\d\\n]{0,25}?(\\d(?:${SEP}?\\d){8})(?!\\d)`,
  "giud",
);

export const detectTin: Detector = (text) => {
  return scan(RE, text, (m) => {
    const group = m.indices?.[1];
    if (!group) return null;
    return { start: group[0], end: group[1] };
  }).map((s): PiiMatch => ({ ...s, type: "TIN", priority: 70 }));
};
