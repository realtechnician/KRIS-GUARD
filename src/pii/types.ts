/**
 * Shared types for personal-data ("PII") detection.
 */

/** The kinds of personal data KRIS Guard looks for. */
export type PiiType = "NATIONAL_ID" | "PHONE" | "EMAIL" | "TIN" | "BANK_ACCOUNT" | "NAME";

export const PII_TYPES: readonly PiiType[] = [
  "NATIONAL_ID",
  "PHONE",
  "EMAIL",
  "TIN",
  "BANK_ACCOUNT",
  "NAME",
];

/** One piece of personal data found in a text: what kind, and where. */
export interface PiiMatch {
  type: PiiType;
  /** Position of the first character. */
  start: number;
  /** Position just after the last character. */
  end: number;
  /**
   * When two detectors claim the same characters, the higher number wins.
   * It only decides the LABEL; either way the text gets hidden.
   */
  priority: number;
}

/** A detector reads a text and reports what it found. It must never change the text. */
export type Detector = (text: string) => PiiMatch[];

/**
 * Characters allowed BETWEEN digits of one number: a space, a non-breaking
 * space, a narrow no-break space, a dot or a hyphen. People write
 * "0788 123 456", "0788-123-456" and "0788.123.456" for the same number.
 */
export const SEP = "[ \\u00A0\\u202F.\\-]";

/**
 * Run a regular expression over a text and collect the matches that pass an
 * extra check. If a candidate fails the check we move forward by ONE character
 * (not past the whole candidate), so a real match that starts inside a
 * rejected one is not skipped.
 */
export function scan(
  re: RegExp,
  text: string,
  onMatch: (m: RegExpExecArray) => { start: number; end: number } | null,
): Array<{ start: number; end: number }> {
  if (!re.global) throw new Error("scan() needs a global regular expression");
  const out: Array<{ start: number; end: number }> = [];
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const span = onMatch(m);
    if (span && span.end > span.start) {
      out.push(span);
      re.lastIndex = span.end;
    } else {
      re.lastIndex = m.index + 1;
    }
  }
  return out;
}

export function digitsOnly(s: string): string {
  return s.replace(/\D/g, "");
}
