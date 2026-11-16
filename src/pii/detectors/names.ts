/**
 * Names from a client-supplied list.
 *
 * KRIS Guard does NOT recognise names by itself. It only hides the names a
 * client lists in its policy file. A name that is not on the list goes
 * through untouched. (Telling a name from an ordinary word needs a language
 * model, and Kinyarwanda names are often ordinary words: Mugisha means
 * "blessing", Keza means "beautiful", Amahoro means "peace".)
 *
 * Matching rules:
 *  - Upper/lower case does not matter: "MUGISHA", "mugisha", "Mugisha".
 *  - Accents do not matter: "Aimé" matches "Aime".
 *  - Only whole words match: "Keza" does not match inside "Mukakeza".
 *  - A multi-word name matches across any spacing or a hyphen:
 *    "Jean Pierre" matches "Jean-Pierre" and "Jean  Pierre".
 *  - "Mugisha's" and "kwa Mugisha" match, because the name is still a whole word.
 *
 * To hide a first name on its own, list it on its own.
 *
 * How it works: instead of one enormous pattern (slow with thousands of
 * names), the text is split into words once, and each word is looked up in a
 * table keyed by the first word of every listed name. That keeps the cost
 * proportional to the length of the text, however long the list is.
 */
import type { Detector, PiiMatch } from "../types.js";

const WORD = /[\p{L}\p{M}\p{N}]+/gu;
/** What may sit between two words of one name: spaces, or one hyphen/apostrophe/dot/comma with spaces. */
const GAP_OK = /^[\s ]*[-'’.,]?[\s ]*$/;

/** Lower-case and strip accents, so "Aimé" and "AIME" compare equal. */
function fold(word: string): string {
  return word.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
}

function wordsOf(s: string): string[] {
  return (s.match(WORD) ?? []).map(fold).filter((w) => w.length > 0);
}

export const MAX_NAMES = 20_000;

/** Build a detector for one client's list of names. Build once, reuse for every request. */
export function createNameDetector(names: readonly string[]): Detector {
  // first word -> all listed names starting with it, longest first
  const index = new Map<string, string[][]>();
  for (const name of names) {
    const words = wordsOf(name);
    if (words.length === 0) continue;
    if (words.length === 1 && words[0]!.length < 2) continue; // a single letter is not a name
    const first = words[0]!;
    const list = index.get(first) ?? [];
    list.push(words);
    index.set(first, list);
  }
  for (const list of index.values()) list.sort((a, b) => b.length - a.length);

  if (index.size === 0) return () => [];

  return (text) => {
    const tokens: Array<{ folded: string; start: number; end: number }> = [];
    WORD.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = WORD.exec(text)) !== null) {
      tokens.push({ folded: fold(m[0]), start: m.index, end: m.index + m[0].length });
    }

    const out: PiiMatch[] = [];
    let i = 0;
    while (i < tokens.length) {
      const candidates = index.get(tokens[i]!.folded);
      let matchedWords = 0;
      if (candidates) {
        for (const words of candidates) {
          if (i + words.length > tokens.length) continue;
          let ok = true;
          for (let k = 1; k < words.length; k++) {
            const prev = tokens[i + k - 1]!;
            const cur = tokens[i + k]!;
            if (cur.folded !== words[k] || !GAP_OK.test(text.slice(prev.end, cur.start))) {
              ok = false;
              break;
            }
          }
          if (ok) {
            matchedWords = words.length;
            break; // candidates are sorted longest first
          }
        }
      }
      if (matchedWords > 0) {
        out.push({
          type: "NAME",
          start: tokens[i]!.start,
          end: tokens[i + matchedWords - 1]!.end,
          priority: 30,
        });
        i += matchedWords;
      } else {
        i += 1;
      }
    }
    return out;
  };
}
