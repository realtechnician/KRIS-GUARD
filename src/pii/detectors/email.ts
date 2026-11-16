/**
 * Email addresses.
 *
 * The pattern is deliberately simple and bounded (the part before the @ is at
 * most 64 characters, each part of the domain at most 63), so it always runs
 * quickly even on hostile input. It covers ordinary addresses; exotic but
 * technically legal ones (quoted names, non-Latin letters) are not detected.
 */
import { scan, type Detector, type PiiMatch } from "../types.js";

const RE =
  /(?<![A-Za-z0-9._%+\-])[A-Za-z0-9_%+\-](?:[A-Za-z0-9._%+\-]{0,63})@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62})(?:\.[A-Za-z0-9\-]{1,63})+/g;

export const detectEmail: Detector = (text) => {
  // Cheap early exit: no "@" means no email.
  if (!text.includes("@")) return [];
  return scan(RE, text, (m) => {
    let value = m[0];
    // A sentence may end right after the address: "write to a@b.rw." or "a@b.rw-"
    value = value.replace(/[.\-]+$/, "");
    if (!/\.[A-Za-z]{2,}$/.test(value)) return null; // must end in a real-looking domain ending
    return { start: m.index, end: m.index + value.length };
  }).map((s): PiiMatch => ({ ...s, type: "EMAIL", priority: 100 }));
};
