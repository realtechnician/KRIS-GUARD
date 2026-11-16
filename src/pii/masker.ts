/**
 * The Masker: hides personal data in a text, and remembers what it hid.
 *
 * One Masker is created per request and thrown away when the request ends.
 */
import { detectAll } from "./detect.js";
import { PlaceholderMap, type PlaceholderMode } from "./placeholders.js";
import type { Detector, PiiType } from "./types.js";

export class ResidualPiiError extends Error {
  constructor() {
    super("personal data remained after masking");
    this.name = "ResidualPiiError";
  }
}

export class Masker {
  readonly map: PlaceholderMap;
  private readonly detectors: readonly Detector[];
  /** How many values of each kind were hidden. Only COUNTS are kept, never values. */
  readonly hidden: Partial<Record<PiiType, number>> = {};

  constructor(detectors: readonly Detector[], mode: PlaceholderMode, requestText: string) {
    this.detectors = detectors;
    this.map = new PlaceholderMap(mode, requestText);
  }

  /** Which kinds of personal data are in this text? Changes nothing. */
  find(text: string): PiiType[] {
    return [...new Set(detectAll(text, this.detectors).map((m) => m.type))];
  }

  /**
   * Replace every piece of personal data in `text` with a placeholder.
   *
   * After replacing, the result is checked AGAIN. If anything is still
   * detected, masking has a bug, and we refuse to continue (fail closed)
   * rather than send the text on.
   */
  mask(text: string): string {
    const matches = detectAll(text, this.detectors);
    if (matches.length === 0) return text;

    let out = "";
    let cursor = 0;
    for (const m of matches) {
      out += text.slice(cursor, m.start);
      out += this.map.placeholderFor(m.type, text.slice(m.start, m.end));
      cursor = m.end;
      this.hidden[m.type] = (this.hidden[m.type] ?? 0) + 1;
    }
    out += text.slice(cursor);

    if (detectAll(out, this.detectors).length > 0) throw new ResidualPiiError();
    return out;
  }

  restore(text: string): string {
    return this.map.restore(text);
  }
}
