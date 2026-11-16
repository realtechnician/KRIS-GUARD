/**
 * Restoring placeholders in a STREAMED answer.
 *
 * When an answer is streamed, it arrives in small pieces. A placeholder can be
 * cut anywhere:
 *
 *     piece 1:  "Please call [[KG-PHO"
 *     piece 2:  "NE-QZKWMXRTPLANBVCD]] today"
 *
 * If we passed piece 1 straight through, the user would see half a
 * placeholder and we could never fix it. So this class holds back the END of
 * the text whenever it could be the beginning of one of our placeholders, and
 * releases it once the next piece shows whether it really was one.
 *
 * It holds back as little as possible: only a tail that exactly matches the
 * start of a placeholder this request actually created.
 */
import { PLACEHOLDER_START, type PlaceholderMap } from "./placeholders.js";

export class StreamRestorer {
  private pending = "";
  private readonly map: PlaceholderMap;
  private readonly known: string[];
  private readonly encode: (value: string) => string;

  /**
   * @param jsonFragment set to true when the stream is a piece of JSON text
   *   (a tool call's arguments). Restored values are then escaped so that a
   *   value containing a quote or backslash cannot break the JSON.
   */
  constructor(map: PlaceholderMap, known: readonly string[], jsonFragment = false) {
    this.map = map;
    this.known = [...known];
    this.encode = jsonFragment ? (v) => JSON.stringify(v).slice(1, -1) : (v) => v;
  }

  /** Feed the next piece; get back the text that is now safe to send on. */
  push(chunk: string): string {
    const buf = this.pending + chunk;
    if (this.known.length === 0) {
      this.pending = "";
      return buf;
    }

    let out = "";
    let i = 0;
    while (i < buf.length) {
      const open = buf.indexOf("[", i);
      if (open === -1) {
        out += buf.slice(i);
        i = buf.length;
        break;
      }
      out += buf.slice(i, open);
      const rest = buf.slice(open);

      // Case 1: a complete placeholder we created starts here.
      const complete = this.known.find((p) => rest.startsWith(p));
      if (complete !== undefined) {
        out += this.encode(this.map.valueFor(complete) ?? complete);
        i = open + complete.length;
        continue;
      }

      // Case 2: the text ends part-way through what could be a placeholder. Hold it back.
      if (this.couldBecomePlaceholder(rest)) {
        this.pending = rest;
        return out;
      }

      // Case 3: just an ordinary "[".
      out += "[";
      i = open + 1;
    }

    this.pending = "";
    return out;
  }

  /** The stream has ended: release whatever was held back, unchanged. */
  flush(): string {
    const rest = this.pending;
    this.pending = "";
    return rest;
  }

  private couldBecomePlaceholder(tail: string): boolean {
    if (tail.length <= PLACEHOLDER_START.length) return PLACEHOLDER_START.startsWith(tail);
    if (!tail.startsWith(PLACEHOLDER_START)) return false;
    return this.known.some((p) => p.length > tail.length && p.startsWith(tail));
  }
}
