/**
 * Server-Sent Events (SSE): the format AI providers use for streaming.
 *
 * A stream is a series of small text blocks separated by a blank line:
 *
 *     event: content_block_delta
 *     data: {"type":"content_block_delta", ...}
 *     (blank line)
 *
 * Network pieces do not line up with these blocks; one block may arrive in
 * three pieces, or three blocks in one piece. SseParser glues the pieces back
 * into whole events.
 */
export interface SseEvent {
  event?: string;
  data: string;
}

/** The most text we will hold while waiting for an event to complete (8 MB). */
const MAX_BUFFER = 8 * 1024 * 1024;

export class SseParser {
  private buffer = "";

  push(text: string): SseEvent[] {
    this.buffer += text;
    if (this.buffer.length > MAX_BUFFER) throw new Error("SSE event too large");

    const events: SseEvent[] = [];
    for (;;) {
      const match = /\r?\n\r?\n/.exec(this.buffer);
      if (!match) break;
      const block = this.buffer.slice(0, match.index);
      this.buffer = this.buffer.slice(match.index + match[0].length);
      const ev = parseBlock(block);
      if (ev) events.push(ev);
    }
    return events;
  }

  /** Anything left when the stream ends (a final event with no blank line after it). */
  end(): SseEvent[] {
    const block = this.buffer;
    this.buffer = "";
    const ev = parseBlock(block);
    return ev ? [ev] : [];
  }
}

function parseBlock(block: string): SseEvent | null {
  let event: string | undefined;
  const data: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (line === "" || line.startsWith(":")) continue; // blank or comment
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") event = value;
    else if (field === "data") data.push(value);
  }
  if (data.length === 0 && event === undefined) return null;
  return event === undefined ? { data: data.join("\n") } : { event, data: data.join("\n") };
}

export function serializeSse(ev: SseEvent): string {
  let out = "";
  if (ev.event !== undefined) out += `event: ${ev.event.replace(/[\r\n]/g, " ")}\n`;
  for (const line of ev.data.split("\n")) out += `data: ${line}\n`;
  return `${out}\n`;
}
