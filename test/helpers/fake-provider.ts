/**
 * A pretend AI provider for tests. It runs on this machine, speaks both the
 * Anthropic and the OpenAI formats (including streaming), and never touches
 * the internet.
 *
 * By default it ECHOES: its answer repeats the text of the last user message.
 * That is exactly what the tests need. The gateway sends it placeholders, the
 * echo sends the placeholders back, and the test checks that (a) the fake
 * provider never saw real personal data and (b) the client got it back.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export interface ReceivedRequest {
  path: string;
  headers: http.IncomingHttpHeaders;
  /** The exact text the gateway sent. Tests search this for leaked personal data. */
  raw: string;
  body: any;
}

export interface Reply {
  /** Text for the answer. */
  text?: string;
  /** Make the answer a tool call instead. */
  tool?: { name: string; input: unknown };
  /** Extra "thinking" block before the text (Anthropic only). */
  thinking?: string;
  /** Answer with an HTTP error instead. */
  status?: number;
  error?: unknown;
}

export interface FakeProvider {
  url: string;
  requests: ReceivedRequest[];
  /** Replace to control the answer. Receives the last user text and the whole body. */
  reply: (lastUserText: string, body: any) => Reply;
  /** How many characters of answer text go in each streamed event. */
  chunkSize: number;
  /** If set, the whole stream is additionally cut into network pieces of this many bytes. */
  networkPieceBytes: number;
  /** Wait this long before answering (to tell provider time from gateway time). */
  delayMs: number;
  /** Stop the stream abruptly after this many events (to test broken streams). */
  dieAfterEvents: number;
  close(): Promise<void>;
}

/** Collect all readable text from a message's content, in either API's shape. */
function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((b: any) => {
      if (typeof b === "string") return b;
      if (b?.type === "text") return b.text ?? "";
      if (b?.type === "tool_result") return textOf(b.content);
      if (b?.type === "document" && b.source?.type === "text") return b.source.data ?? "";
      return "";
    })
    .join(" ");
}

function lastUserText(body: any): string {
  const messages: any[] = Array.isArray(body?.messages) ? body.messages : [];
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i]?.role === "user" || messages[i]?.role === "tool") return textOf(messages[i].content);
  }
  return "";
}

function pieces(text: string, size: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out.length > 0 ? out : [""];
}

function sse(event: string | null, data: unknown): string {
  return `${event ? `event: ${event}\n` : ""}data: ${typeof data === "string" ? data : JSON.stringify(data)}\n\n`;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function startFakeProvider(): Promise<FakeProvider> {
  const provider: FakeProvider = {
    url: "",
    requests: [],
    reply: (text) => ({ text: `Echo: ${text}` }),
    chunkSize: 5,
    networkPieceBytes: 0,
    delayMs: 0,
    dieAfterEvents: 0,
    close: async () => undefined,
  };

  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = JSON.parse(raw || "{}");
    const path = req.url ?? "";
    provider.requests.push({ path, headers: req.headers, raw, body });
    if (provider.delayMs > 0) await sleep(provider.delayMs);

    const reply = provider.reply(lastUserText(body), body);
    const isAnthropic = path === "/v1/messages";

    if (reply.status && reply.status >= 400) {
      res.writeHead(reply.status, { "content-type": "application/json", "request-id": "req_fake_err" });
      res.end(
        JSON.stringify(
          reply.error ??
            (isAnthropic
              ? { type: "error", error: { type: "invalid_request_error", message: "fake provider error" } }
              : { error: { message: "fake provider error", type: "invalid_request_error" } }),
        ),
      );
      return;
    }

    const stream = body.stream === true;
    const model = body.model ?? "fake-model";

    // ---- Build the list of streamed events (or the single JSON answer) ----
    let events: string[] = [];
    let json: unknown;

    if (isAnthropic) {
      const content: any[] = [];
      if (reply.thinking !== undefined) content.push({ type: "thinking", thinking: reply.thinking, signature: "sig_fake" });
      if (reply.tool) content.push({ type: "tool_use", id: "toolu_fake01", name: reply.tool.name, input: reply.tool.input });
      else content.push({ type: "text", text: reply.text ?? "" });
      const usage = { input_tokens: 11, output_tokens: 7 };
      json = {
        id: "msg_fake01",
        type: "message",
        role: "assistant",
        model,
        content,
        stop_reason: reply.tool ? "tool_use" : "end_turn",
        stop_sequence: null,
        usage,
      };
      if (stream) {
        events.push(
          sse("message_start", {
            type: "message_start",
            message: { ...(json as object), content: [], stop_reason: null, usage: { input_tokens: 11, output_tokens: 0 } },
          }),
        );
        content.forEach((block, index) => {
          if (block.type === "text") {
            events.push(sse("content_block_start", { type: "content_block_start", index, content_block: { type: "text", text: "" } }));
            for (const p of pieces(block.text, provider.chunkSize)) {
              events.push(sse("content_block_delta", { type: "content_block_delta", index, delta: { type: "text_delta", text: p } }));
            }
          } else if (block.type === "tool_use") {
            events.push(
              sse("content_block_start", {
                type: "content_block_start",
                index,
                content_block: { type: "tool_use", id: block.id, name: block.name, input: {} },
              }),
            );
            for (const p of pieces(JSON.stringify(block.input), provider.chunkSize)) {
              events.push(
                sse("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: p } }),
              );
            }
          } else if (block.type === "thinking") {
            events.push(
              sse("content_block_start", { type: "content_block_start", index, content_block: { type: "thinking", thinking: "", signature: "" } }),
            );
            for (const p of pieces(block.thinking, provider.chunkSize)) {
              events.push(sse("content_block_delta", { type: "content_block_delta", index, delta: { type: "thinking_delta", thinking: p } }));
            }
            events.push(
              sse("content_block_delta", { type: "content_block_delta", index, delta: { type: "signature_delta", signature: "sig_fake" } }),
            );
          }
          events.push(sse("content_block_stop", { type: "content_block_stop", index }));
        });
        events.push(
          sse("message_delta", {
            type: "message_delta",
            delta: { stop_reason: reply.tool ? "tool_use" : "end_turn", stop_sequence: null },
            usage: { output_tokens: 7 },
          }),
        );
        events.push(sse("message_stop", { type: "message_stop" }));
      }
    } else {
      const message: any = { role: "assistant", content: reply.tool ? null : (reply.text ?? "") };
      if (reply.tool) {
        message.tool_calls = [
          { id: "call_fake01", type: "function", function: { name: reply.tool.name, arguments: JSON.stringify(reply.tool.input) } },
        ];
      }
      const usage = { prompt_tokens: 13, completion_tokens: 5, total_tokens: 18 };
      const base = { id: "chatcmpl-fake01", created: 1700000000, model };
      json = {
        ...base,
        object: "chat.completion",
        choices: [{ index: 0, message, finish_reason: reply.tool ? "tool_calls" : "stop" }],
        usage,
      };
      if (stream) {
        const chunk = (delta: unknown, finish: string | null = null) =>
          sse(null, { ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta, finish_reason: finish }] });
        events.push(chunk({ role: "assistant", content: "" }));
        if (reply.tool) {
          events.push(
            chunk({ tool_calls: [{ index: 0, id: "call_fake01", type: "function", function: { name: reply.tool.name, arguments: "" } }] }),
          );
          for (const p of pieces(JSON.stringify(reply.tool.input), provider.chunkSize)) {
            events.push(chunk({ tool_calls: [{ index: 0, function: { arguments: p } }] }));
          }
          events.push(chunk({}, "tool_calls"));
        } else {
          for (const p of pieces(reply.text ?? "", provider.chunkSize)) events.push(chunk({ content: p }));
          events.push(chunk({}, "stop"));
        }
        if (body.stream_options?.include_usage === true) {
          events.push(sse(null, { ...base, object: "chat.completion.chunk", choices: [], usage }));
        }
        events.push(sse(null, "[DONE]"));
      }
    }

    if (!stream) {
      res.writeHead(200, { "content-type": "application/json", "request-id": "req_fake01" });
      res.end(JSON.stringify(json));
      return;
    }

    res.writeHead(200, { "content-type": "text/event-stream", "request-id": "req_fake01" });
    if (provider.dieAfterEvents > 0) {
      events = events.slice(0, provider.dieAfterEvents);
      for (const e of events) res.write(e);
      await sleep(20);
      res.destroy(); // cut the connection without finishing
      return;
    }
    if (provider.networkPieceBytes > 0) {
      // Cut the stream at arbitrary byte positions, ignoring event boundaries.
      const all = Buffer.from(events.join(""), "utf8");
      for (let i = 0; i < all.length; i += provider.networkPieceBytes) {
        res.write(all.subarray(i, i + provider.networkPieceBytes));
        await sleep(0);
      }
    } else {
      for (const e of events) res.write(e);
    }
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  provider.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  provider.close = () =>
    new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });
  return provider;
}
