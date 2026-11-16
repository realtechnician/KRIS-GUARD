/**
 * Adapter for the Anthropic Messages API (POST /v1/messages).
 *
 * The request is made of "content blocks": text, images, documents, tool
 * calls, tool results, and so on. `sanitizeBlock` below decides, block type
 * by block type, which parts are free text (masked), which are fixed names
 * (checked), and which are attachments.
 */
import type { Config } from "../config.js";
import { GuardError } from "../errors.js";
import type { Masker } from "../pii/masker.js";
import { StreamRestorer } from "../pii/stream-restorer.js";
import {
  check,
  freeform,
  isObject,
  keep,
  mask,
  maskFreeform,
  maskText,
  restoreDeep,
  walkFields,
  type WalkContext,
} from "../pii/walk.js";
import { NO_USAGE, firstHeader, num, type ApiAdapter, type StreamTransformer, type Usage } from "./adapter.js";
import type { SseEvent } from "./sse.js";

const DEFAULT_API_VERSION = "2023-06-01";

/** Block types that carry a tool call's input (arbitrary data). */
const TOOL_CALL_TYPES = new Set(["tool_use", "server_tool_use", "mcp_tool_use"]);

function sanitizeContent(ctx: WalkContext, value: unknown, path: string): unknown {
  if (typeof value === "string") return maskText(ctx, value, path);
  if (Array.isArray(value)) return value.map((b, i) => sanitizeBlock(ctx, b, `${path}[${i}]`));
  return maskFreeform(ctx, value, path);
}

/** Does this "source" point at file contents we cannot read (base64 data, a URL, an uploaded file)? */
function isUnreadableSource(source: unknown): boolean {
  if (!isObject(source)) return true;
  return source.type !== "text" && source.type !== "content";
}

function sanitizeBlock(ctx: WalkContext, block: unknown, path: string): unknown {
  if (!isObject(block)) return maskFreeform(ctx, block, path);
  const type = typeof block.type === "string" ? block.type : "";
  const content = (v: unknown, p: string) => sanitizeContent(ctx, v, p);

  if (type === "text") {
    return walkFields(ctx, block, path, { text: mask(ctx), citations: freeform(ctx), cache_control: keep });
  }

  if (type === "thinking") {
    // The AI's own earlier reasoning, sent back by the client. Normally it
    // contains only placeholders (we never restore inside thinking), so
    // masking changes nothing and the provider's signature stays valid.
    return walkFields(ctx, block, path, { thinking: mask(ctx) });
  }

  if (type === "redacted_thinking") {
    return walkFields(ctx, block, path, { data: keep }); // sealed by the provider; unreadable
  }

  if (TOOL_CALL_TYPES.has(type)) {
    return walkFields(ctx, block, path, { input: freeform(ctx), cache_control: keep });
  }

  if (type === "tool_result" || type === "mcp_tool_result") {
    return walkFields(ctx, block, path, { content, cache_control: keep });
  }

  if (type === "image" || type === "container_upload" || type === "file") {
    ctx.attachments.push({ path, kind: type === "image" ? "image" : "file" });
    return walkFields(ctx, block, path, { source: keep, cache_control: keep });
  }

  if (type === "document") {
    const source = block.source;
    let sourceHandler: (v: unknown, p: string) => unknown;
    if (isUnreadableSource(source)) {
      // A PDF, a URL or an uploaded file: we cannot look inside.
      ctx.attachments.push({ path, kind: "document" });
      sourceHandler = keep;
    } else {
      // A plain-text document, or one made of content blocks: readable, so it is masked like any text.
      sourceHandler = (v, p) =>
        isObject(v) ? walkFields(ctx, v, p, { data: mask(ctx), content }) : maskFreeform(ctx, v, p);
    }
    return walkFields(ctx, block, path, {
      source: sourceHandler,
      title: mask(ctx),
      context: mask(ctx),
      cache_control: keep,
    });
  }

  if (type === "search_result") {
    return walkFields(ctx, block, path, { source: mask(ctx), title: mask(ctx), content, cache_control: keep });
  }

  if (type === "compaction") {
    return walkFields(ctx, block, path, { content: mask(ctx), cache_control: keep });
  }

  // Anything else (web search results, code execution results, and block
  // types that did not exist when this was written): mask every string we
  // find, check the identifying fields, and look for nested blocks.
  return walkFields(
    ctx,
    block,
    path,
    {
      type: check(ctx),
      id: check(ctx),
      tool_use_id: check(ctx),
      name: check(ctx),
      cache_control: keep,
      content: (v, p) => sanitizeUnknown(ctx, v, p),
    },
    "freeform",
  );
}

/** Data of unknown shape that may contain further blocks. */
function sanitizeUnknown(ctx: WalkContext, value: unknown, path: string): unknown {
  if (Array.isArray(value)) return value.map((v, i) => sanitizeUnknown(ctx, v, `${path}[${i}]`));
  if (isObject(value) && typeof value.type === "string") return sanitizeBlock(ctx, value, path);
  return maskFreeform(ctx, value, path);
}

function sanitizeMessages(ctx: WalkContext, value: unknown, path: string): unknown {
  if (!Array.isArray(value)) {
    throw new GuardError("invalid_request", "KRIS Guard: `messages` must be a list.");
  }
  return value.map((m, i) => {
    const p = `${path}[${i}]`;
    if (!isObject(m)) throw new GuardError("invalid_request", `KRIS Guard: ${p} must be an object.`);
    return walkFields(ctx, m, p, { content: (v, cp) => sanitizeContent(ctx, v, cp) });
  });
}

function sanitizeTools(ctx: WalkContext, value: unknown, path: string): unknown {
  if (!Array.isArray(value)) return maskFreeform(ctx, value, path);
  return value.map((t, i) => {
    const p = `${path}[${i}]`;
    if (!isObject(t)) return maskFreeform(ctx, t, p);
    return walkFields(ctx, t, p, {
      description: mask(ctx),
      input_schema: freeform(ctx),
      input_examples: freeform(ctx),
      cache_control: keep,
    });
  });
}

function sanitizeRequest(body: Record<string, unknown>, ctx: WalkContext): Record<string, unknown> {
  return walkFields(ctx, body, "", {
    system: (v, p) => sanitizeContent(ctx, v, p),
    messages: (v, p) => sanitizeMessages(ctx, v, p),
    tools: (v, p) => sanitizeTools(ctx, v, p),
    metadata: freeform(ctx),
    stop_sequences: freeform(ctx),
    output_config: (v, p) =>
      isObject(v)
        ? walkFields(ctx, v, p, {
            format: (f, fp) => (isObject(f) ? walkFields(ctx, f, fp, { schema: freeform(ctx) }) : check(ctx)(f, fp)),
          })
        : check(ctx)(v, p),
  });
}

/** Thinking blocks are left exactly as the provider sent them (see README, "Honest limits"). */
const isThinking = (obj: Record<string, unknown>) => obj.type === "thinking" || obj.type === "redacted_thinking";

function readUsage(u: unknown, into: Usage): Usage {
  if (!isObject(u)) return into;
  return {
    inputTokens: num(u.input_tokens) ?? into.inputTokens,
    outputTokens: num(u.output_tokens) ?? into.outputTokens,
    cacheReadTokens: num(u.cache_read_input_tokens) ?? into.cacheReadTokens,
    cacheWriteTokens: num(u.cache_creation_input_tokens) ?? into.cacheWriteTokens,
  };
}

class AnthropicStream implements StreamTransformer {
  /** One restorer per content block that is currently being streamed. */
  private readonly restorers = new Map<number, { restorer: StreamRestorer; field: "text" | "partial_json" }>();
  private readonly placeholders: string[];
  private current: Usage = NO_USAGE;

  constructor(private readonly masker: Masker) {
    this.placeholders = masker.map.placeholders();
  }

  usage(): Usage {
    return this.current;
  }

  transform(ev: SseEvent): SseEvent[] {
    let data: unknown;
    try {
      data = JSON.parse(ev.data);
    } catch {
      return [ev]; // not JSON: nothing of ours can be inside
    }
    if (!isObject(data)) return [ev];

    switch (data.type) {
      case "message_start": {
        if (isObject(data.message)) this.current = readUsage(data.message.usage, this.current);
        return [ev];
      }

      case "content_block_start": {
        const index = num(data.index) ?? -1;
        const block = data.content_block;
        if (isObject(block) && !isThinking(block)) {
          const blockType = typeof block.type === "string" ? block.type : "";
          if (blockType === "text") {
            this.restorers.set(index, {
              restorer: new StreamRestorer(this.masker.map, this.placeholders, false),
              field: "text",
            });
          } else if (TOOL_CALL_TYPES.has(blockType)) {
            this.restorers.set(index, {
              restorer: new StreamRestorer(this.masker.map, this.placeholders, true),
              field: "partial_json",
            });
          }
          data.content_block = restoreDeep(this.masker, block);
        }
        return [{ ...ev, data: JSON.stringify(data) }];
      }

      case "content_block_delta": {
        const index = num(data.index) ?? -1;
        const delta = data.delta;
        if (!isObject(delta)) return [ev];

        if (delta.type === "text_delta" || delta.type === "input_json_delta") {
          const field = delta.type === "text_delta" ? "text" : "partial_json";
          let entry = this.restorers.get(index);
          if (!entry) {
            // A delta for a block we never saw start. Handle it anyway.
            entry = {
              restorer: new StreamRestorer(this.masker.map, this.placeholders, field === "partial_json"),
              field,
            };
            this.restorers.set(index, entry);
          }
          const piece = delta[field];
          if (typeof piece !== "string") return [ev];
          const restored = entry.restorer.push(piece);
          // Everything was held back (it might be half a placeholder): send nothing yet.
          if (restored === "" && piece !== "") return [];
          delta[field] = restored;
          return [{ ...ev, data: JSON.stringify(data) }];
        }

        if (delta.type === "thinking_delta" || delta.type === "signature_delta") return [ev];

        // Other delta kinds (e.g. citations): restore any placeholders inside.
        data.delta = restoreDeep(this.masker, delta);
        return [{ ...ev, data: JSON.stringify(data) }];
      }

      case "content_block_stop": {
        const index = num(data.index) ?? -1;
        const entry = this.restorers.get(index);
        this.restorers.delete(index);
        const out: SseEvent[] = [];
        const rest = entry?.restorer.flush() ?? "";
        if (rest !== "") out.push(this.deltaEvent(index, entry!.field, rest));
        out.push(ev);
        return out;
      }

      case "message_delta": {
        this.current = readUsage(data.usage, this.current);
        return [ev];
      }

      default:
        return [ev];
    }
  }

  finish(): SseEvent[] {
    const out: SseEvent[] = [];
    for (const [index, entry] of this.restorers) {
      const rest = entry.restorer.flush();
      if (rest !== "") out.push(this.deltaEvent(index, entry.field, rest));
    }
    this.restorers.clear();
    return out;
  }

  private deltaEvent(index: number, field: "text" | "partial_json", value: string): SseEvent {
    const delta = field === "text" ? { type: "text_delta", text: value } : { type: "input_json_delta", partial_json: value };
    return { event: "content_block_delta", data: JSON.stringify({ type: "content_block_delta", index, delta }) };
  }
}

/** Maps our error codes onto the error types Anthropic's client libraries know. */
function errorType(err: GuardError): string {
  if (err.status === 401) return "authentication_error";
  if (err.status === 403) return "permission_error";
  if (err.status === 413) return "request_too_large";
  if (err.status === 400) return "invalid_request_error";
  if (err.status === 504) return "timeout_error";
  return "api_error";
}

export const anthropicAdapter: ApiAdapter = {
  name: "anthropic",
  path: "/v1/messages",

  providerKey: (config: Config) => config.anthropicApiKey,
  upstreamUrl: (config: Config) => `${config.anthropicBaseUrl}/v1/messages`,

  upstreamHeaders(providerKey, clientHeaders) {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-api-key": providerKey,
      "anthropic-version": firstHeader(clientHeaders["anthropic-version"]) ?? DEFAULT_API_VERSION,
    };
    const beta = clientHeaders["anthropic-beta"];
    if (beta !== undefined) headers["anthropic-beta"] = Array.isArray(beta) ? beta.join(",") : beta;
    return headers;
  },

  sanitize: sanitizeRequest,
  prepare: (body) => body,

  userLabelFromBody(body) {
    const meta = body.metadata;
    return isObject(meta) && typeof meta.user_id === "string" ? meta.user_id : undefined;
  },

  restoreResponse: (json, masker) => restoreDeep(masker, json, isThinking),

  usageFromResponse: (json) => (isObject(json) ? readUsage(json.usage, NO_USAGE) : NO_USAGE),

  createStreamTransformer: (masker) => new AnthropicStream(masker),

  errorBody: (err, requestId) => ({
    type: "error",
    error: { type: errorType(err), message: err.message, code: `kris_guard_${err.code}` },
    request_id: requestId,
  }),

  streamErrorEvent: (err, requestId) => ({
    event: "error",
    data: JSON.stringify({
      type: "error",
      error: { type: errorType(err), message: err.message, code: `kris_guard_${err.code}` },
      request_id: requestId,
    }),
  }),
};
