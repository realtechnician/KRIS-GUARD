/**
 * Adapter for the OpenAI Chat Completions API (POST /v1/chat/completions).
 *
 * One quirk to know about: OpenAI sends a tool call's arguments as a piece of
 * JSON *written inside a string*:
 *
 *     "arguments": "{\"phone\": \"0788123456\"}"
 *
 * So we open that string up, mask what is inside, and close it again. On the
 * way back, restored values are written with proper JSON escaping so a value
 * containing a quote cannot break the JSON.
 */
import type { Config } from "../config.js";
import { GuardError } from "../errors.js";
import type { Masker } from "../pii/masker.js";
import { PLACEHOLDER_RE } from "../pii/placeholders.js";
import { StreamRestorer } from "../pii/stream-restorer.js";
import {
  check,
  freeform,
  isObject,
  keep,
  mask,
  maskFreeform,
  maskText,
  setOwn,
  walkFields,
  type WalkContext,
} from "../pii/walk.js";
import { NO_USAGE, num, type ApiAdapter, type StreamTransformer, type Usage } from "./adapter.js";
import type { SseEvent } from "./sse.js";

const ATTACHMENT_PARTS = new Set(["image_url", "input_audio", "file"]);

/** Mask a string that is supposed to contain JSON (a tool call's arguments). */
function maskJsonText(ctx: WalkContext, value: unknown, path: string): unknown {
  if (typeof value !== "string") return maskFreeform(ctx, value, path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return maskText(ctx, value, path); // not valid JSON: treat as plain text
  }
  if (parsed === null || typeof parsed !== "object") return maskText(ctx, value, path);
  return JSON.stringify(maskFreeform(ctx, parsed, path));
}

function sanitizePart(ctx: WalkContext, part: unknown, path: string): unknown {
  if (!isObject(part)) return maskFreeform(ctx, part, path);
  const type = typeof part.type === "string" ? part.type : "";
  if (type === "text") return walkFields(ctx, part, path, { text: mask(ctx) });
  if (type === "refusal") return walkFields(ctx, part, path, { refusal: mask(ctx) });
  if (ATTACHMENT_PARTS.has(type)) {
    ctx.attachments.push({ path, kind: type === "image_url" ? "image" : type === "input_audio" ? "audio" : "file" });
    return walkFields(ctx, part, path, { image_url: keep, input_audio: keep, file: keep });
  }
  return walkFields(ctx, part, path, { type: check(ctx) }, "freeform");
}

function sanitizeContent(ctx: WalkContext, value: unknown, path: string): unknown {
  if (typeof value === "string") return maskText(ctx, value, path);
  if (Array.isArray(value)) return value.map((p, i) => sanitizePart(ctx, p, `${path}[${i}]`));
  return maskFreeform(ctx, value, path);
}

function sanitizeFunctionCall(ctx: WalkContext, value: unknown, path: string): unknown {
  if (!isObject(value)) return maskFreeform(ctx, value, path);
  return walkFields(ctx, value, path, { arguments: (v, p) => maskJsonText(ctx, v, p) });
}

function sanitizeToolCalls(ctx: WalkContext, value: unknown, path: string): unknown {
  if (!Array.isArray(value)) return maskFreeform(ctx, value, path);
  return value.map((tc, i) => {
    const p = `${path}[${i}]`;
    if (!isObject(tc)) return maskFreeform(ctx, tc, p);
    return walkFields(ctx, tc, p, {
      function: (v, fp) => sanitizeFunctionCall(ctx, v, fp),
      custom: (v, cp) => (isObject(v) ? walkFields(ctx, v, cp, { input: mask(ctx) }) : maskFreeform(ctx, v, cp)),
    });
  });
}

function sanitizeMessages(ctx: WalkContext, value: unknown, path: string): unknown {
  if (!Array.isArray(value)) {
    throw new GuardError("invalid_request", "KRIS Guard: `messages` must be a list.");
  }
  return value.map((m, i) => {
    const p = `${path}[${i}]`;
    if (!isObject(m)) throw new GuardError("invalid_request", `KRIS Guard: ${p} must be an object.`);
    return walkFields(ctx, m, p, {
      content: (v, cp) => sanitizeContent(ctx, v, cp),
      refusal: mask(ctx),
      tool_calls: (v, tp) => sanitizeToolCalls(ctx, v, tp),
      function_call: (v, fp) => sanitizeFunctionCall(ctx, v, fp),
    });
  });
}

/** A function definition: its description is text, its parameters are a JSON schema. */
function sanitizeFunctionDef(ctx: WalkContext, value: unknown, path: string): unknown {
  if (!isObject(value)) return maskFreeform(ctx, value, path);
  return walkFields(ctx, value, path, { description: mask(ctx), parameters: freeform(ctx) });
}

function sanitizeRequest(body: Record<string, unknown>, ctx: WalkContext): Record<string, unknown> {
  return walkFields(ctx, body, "", {
    messages: (v, p) => sanitizeMessages(ctx, v, p),
    tools: (v, p) =>
      Array.isArray(v)
        ? v.map((t, i) =>
            isObject(t)
              ? walkFields(ctx, t, `${p}[${i}]`, { function: (f, fp) => sanitizeFunctionDef(ctx, f, fp) })
              : maskFreeform(ctx, t, `${p}[${i}]`),
          )
        : maskFreeform(ctx, v, p),
    functions: (v, p) =>
      Array.isArray(v) ? v.map((f, i) => sanitizeFunctionDef(ctx, f, `${p}[${i}]`)) : maskFreeform(ctx, v, p),
    response_format: (v, p) =>
      isObject(v)
        ? walkFields(ctx, v, p, {
            json_schema: (js, jp) =>
              isObject(js)
                ? walkFields(ctx, js, jp, { description: mask(ctx), schema: freeform(ctx) })
                : maskFreeform(ctx, js, jp),
          })
        : maskFreeform(ctx, v, p),
    prediction: (v, p) =>
      isObject(v) ? walkFields(ctx, v, p, { content: (c, cp) => sanitizeContent(ctx, c, cp) }) : maskFreeform(ctx, v, p),
    stop: freeform(ctx),
    user: mask(ctx),
    metadata: freeform(ctx),
  });
}

/** Restore placeholders inside a string that holds JSON, keeping the JSON valid. */
function restoreJsonText(masker: Masker, text: string): string {
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed !== null && typeof parsed === "object") return JSON.stringify(restoreResponseValue(masker, parsed));
  } catch {
    // fall through: restore in place, escaping each value for JSON
  }
  return text.replace(PLACEHOLDER_RE, (ph) => {
    const value = masker.map.valueFor(ph);
    return value === undefined ? ph : JSON.stringify(value).slice(1, -1);
  });
}

function restoreResponseValue(masker: Masker, value: unknown, key?: string, depth = 0): unknown {
  if (depth > 100) return value;
  if (typeof value === "string") {
    return key === "arguments" ? restoreJsonText(masker, value) : masker.restore(value);
  }
  if (Array.isArray(value)) return value.map((v) => restoreResponseValue(masker, v, undefined, depth + 1));
  if (isObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      setOwn(out, masker.restore(k), restoreResponseValue(masker, v, k, depth + 1));
    }
    return out;
  }
  return value;
}

function readUsage(u: unknown, into: Usage): Usage {
  if (!isObject(u)) return into;
  const details = isObject(u.prompt_tokens_details) ? u.prompt_tokens_details : {};
  return {
    inputTokens: num(u.prompt_tokens) ?? into.inputTokens,
    outputTokens: num(u.completion_tokens) ?? into.outputTokens,
    cacheReadTokens: num(details.cached_tokens) ?? into.cacheReadTokens,
    cacheWriteTokens: into.cacheWriteTokens,
  };
}

class OpenAIStream implements StreamTransformer {
  /** One restorer per stream of text: keyed by choice and field, e.g. "0:content", "0:tool:1". */
  private readonly restorers = new Map<string, StreamRestorer>();
  private readonly placeholders: string[];
  private current: Usage = NO_USAGE;
  private envelope: Record<string, unknown> | null = null;

  /**
   * @param clientWantsUsage whether the CLIENT asked for the token-count
   *   event. We always ask the provider for it (the audit log needs it); if
   *   the client did not ask, we remove that extra event before passing the
   *   stream on, so the client sees exactly what it expects.
   */
  constructor(
    private readonly masker: Masker,
    private readonly clientWantsUsage: boolean,
  ) {
    this.placeholders = masker.map.placeholders();
  }

  usage(): Usage {
    return this.current;
  }

  private restorer(key: string, json: boolean): StreamRestorer {
    let r = this.restorers.get(key);
    if (!r) {
      r = new StreamRestorer(this.masker.map, this.placeholders, json);
      this.restorers.set(key, r);
    }
    return r;
  }

  transform(ev: SseEvent): SseEvent[] {
    if (ev.data.trim() === "[DONE]") return [...this.finish(), ev];

    let data: unknown;
    try {
      data = JSON.parse(ev.data);
    } catch {
      return [ev];
    }
    if (!isObject(data)) return [ev];

    if (isObject(data.usage)) this.current = readUsage(data.usage, this.current);

    const choices = Array.isArray(data.choices) ? data.choices : [];
    if (choices.length === 0) {
      if (isObject(data.usage) && !this.clientWantsUsage) return []; // the extra event we asked for
      return [ev];
    }
    if (!this.clientWantsUsage && "usage" in data) delete data.usage;

    this.envelope = { id: data.id, object: data.object, created: data.created, model: data.model };

    for (const choice of choices) {
      if (!isObject(choice)) continue;
      const ci = num(choice.index) ?? 0;
      const delta = isObject(choice.delta) ? choice.delta : null;
      const finished = choice.finish_reason !== null && choice.finish_reason !== undefined;

      if (delta) {
        for (const field of ["content", "refusal"] as const) {
          if (typeof delta[field] === "string") {
            delta[field] = this.restorer(`${ci}:${field}`, false).push(delta[field]);
          }
        }
        if (Array.isArray(delta.tool_calls)) {
          for (const tc of delta.tool_calls) {
            if (!isObject(tc) || !isObject(tc.function)) continue;
            if (typeof tc.function.arguments === "string") {
              const ti = num(tc.index) ?? 0;
              tc.function.arguments = this.restorer(`${ci}:tool:${ti}`, true).push(tc.function.arguments);
            }
          }
        }
        if (isObject(delta.function_call) && typeof delta.function_call.arguments === "string") {
          delta.function_call.arguments = this.restorer(`${ci}:fn`, true).push(delta.function_call.arguments);
        }
      }

      if (finished) {
        // This choice is done: release anything still held back, in this same event.
        const target = delta ?? {};
        if (!delta) choice.delta = target;
        this.flushChoice(ci, target);
      }
    }

    return [{ ...ev, data: JSON.stringify(data) }];
  }

  /** Move held-back text for one choice into `delta`. */
  private flushChoice(ci: number, delta: Record<string, unknown>): void {
    for (const [key, r] of this.restorers) {
      if (!key.startsWith(`${ci}:`)) continue;
      const rest = r.flush();
      this.restorers.delete(key);
      if (rest === "") continue;
      const [, field, toolIndex] = key.split(":");
      if (field === "content" || field === "refusal") {
        delta[field] = (typeof delta[field] === "string" ? delta[field] : "") + rest;
      } else if (field === "tool") {
        const list = Array.isArray(delta.tool_calls) ? delta.tool_calls : [];
        list.push({ index: Number(toolIndex), function: { arguments: rest } });
        delta.tool_calls = list;
      } else if (field === "fn") {
        delta.function_call = { arguments: rest };
      }
    }
  }

  finish(): SseEvent[] {
    // Only reached with text still held back if the provider's stream stopped without a proper ending.
    const byChoice = new Map<number, Record<string, unknown>>();
    for (const key of [...this.restorers.keys()]) {
      const ci = Number(key.split(":")[0]);
      if (!byChoice.has(ci)) byChoice.set(ci, {});
    }
    const out: SseEvent[] = [];
    for (const [ci, delta] of byChoice) {
      this.flushChoice(ci, delta);
      if (Object.keys(delta).length === 0) continue;
      out.push({
        data: JSON.stringify({
          ...(this.envelope ?? {}),
          choices: [{ index: ci, delta, finish_reason: null }],
        }),
      });
    }
    return out;
  }
}

function errorType(err: GuardError): string {
  if (err.status === 401) return "authentication_error";
  if (err.status === 403) return "permission_error";
  if (err.status === 400 || err.status === 413) return "invalid_request_error";
  return "api_error";
}

function errorBody(err: GuardError, requestId: string): unknown {
  return {
    error: {
      message: err.message,
      type: errorType(err),
      param: null,
      code: `kris_guard_${err.code}`,
      request_id: requestId,
    },
  };
}

export const openaiAdapter: ApiAdapter = {
  name: "openai",
  path: "/v1/chat/completions",

  providerKey: (config: Config) => config.openaiApiKey,
  upstreamUrl: (config: Config) => `${config.openaiBaseUrl}/v1/chat/completions`,

  upstreamHeaders: (providerKey) => ({
    "content-type": "application/json",
    authorization: `Bearer ${providerKey}`,
  }),

  sanitize: sanitizeRequest,

  prepare(body) {
    // When streaming, OpenAI only reports token counts if asked. We need them for the audit log.
    if (body.stream !== true) return body;
    const options = isObject(body.stream_options) ? body.stream_options : {};
    return { ...body, stream_options: { ...options, include_usage: true } };
  },

  userLabelFromBody: (body) => (typeof body.user === "string" ? body.user : undefined),

  restoreResponse: (json, masker) => restoreResponseValue(masker, json),

  usageFromResponse: (json) => (isObject(json) ? readUsage(json.usage, NO_USAGE) : NO_USAGE),

  createStreamTransformer(masker, originalBody) {
    const options = originalBody.stream_options;
    const wantsUsage = isObject(options) && options.include_usage === true;
    return new OpenAIStream(masker, wantsUsage);
  },

  errorBody,

  streamErrorEvent: (err, requestId) => ({ data: JSON.stringify(errorBody(err, requestId)) }),
};
