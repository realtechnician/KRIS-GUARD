/**
 * The heart of KRIS Guard: what happens to one request, step by step.
 *
 *   1. Who is calling?            (the key decides; nothing else can)
 *   2. Load that client's policy.
 *   3. Hide personal data everywhere in the request.
 *   4. Apply the attachment rule.
 *   5. Write the audit entry.     (no record, no forward)
 *   6. Forward to the provider with KRIS's own key.
 *   7. Put real values back into the answer (streamed or not).
 *   8. Write the second audit entry (tokens, status).
 *
 * FAIL CLOSED: steps 1-5 run inside one try/catch. If ANYTHING unexpected
 * goes wrong there, the request is blocked and nothing reaches the provider.
 */
import { once } from "node:events";
import type { ServerResponse } from "node:http";
import { performance } from "node:perf_hooks";
import type { FastifyBaseLogger, FastifyReply, FastifyRequest } from "fastify";
import type { AuditLog } from "../audit/log.js";
import type { AuthenticatedClient, ClientService } from "../clients/service.js";
import type { Config } from "../config.js";
import { deriveKey, hmacBytes, hmacHex, randomHex } from "../crypto.js";
import { GuardError, describeErrorSafely, failClosedError } from "../errors.js";
import { screenText, summarizeFindings, type InjectionDetector, type InjectionFinding } from "../injection/detector.js";
import { RuleBasedInjectionDetector } from "../injection/rules.js";
import { BUILT_IN_DETECTORS } from "../pii/detect.js";
import { Masker } from "../pii/masker.js";
import { countPlaceholders, type PlaceholderMode } from "../pii/placeholders.js";
import type { Detector } from "../pii/types.js";
import { isObject, type WalkContext } from "../pii/walk.js";
import type { PolicyStore } from "../policy/policy.js";
import { NO_USAGE, firstHeader, type ApiAdapter, type Usage } from "./adapter.js";
import { SseParser, serializeSse } from "./sse.js";

export interface ProxyDeps {
  config: Config;
  audit: AuditLog;
  clients: ClientService;
  policies: PolicyStore;
  log: FastifyBaseLogger;
  /** Extra detectors. Used by tests (for example, one that always fails). */
  extraDetectors?: readonly Detector[];
  /** The planted-instruction detector. Replace this to plug in a better one. */
  injectionDetector?: InjectionDetector;
}

/** What the JSON body parser in server.ts hands us: the parsed data and the original text. */
export interface ParsedBody {
  raw: string;
  json: unknown;
}

declare module "fastify" {
  interface FastifyRequest {
    /** Set by the authentication step. Absent means "not authenticated". */
    krisClient?: AuthenticatedClient;
    krisRequestId?: string;
    krisStarted?: number;
  }
}

/** Largest provider answer we will hold in memory for a non-streamed request (32 MB). */
const MAX_UPSTREAM_BODY = 32 * 1024 * 1024;

/** The key may arrive the Anthropic way (x-api-key) or the OpenAI way (Authorization: Bearer). */
export function extractApiKey(headers: FastifyRequest["headers"]): string | undefined {
  const direct = firstHeader(headers["x-api-key"]);
  if (direct) return direct.trim();
  const auth = firstHeader(headers.authorization);
  if (auth && /^bearer\s+/i.test(auth)) return auth.replace(/^bearer\s+/i, "").trim();
  return undefined;
}

/**
 * The model name goes into the audit log, so it must be harmless: short,
 * made of ordinary characters, and free of personal data.
 */
function modelForAudit(model: unknown, masker: Masker): string {
  if (typeof model !== "string" || model.length === 0 || model.length > 100) return "[invalid]";
  if (!/^[A-Za-z0-9._:/@\-]+$/.test(model)) return "[invalid]";
  if (masker.find(model).length > 0) return "[invalid]";
  return model;
}

/**
 * The "user label" lets a client say which of ITS users made a request, so
 * usage can be broken down per user. It is written to the audit log, so it
 * must not be personal data. A plain id like "user-4821" is kept. Anything
 * that looks like personal data (an email, a phone number...) or contains
 * unusual characters is replaced by a scrambled code that is still the same
 * for the same user, so counting per user keeps working.
 */
function userLabelForAudit(raw: string | undefined, masker: Masker, key: Buffer): string | null {
  const value = raw?.trim();
  if (!value) return null;
  const plain = value.length <= 64 && /^[A-Za-z0-9._:\-]+$/.test(value) && masker.find(value).length === 0;
  return plain ? value : `anon_${hmacHex(key, value).slice(0, 16)}`;
}

function usageForAudit(u: Usage): Record<string, unknown> {
  return {
    input_tokens: u.inputTokens,
    output_tokens: u.outputTokens,
    cache_read_tokens: u.cacheReadTokens,
    cache_write_tokens: u.cacheWriteTokens,
  };
}

/** Write to the client, waiting if its connection is slow. Stops waiting if the client has gone. */
async function writeToClient(res: ServerResponse, chunk: string): Promise<void> {
  if (res.destroyed || res.writableEnded) return;
  if (!res.write(chunk)) {
    await Promise.race([once(res, "drain"), once(res, "close")]).catch(() => undefined);
  }
}

async function readLimited(response: Response, limit: number): Promise<string> {
  if (!response.body) return "";
  const decoder = new TextDecoder();
  let text = "";
  for await (const chunk of response.body as AsyncIterable<Uint8Array>) {
    text += decoder.decode(chunk, { stream: true });
    if (text.length > limit) throw new Error("upstream body too large");
  }
  return text + decoder.decode();
}

export function createProxyHandler(adapter: ApiAdapter, deps: ProxyDeps) {
  const { config, audit, log } = deps;
  const stableKeyRoot = deriveKey(config.serverSecret, "stable-placeholders");
  const userLabelKey = deriveKey(config.serverSecret, "user-label");
  const injectionDetector = deps.injectionDetector ?? new RuleBasedInjectionDetector();

  return async function handle(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const started = request.krisStarted ?? performance.now();
    const requestId = request.krisRequestId ?? `kgreq_${randomHex(12)}`;
    const who = request.krisClient;

    /** Facts for the audit entry. Filled in as we learn them. Never holds personal data. */
    const record: Record<string, unknown> = { request_id: requestId, api: adapter.name };
    /** Has the "request" audit entry been written yet? */
    let recorded = false;
    let streaming = false;

    const sendError = async (err: unknown): Promise<void> => {
      const guardErr = err instanceof GuardError ? err : failClosedError();
      if (!(err instanceof GuardError)) {
        log.error({ requestId, err: describeErrorSafely(err) }, "unexpected error; request blocked (fail closed)");
      }
      try {
        if (who && !recorded) {
          await audit.append("request", { ...record, decision: "blocked", reason: guardErr.code });
        } else if (who && recorded) {
          await audit.append("response", {
            request_id: requestId,
            client_id: who.clientId,
            status: "error",
            reason: guardErr.code,
            ...usageForAudit(NO_USAGE),
            cost_usd: null,
            duration_ms: Math.round(performance.now() - started),
          });
        }
      } catch (auditErr) {
        log.error({ requestId, err: describeErrorSafely(auditErr) }, "could not write audit entry for a blocked request");
      }

      if (streaming) {
        // Headers are already sent; the only way to report an error is an event in the stream.
        const res = reply.raw;
        await writeToClient(res, serializeSse(adapter.streamErrorEvent(guardErr, requestId)));
        if (!res.writableEnded) res.end();
        return;
      }
      await reply
        .code(guardErr.status)
        .header("content-type", "application/json; charset=utf-8")
        .send(JSON.stringify(adapter.errorBody(guardErr, requestId)));
    };

    try {
      // ── 1. Who is calling? ────────────────────────────────────────────────
      if (!who) throw new GuardError("unauthorized", "KRIS Guard: missing or invalid API key.");
      record.client_id = who.clientId;
      record.key_id = who.keyId;

      const parsed = request.body as ParsedBody | undefined;
      if (!parsed || !isObject(parsed.json)) {
        throw new GuardError("invalid_request", "KRIS Guard: the request body must be a JSON object.");
      }
      const body = parsed.json;
      record.stream = body.stream === true;

      // ── 2. The client's policy ────────────────────────────────────────────
      const { policy, nameDetector } = await deps.policies.load(who.clientId);

      // ── 3. Hide personal data ─────────────────────────────────────────────
      const detectors = [...BUILT_IN_DETECTORS, nameDetector, ...(deps.extraDetectors ?? [])];
      const mode: PlaceholderMode =
        policy.personal_data.placeholders === "stable"
          ? { kind: "stable", key: hmacBytes(stableKeyRoot, who.clientId) }
          : { kind: "random" };
      const masker = new Masker(detectors, mode, parsed.raw);
      const ctx: WalkContext = { masker, attachments: [] };

      record.model = modelForAudit(body.model, masker);
      record.user_label = userLabelForAudit(
        firstHeader(request.headers["x-kris-user"]) ?? adapter.userLabelFromBody(body),
        masker,
        userLabelKey,
      );

      if (typeof body.model !== "string" || body.model.length === 0) {
        throw new GuardError("invalid_request", "KRIS Guard: `model` is required.");
      }

      // Planted-instruction screening runs on untrusted text, before masking.
      const injectionAction = policy.injection_screening.action;
      const injectionFindings: InjectionFinding[] = [];
      if (injectionAction !== "off") {
        ctx.screenUserMessages = policy.injection_screening.scan_user_messages;
        ctx.screen = (text) => {
          const result = screenText(injectionDetector, injectionAction, text);
          for (const f of result.findings) injectionFindings.push(f);
          return result.text;
        };
      }

      const safeBody = adapter.prepare(adapter.sanitize(body, ctx));
      record.pii_hidden = { ...masker.hidden };
      record.attachments = ctx.attachments.length;

      // ── 4. Attachments ────────────────────────────────────────────────────
      const decisions: string[] = [];
      if (ctx.attachments.length > 0) {
        if (!policy.attachments.allowed) {
          const first = ctx.attachments[0]!;
          throw new GuardError(
            "attachment_blocked",
            `KRIS Guard blocked this request because it contains ${ctx.attachments.length} attachment(s) ` +
              `(first: ${first.kind} at ${first.path}). Images, files and PDFs cannot be checked for personal data, ` +
              "so they are only accepted if the client's policy allows attachments.",
          );
        }
        decisions.push("attachments_allowed_unchecked");
      }
      if (Object.keys(masker.hidden).length > 0) decisions.push("personal_data_hidden");

      // ── 4b. Planted instructions ─────────────────────────────────────────
      const warnings: string[] = [];
      if (injectionFindings.length > 0) {
        // Rule names and counts only. The matched text is never recorded.
        record.injection = { action: injectionAction, detector: injectionDetector.name, rules: summarizeFindings(injectionFindings) };
        if (injectionAction === "block") {
          throw new GuardError(
            "injection_blocked",
            "KRIS Guard blocked this request: text from a document, web page or tool result looks like an instruction " +
              "planted for the AI. If this is a mistake, ask the KRIS administrator to review the client's screening setting.",
          );
        }
        decisions.push(injectionAction === "strip" ? "planted_instruction_stripped" : "planted_instruction_warning");
        warnings.push(injectionAction === "strip" ? "planted-instruction-stripped" : "possible-planted-instruction");
      }
      record.policy_decisions = decisions;

      const providerKey = adapter.providerKey(config);
      if (!providerKey) {
        throw new GuardError("provider_not_configured", "KRIS Guard: this AI provider is not configured on the server.");
      }

      // ── 5. Record first: no record, no forward ────────────────────────────
      try {
        await audit.append("request", { ...record, decision: "forwarded" });
        recorded = true;
      } catch (err) {
        log.error({ requestId, err: describeErrorSafely(err) }, "audit log unavailable; request blocked");
        throw new GuardError(
          "audit_unavailable",
          "KRIS Guard could not record this request in its audit log, so the request was blocked. Nothing was sent to the AI provider.",
        );
      }

      // ── 6. Forward ────────────────────────────────────────────────────────
      const controller = new AbortController();
      let timedOut = false;
      let timer: NodeJS.Timeout | undefined;
      /** (Re)start the countdown. Used for "no answer yet" and for "stream went quiet". */
      const armTimer = () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
          timedOut = true;
          controller.abort();
        }, config.upstreamTimeoutMs);
      };
      // If the client hangs up, stop the provider call too.
      reply.raw.on("close", () => {
        if (!reply.raw.writableFinished) controller.abort();
      });

      const beforeForward = performance.now();
      let upstream: Response;
      try {
        armTimer();
        upstream = await fetch(adapter.upstreamUrl(config), {
          method: "POST",
          headers: adapter.upstreamHeaders(providerKey, request.headers),
          body: JSON.stringify(safeBody),
          signal: controller.signal,
        });
      } catch {
        clearTimeout(timer);
        throw timedOut
          ? new GuardError("provider_timeout", "KRIS Guard: the AI provider did not answer in time.")
          : new GuardError("provider_unreachable", "KRIS Guard: could not reach the AI provider.");
      }
      let overheadMs = beforeForward - started;

      /**
       * Optional: which kinds of personal data appear in the answer that were
       * NOT in the request. The answer is scanned BEFORE restoring: at that
       * point everything from the request is still a placeholder, so anything
       * a detector finds is new by construction. Only the KINDS are returned.
       */
      const scanAnswers = policy.personal_data.scan_answers;
      const newPiiIn = (texts: readonly string[]): string[] => {
        const kinds = new Set<string>();
        for (const t of texts) for (const k of masker.find(t)) kinds.add(k);
        return [...kinds].sort();
      };

      const finish = async (status: number | string, usage: Usage, extra: Record<string, unknown> = {}) => {
        clearTimeout(timer);
        try {
          await audit.append("response", {
            request_id: requestId,
            client_id: who.clientId,
            status,
            ...usageForAudit(usage),
            cost_usd: null, // Phase 2 fills this in from the price table
            duration_ms: Math.round(performance.now() - started),
            overhead_ms: Math.round(overheadMs * 10) / 10,
            ...extra,
          });
        } catch (err) {
          log.error({ requestId, err: describeErrorSafely(err) }, "could not write response audit entry");
        }
        log.info({ requestId, client: who.clientId, api: adapter.name, status, overheadMs: Math.round(overheadMs) }, "request done");
      };

      const contentType = upstream.headers.get("content-type") ?? "";
      const upstreamRequestId = upstream.headers.get("request-id") ?? upstream.headers.get("x-request-id");
      if (upstreamRequestId) reply.header("x-upstream-request-id", upstreamRequestId.slice(0, 200));
      reply.header("x-kris-request-id", requestId);
      // Lets the client app know something was flagged, so it can warn its user.
      if (warnings.length > 0) reply.header("x-kris-guard-warnings", warnings.join(","));

      // ── 7a. The provider refused or failed ────────────────────────────────
      if (!upstream.ok) {
        // Passed on as-is. It can only contain placeholders, never real values,
        // and we do NOT restore inside error messages (they tend to end up in logs).
        let text: string;
        try {
          text = await readLimited(upstream, 1024 * 1024);
        } catch {
          throw new GuardError("provider_unreachable", "KRIS Guard: the AI provider returned an unreadable error.");
        }
        const retryAfter = upstream.headers.get("retry-after");
        if (retryAfter) reply.header("retry-after", retryAfter.slice(0, 50));
        await finish(upstream.status, NO_USAGE);
        await reply
          .code(upstream.status)
          .header("content-type", contentType.includes("json") ? "application/json; charset=utf-8" : "text/plain; charset=utf-8")
          .send(text);
        return;
      }

      // ── 7b. A streamed answer ─────────────────────────────────────────────
      if (contentType.includes("text/event-stream") && upstream.body) {
        streaming = true;
        reply.hijack();
        const res = reply.raw;
        res.writeHead(200, {
          "content-type": "text/event-stream; charset=utf-8",
          "cache-control": "no-cache, no-transform",
          connection: "keep-alive",
          "x-accel-buffering": "no",
          "x-kris-request-id": requestId,
          "x-kris-guard-overhead-ms": overheadMs.toFixed(1),
          ...(warnings.length > 0 ? { "x-kris-guard-warnings": warnings.join(",") } : {}),
        });

        const parser = new SseParser();
        const transformer = adapter.createStreamTransformer(masker, body, scanAnswers);
        const decoder = new TextDecoder();
        let unrestored = 0;
        const emit = async (events: ReturnType<SseParser["push"]>) => {
          for (const ev of events) {
            for (const out of transformer.transform(ev)) {
              unrestored += countPlaceholders(out.data);
              await writeToClient(res, serializeSse(out));
            }
          }
        };

        try {
          for await (const chunk of upstream.body as AsyncIterable<Uint8Array>) {
            armTimer(); // the stream is alive; restart the "gone quiet" countdown
            await emit(parser.push(decoder.decode(chunk, { stream: true })));
          }
          await emit(parser.push(decoder.decode()));
          await emit(parser.end());
          for (const out of transformer.finish()) await writeToClient(res, serializeSse(out));
        } catch (err) {
          clearTimeout(timer);
          if (!(err instanceof GuardError) && !controller.signal.aborted) {
            log.error({ requestId, err: describeErrorSafely(err) }, "stream failed");
          }
          throw timedOut
            ? new GuardError("provider_timeout", "KRIS Guard: the AI provider stopped answering.")
            : new GuardError("provider_unreachable", "KRIS Guard: the connection to the AI provider was interrupted.");
        }
        if (!res.writableEnded) res.end();
        // A streamed answer has already been sent, so new personal data can only be recorded, not announced.
        const streamedNew = scanAnswers ? newPiiIn([transformer.collectedText()]) : [];
        await finish(200, transformer.usage(), {
          ...(unrestored > 0 ? { unrestored_placeholders: unrestored } : {}),
          ...(streamedNew.length > 0 ? { answer_new_pii: streamedNew } : {}),
        });
        return;
      }

      // ── 7c. A complete (non-streamed) answer ──────────────────────────────
      let text: string;
      try {
        text = await readLimited(upstream, MAX_UPSTREAM_BODY);
      } catch {
        throw timedOut
          ? new GuardError("provider_timeout", "KRIS Guard: the AI provider did not answer in time.")
          : new GuardError("provider_unreachable", "KRIS Guard: the AI provider's answer could not be read.");
      }
      const afterBody = performance.now();
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        throw new GuardError("provider_unreachable", "KRIS Guard: the AI provider's answer was not valid JSON.");
      }
      const answerNew = scanAnswers ? newPiiIn(adapter.answerTexts(json)) : [];
      if (answerNew.length > 0) {
        warnings.push("new-personal-data-in-answer");
        reply.header("x-kris-guard-warnings", warnings.join(","));
      }
      const restored = JSON.stringify(adapter.restoreResponse(json, masker));
      const unrestored = countPlaceholders(restored);
      overheadMs += performance.now() - afterBody;

      reply.header("x-kris-guard-overhead-ms", overheadMs.toFixed(1));
      await reply.code(200).header("content-type", "application/json; charset=utf-8").send(restored);
      await finish(200, adapter.usageFromResponse(json), {
        ...(unrestored > 0 ? { unrestored_placeholders: unrestored } : {}),
        ...(answerNew.length > 0 ? { answer_new_pii: answerNew } : {}),
      });
    } catch (err) {
      await sendError(err);
    }
  };
}
