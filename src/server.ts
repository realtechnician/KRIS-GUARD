/**
 * Builds the web server: which addresses exist and what handles each one.
 *
 * Kept separate from index.ts so tests can build a server without starting
 * the real program.
 */
import { performance } from "node:perf_hooks";
import Fastify, { LogController, type FastifyError, type FastifyInstance } from "fastify";
import type { AuditLog } from "./audit/log.js";
import type { ClientService } from "./clients/service.js";
import type { Config } from "./config.js";
import { randomHex } from "./crypto.js";
import { GuardError, describeErrorSafely, failClosedError } from "./errors.js";
import type { Detector } from "./pii/types.js";
import type { PolicyStore } from "./policy/policy.js";
import type { ApiAdapter } from "./proxy/adapter.js";
import { anthropicAdapter } from "./proxy/anthropic.js";
import { createProxyHandler, extractApiKey, type ParsedBody } from "./proxy/handler.js";
import { openaiAdapter } from "./proxy/openai.js";

export interface AppDeps {
  config: Config;
  audit: AuditLog;
  clients: ClientService;
  policies: PolicyStore;
  /** Tests only. */
  extraDetectors?: readonly Detector[];
  /** Tests can pass their own log destination to check nothing personal is logged. */
  logStream?: { write(msg: string): void };
}

const ADAPTERS: readonly ApiAdapter[] = [anthropicAdapter, openaiAdapter];

function adapterForUrl(url: string): ApiAdapter | undefined {
  const path = url.split("?")[0];
  return ADAPTERS.find((a) => a.path === path);
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const { config } = deps;

  const app = Fastify({
    bodyLimit: config.maxBodyBytes,
    // We write our own, minimal log lines. Fastify's automatic request logs are off.
    logController: new LogController({ disableRequestLogging: true }),
    logger: deps.logStream
      ? { level: config.logLevel, stream: deps.logStream }
      : { level: config.logLevel },
  });

  // Read JSON ourselves so that (a) we keep the original text, and (b) a
  // parsing error never echoes part of the body back or into the log.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("application/json", { parseAs: "string" }, (_req, body, done) => {
    try {
      const raw = body as string;
      const parsed: ParsedBody = { raw, json: JSON.parse(raw) };
      done(null, parsed);
    } catch {
      done(new GuardError("invalid_request", "KRIS Guard: the request body is not valid JSON."));
    }
  });

  // Turn every error into a short, safe answer in the style the caller's
  // client library expects. Details stay in the server log.
  app.setErrorHandler((error: FastifyError | GuardError, request, reply) => {
    let guardErr: GuardError;
    if (error instanceof GuardError) {
      guardErr = error;
    } else if (error.code === "FST_ERR_CTP_BODY_TOO_LARGE") {
      guardErr = new GuardError("request_too_large", "KRIS Guard: the request is larger than this server accepts.");
    } else if (error.code === "FST_ERR_CTP_INVALID_MEDIA_TYPE" || error.code === "FST_ERR_CTP_EMPTY_JSON_BODY") {
      guardErr = new GuardError("invalid_request", "KRIS Guard: requests must be sent as JSON (Content-Type: application/json).");
    } else if (typeof error.statusCode === "number" && error.statusCode >= 400 && error.statusCode < 500) {
      guardErr = new GuardError("invalid_request", "KRIS Guard: the request could not be understood.");
    } else {
      request.log.error({ err: describeErrorSafely(error) }, "unexpected server error");
      guardErr = failClosedError();
    }
    const requestId = request.krisRequestId ?? `kgreq_${randomHex(12)}`;
    const adapter = adapterForUrl(request.url);
    const body = adapter
      ? adapter.errorBody(guardErr, requestId)
      : { error: { message: guardErr.message, code: `kris_guard_${guardErr.code}`, request_id: requestId } };
    void reply.code(guardErr.status).header("content-type", "application/json; charset=utf-8").send(JSON.stringify(body));
  });

  app.setNotFoundHandler((_request, reply) => {
    void reply
      .code(404)
      .header("content-type", "application/json; charset=utf-8")
      .send(JSON.stringify({ error: { message: "KRIS Guard: no such address.", code: "kris_guard_not_found" } }));
  });

  // A minimal "is it running?" address. Phase 3 adds a fuller health report.
  app.get("/health", async () => ({ status: "ok" }));

  for (const adapter of ADAPTERS) {
    const handler = createProxyHandler(adapter, {
      config,
      audit: deps.audit,
      clients: deps.clients,
      policies: deps.policies,
      log: app.log,
      ...(deps.extraDetectors ? { extraDetectors: deps.extraDetectors } : {}),
    });

    app.post(
      adapter.path,
      {
        // Check the key BEFORE reading the body, so someone without a key
        // cannot make the server read megabytes of data.
        onRequest: async (request, reply) => {
          request.krisStarted = performance.now();
          request.krisRequestId = `kgreq_${randomHex(12)}`;
          let who = null;
          try {
            who = await deps.clients.authenticate(extractApiKey(request.headers));
          } catch (err) {
            request.log.error({ err: describeErrorSafely(err) }, "key check failed; request blocked");
            throw failClosedError();
          }
          if (!who) {
            request.log.warn({ requestId: request.krisRequestId, api: adapter.name }, "rejected: missing or invalid API key");
            const err = new GuardError("unauthorized", "KRIS Guard: missing or invalid API key.");
            await reply
              .code(err.status)
              .header("content-type", "application/json; charset=utf-8")
              .send(JSON.stringify(adapter.errorBody(err, request.krisRequestId)));
            return reply;
          }
          request.krisClient = who;
        },
      },
      handler,
    );
  }

  return app;
}
