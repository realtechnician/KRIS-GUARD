/**
 * An "adapter" describes one AI provider's API to the rest of KRIS Guard.
 *
 * The proxy logic (check key, hide data, forward, restore, record) is the
 * same for every provider. Only the SHAPE of requests and answers differs.
 * Each adapter knows that shape. To support another provider later, write
 * another adapter; nothing else changes.
 */
import type { Config } from "../config.js";
import type { GuardError } from "../errors.js";
import type { Masker } from "../pii/masker.js";
import type { WalkContext } from "../pii/walk.js";
import type { SseEvent } from "./sse.js";

/** Token counts reported by the provider. null means "the provider did not say". */
export interface Usage {
  inputTokens: number | null;
  outputTokens: number | null;
  cacheReadTokens: number | null;
  cacheWriteTokens: number | null;
}

export const NO_USAGE: Usage = {
  inputTokens: null,
  outputTokens: null,
  cacheReadTokens: null,
  cacheWriteTokens: null,
};

/** Rewrites a streamed answer event by event, restoring placeholders. */
export interface StreamTransformer {
  /** One event in from the provider; zero or more events out to the client. */
  transform(event: SseEvent): SseEvent[];
  /** The provider's stream ended; release anything still held back. */
  finish(): SseEvent[];
  usage(): Usage;
  /**
   * The answer's text exactly as the PROVIDER sent it (placeholders not yet
   * restored), for the optional "new personal data in the answer" scan.
   * Capped in size; empty unless collection was switched on.
   */
  collectedText(): string;
}

/** The most answer text kept for scanning a streamed answer (1 MB). */
export const MAX_COLLECTED_ANSWER = 1024 * 1024;

export interface ApiAdapter {
  name: "anthropic" | "openai";
  /** The path clients call on KRIS Guard, e.g. "/v1/messages". */
  path: string;

  /** KRIS's key for this provider, or undefined if not configured. */
  providerKey(config: Config): string | undefined;
  upstreamUrl(config: Config): string;
  /** Headers sent to the provider. Built from scratch: nothing the client sent is forwarded unless listed here. */
  upstreamHeaders(providerKey: string, clientHeaders: Record<string, string | string[] | undefined>): Record<string, string>;

  /** Hide personal data everywhere in the request; collect attachments. Returns the safe copy. */
  sanitize(body: Record<string, unknown>, ctx: WalkContext): Record<string, unknown>;
  /** Last-minute adjustments to the safe copy before it is sent (e.g. ask for token counts). */
  prepare(body: Record<string, unknown>): Record<string, unknown>;
  /** The end-user label the client supplied in the body, if any. */
  userLabelFromBody(body: Record<string, unknown>): string | undefined;

  /** Put real values back into a complete (non-streamed) answer. */
  restoreResponse(json: unknown, masker: Masker): unknown;
  usageFromResponse(json: unknown): Usage;
  /** The pieces of text the AI wrote in a complete answer (before restoring), for the answer scan. */
  answerTexts(json: unknown): string[];
  /** @param collectAnswer keep the un-restored answer text so it can be scanned at the end */
  createStreamTransformer(masker: Masker, originalBody: Record<string, unknown>, collectAnswer: boolean): StreamTransformer;

  /** The error body in this provider's style, so client libraries understand it. */
  errorBody(err: GuardError, requestId: string): unknown;
  /** An error event for use in the middle of a stream. */
  streamErrorEvent(err: GuardError, requestId: string): SseEvent;
}

export function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export function firstHeader(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}
