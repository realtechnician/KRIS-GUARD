/**
 * Starts a complete KRIS Guard for a test: its own temporary folder, its own
 * database file, its own policy folder, pointed at the fake provider.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { loadConfig, type Config } from "../../src/config.js";
import type { InjectionDetector } from "../../src/injection/detector.js";
import type { Detector } from "../../src/pii/types.js";
import { buildApp } from "../../src/server.js";
import { createServices, type Services } from "../../src/services.js";
import { startFakeProvider, type FakeProvider } from "./fake-provider.js";

export const TEST_AUDIT_KEY = "test-audit-key-0123456789abcdef0123456789abcdef";
export const TEST_SERVER_SECRET = "test-server-secret-fedcba9876543210fedcba9876543210";

export interface TestGateway {
  url: string;
  dir: string;
  dbFile: string;
  config: Config;
  services: Services;
  provider: FakeProvider;
  app: FastifyInstance;
  /** Every log line the server wrote. Tests check that none contains personal data. */
  logs: string[];
  /** Create a client with a policy; returns its API key. */
  addClient(name: string, policyYaml?: string): Promise<{ id: string; apiKey: string; keyId: string }>;
  /** Call the Anthropic-style endpoint. */
  anthropic(apiKey: string, body: unknown, headers?: Record<string, string>): Promise<Response>;
  /** Call the OpenAI-style endpoint. */
  openai(apiKey: string, body: unknown, headers?: Record<string, string>): Promise<Response>;
  close(): Promise<void>;
}

export const DEFAULT_POLICY = `
attachments:
  allowed: false
personal_data:
  names: []
  placeholders: random
`;

export async function startGateway(
  options: {
    extraDetectors?: Detector[];
    injectionDetector?: InjectionDetector;
    env?: Record<string, string>;
    databaseUrl?: string;
  } = {},
): Promise<TestGateway> {
  const provider = await startFakeProvider();
  const dir = await mkdtemp(join(tmpdir(), "kris-guard-test-"));
  const dbFile = join(dir, "kris-guard.db");
  const config = loadConfig({
    KRIS_GUARD_AUDIT_KEY: TEST_AUDIT_KEY,
    KRIS_GUARD_SECRET: TEST_SERVER_SECRET,
    ANTHROPIC_API_KEY: "sk-ant-real-provider-key",
    OPENAI_API_KEY: "sk-openai-real-provider-key",
    ANTHROPIC_BASE_URL: provider.url,
    OPENAI_BASE_URL: provider.url,
    DATABASE_URL: options.databaseUrl ?? `sqlite:${dbFile}`,
    POLICY_DIR: join(dir, "policies"),
    CHECKPOINT_DIR: join(dir, "checkpoints"),
    LOG_LEVEL: "info",
    ...options.env,
  });
  const { mkdir } = await import("node:fs/promises");
  await mkdir(config.policyDir, { recursive: true });

  const services = await createServices(config);
  const logs: string[] = [];
  const app = buildApp({
    config,
    ...services,
    logStream: { write: (msg: string) => void logs.push(msg) },
    ...(options.extraDetectors ? { extraDetectors: options.extraDetectors } : {}),
    ...(options.injectionDetector ? { injectionDetector: options.injectionDetector } : {}),
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const url = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;

  const post = (path: string, authHeader: Record<string, string>, body: unknown, headers: Record<string, string> = {}) =>
    fetch(`${url}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...authHeader, ...headers },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });

  return {
    url,
    dir,
    dbFile,
    config,
    services,
    provider,
    app,
    logs,
    async addClient(name, policyYaml = DEFAULT_POLICY) {
      const client = await services.clients.createClient(name, "test");
      await writeFile(join(config.policyDir, `${client.id}.yaml`), policyYaml);
      const key = await services.clients.createKey(client.id, "test");
      return { id: client.id, apiKey: key.apiKey, keyId: key.record.id };
    },
    anthropic: (apiKey, body, headers) => post("/v1/messages", { "x-api-key": apiKey }, body, headers),
    openai: (apiKey, body, headers) => post("/v1/chat/completions", { authorization: `Bearer ${apiKey}` }, body, headers),
    async close() {
      await app.close();
      await services.db.close();
      await provider.close();
      await rm(dir, { recursive: true, force: true });
    },
  };
}

/** Read a streamed (SSE) answer and return its events as parsed objects. */
export async function readSse(res: Response): Promise<Array<{ event?: string; data: any; raw: string }>> {
  const text = await res.text();
  const out: Array<{ event?: string; data: any; raw: string }> = [];
  for (const block of text.split("\n\n")) {
    if (block.trim() === "") continue;
    let event: string | undefined;
    const data: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith("event: ")) event = line.slice(7);
      else if (line.startsWith("data: ")) data.push(line.slice(6));
    }
    const raw = data.join("\n");
    let parsed: any = raw;
    try {
      parsed = JSON.parse(raw);
    } catch {
      /* e.g. [DONE] */
    }
    out.push(event === undefined ? { data: parsed, raw } : { event, data: parsed, raw });
  }
  return out;
}

/** Join the text of an Anthropic stream. */
export function anthropicStreamText(events: Awaited<ReturnType<typeof readSse>>): string {
  return events
    .filter((e) => e.data?.type === "content_block_delta" && e.data.delta?.type === "text_delta")
    .map((e) => e.data.delta.text)
    .join("");
}

/** Join the tool-call JSON of an Anthropic stream. */
export function anthropicStreamToolJson(events: Awaited<ReturnType<typeof readSse>>): string {
  return events
    .filter((e) => e.data?.type === "content_block_delta" && e.data.delta?.type === "input_json_delta")
    .map((e) => e.data.delta.partial_json)
    .join("");
}

/** Join the text of an OpenAI stream. */
export function openaiStreamText(events: Awaited<ReturnType<typeof readSse>>): string {
  return events.map((e) => e.data?.choices?.[0]?.delta?.content ?? "").join("");
}

/** Join the tool-call arguments of an OpenAI stream. */
export function openaiStreamToolArgs(events: Awaited<ReturnType<typeof readSse>>): string {
  return events.map((e) => e.data?.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments ?? "").join("");
}

/** Sample personal data used across tests. None of it belongs to a real person. */
export const SAMPLE = {
  id: "1199080012345678",
  idSpaced: "1 1990 8 0012345 0 67",
  phone: "+250788123456",
  phoneLocal: "0788 123 456",
  momo: "0791234567",
  email: "jean.mugisha@example.rw",
  tin: "102345678",
  account: "00040-06945754-07",
  name: "Mugisha Jean",
};

export const ALL_SAMPLE_VALUES = Object.values(SAMPLE);
