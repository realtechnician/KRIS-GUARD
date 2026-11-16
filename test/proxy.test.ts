/**
 * End-to-end tests: a real KRIS Guard server, a fake AI provider, real HTTP
 * requests in between. Nothing here touches the internet.
 *
 * The two questions asked over and over:
 *   1. Did the PROVIDER ever see real personal data?  (it must not)
 *   2. Did the CLIENT get its real data back?          (it must)
 */
import { readFile } from "node:fs/promises";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { AuditEntry } from "../src/audit/log.js";
import { PLACEHOLDER_RE } from "../src/pii/placeholders.js";
import {
  ALL_SAMPLE_VALUES,
  SAMPLE,
  anthropicStreamText,
  anthropicStreamToolJson,
  openaiStreamText,
  openaiStreamToolArgs,
  readSse,
  startGateway,
  type TestGateway,
} from "./helpers/gateway.js";

let gw: TestGateway;
let key: string;
let clientId: string;

const POLICY_WITH_NAMES = `
attachments:
  allowed: false
personal_data:
  names:
    - ${SAMPLE.name}
`;

/** A sentence containing one of every kind of personal data. */
const PASSAGE =
  `Umukiriya ${SAMPLE.name} (ID ${SAMPLE.idSpaced}) yahamagaye kuri ${SAMPLE.phoneLocal}. ` +
  `Email: ${SAMPLE.email}, TIN: ${SAMPLE.tin}, konti ${SAMPLE.account}, MoMo ${SAMPLE.momo}. Thanks!`;

function expectProviderSawNoPersonalData(): void {
  expect(gw.provider.requests.length).toBeGreaterThan(0);
  for (const req of gw.provider.requests) {
    for (const value of ALL_SAMPLE_VALUES) expect(req.raw).not.toContain(value);
  }
}

async function auditEntries(): Promise<AuditEntry[]> {
  const out: AuditEntry[] = [];
  for await (const e of gw.services.audit.entries()) out.push(e);
  return out;
}

/** The fake provider answers before the gateway finishes its bookkeeping; wait for the audit entry. */
async function lastAudit(kind: string): Promise<AuditEntry> {
  for (let i = 0; i < 100; i++) {
    const all = (await auditEntries()).filter((e) => e.kind === kind);
    const last = all[all.length - 1];
    if (last) return last;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`no ${kind} audit entry`);
}

async function waitForResponseEntry(requestId: string): Promise<AuditEntry> {
  for (let i = 0; i < 200; i++) {
    const found = (await auditEntries()).find((e) => e.kind === "response" && e.data.request_id === requestId);
    if (found) return found;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("no response audit entry");
}

beforeAll(async () => {
  gw = await startGateway();
  const client = await gw.addClient("Atelier", POLICY_WITH_NAMES);
  key = client.apiKey;
  clientId = client.id;
});

afterAll(async () => {
  await gw.close();
});

beforeEach(() => {
  gw.provider.requests.length = 0;
  gw.provider.reply = (text) => ({ text: `Echo: ${text}` });
  gw.provider.chunkSize = 5;
  gw.provider.networkPieceBytes = 0;
  gw.provider.dieAfterEvents = 0;
});

describe("Anthropic Messages API (/v1/messages)", () => {
  it("hides personal data on the way out and restores it in the answer", async () => {
    const res = await gw.anthropic(key, {
      model: "claude-opus-5-5",
      max_tokens: 1000,
      messages: [{ role: "user", content: PASSAGE }],
    });
    expect(res.status).toBe(200);
    const json: any = await res.json();

    expectProviderSawNoPersonalData();
    expect(json.content[0].text).toBe(`Echo: ${PASSAGE}`);
    expect(json.model).toBe("claude-opus-5-5");
    expect(res.headers.get("x-kris-request-id")).toMatch(/^kgreq_/);
  });

  it("covers every text field: system, message blocks, tools, tool calls and tool results", async () => {
    const res = await gw.anthropic(key, {
      model: "claude-opus-5-5",
      max_tokens: 1000,
      system: [{ type: "text", text: `You assist ${SAMPLE.name}. Their email is ${SAMPLE.email}.` }],
      tools: [
        {
          name: "send_sms",
          description: `Send an SMS. The default recipient is ${SAMPLE.phone}.`,
          input_schema: {
            type: "object",
            properties: {
              to: { type: "string", description: `e.g. ${SAMPLE.phoneLocal}`, enum: [SAMPLE.phone, SAMPLE.momo] },
            },
          },
        },
      ],
      metadata: { user_id: SAMPLE.email },
      stop_sequences: [SAMPLE.tin.padStart(12, "TIN ")],
      messages: [
        { role: "user", content: [{ type: "text", text: `ID yanjye ni ${SAMPLE.id}` }] },
        {
          role: "assistant",
          content: [
            { type: "text", text: `Noted for ${SAMPLE.name}.` },
            {
              type: "tool_use",
              id: "toolu_01",
              name: "send_sms",
              input: { to: SAMPLE.phone, nested: { list: [SAMPLE.email, { deep: SAMPLE.account }] }, asNumber: 250788123456 },
            },
          ],
        },
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "toolu_01", content: `Sent to ${SAMPLE.phone}` },
            {
              type: "tool_result",
              tool_use_id: "toolu_02",
              content: [{ type: "text", text: `{"customer":"${SAMPLE.name}","tin":"TIN ${SAMPLE.tin}"}` }],
            },
            { type: "document", source: { type: "text", media_type: "text/plain", data: `Konti: ${SAMPLE.account}` }, title: `File of ${SAMPLE.name}` },
            { type: "text", text: `Reply to ${SAMPLE.email} please.` },
          ],
        },
      ],
    });
    expect(res.status).toBe(200);
    expectProviderSawNoPersonalData();

    const sent = gw.provider.requests[0]!;
    expect(sent.raw).not.toContain("250788123456"); // the phone number that was a JSON number
    // The structure survived: same tool name, same ids, same roles.
    expect(sent.body.tools[0].name).toBe("send_sms");
    expect(sent.body.messages[1].content[1].id).toBe("toolu_01");
    expect(sent.body.messages[2].content[0].tool_use_id).toBe("toolu_01");
    expect(sent.body.messages[1].content[1].input.to).toMatch(PLACEHOLDER_RE);

    const json: any = await res.json();
    expect(json.content[0].text).toContain(SAMPLE.email);
  });

  it("restores personal data inside a tool call the AI makes", async () => {
    gw.provider.reply = (text) => {
      const placeholders = text.match(PLACEHOLDER_RE) ?? [];
      return { tool: { name: "send_sms", input: { to: placeholders[0], body: `Hello ${placeholders[1]}`, copies: [placeholders[0]] } } };
    };
    const res = await gw.anthropic(key, {
      model: "claude-opus-5-5",
      max_tokens: 1000,
      tools: [{ name: "send_sms", description: "Send an SMS", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: `Text ${SAMPLE.phone} and greet ${SAMPLE.name}` }],
    });
    const json: any = await res.json();
    expectProviderSawNoPersonalData();
    expect(json.content[0]).toMatchObject({
      type: "tool_use",
      name: "send_sms",
      input: { to: SAMPLE.phone, body: `Hello ${SAMPLE.name}`, copies: [SAMPLE.phone] },
    });
  });

  it("streaming: restores placeholders that are split across chunks", async () => {
    for (const chunkSize of [1, 3, 7, 16, 500]) {
      gw.provider.chunkSize = chunkSize;
      const res = await gw.anthropic(key, {
        model: "claude-opus-5-5",
        max_tokens: 1000,
        stream: true,
        messages: [{ role: "user", content: PASSAGE }],
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/event-stream");
      const events = await readSse(res);
      const text = anthropicStreamText(events);
      expect(text).toBe(`Echo: ${PASSAGE}`);
      // No single event may contain part of a placeholder.
      for (const e of events) expect(e.raw).not.toContain("[[KG");
      // The stream still has its proper shape.
      expect(events[0]!.event).toBe("message_start");
      expect(events[events.length - 1]!.event).toBe("message_stop");
    }
    expectProviderSawNoPersonalData();
  });

  it("streaming: works when the network cuts events at arbitrary bytes", async () => {
    gw.provider.chunkSize = 4;
    gw.provider.networkPieceBytes = 7;
    const res = await gw.anthropic(key, {
      model: "claude-opus-5-5",
      max_tokens: 1000,
      stream: true,
      messages: [{ role: "user", content: PASSAGE }],
    });
    expect(anthropicStreamText(await readSse(res))).toBe(`Echo: ${PASSAGE}`);
  });

  it("streaming: restores personal data inside a streamed tool call", async () => {
    gw.provider.chunkSize = 3;
    gw.provider.reply = (text) => {
      const placeholders = text.match(PLACEHOLDER_RE) ?? [];
      return { tool: { name: "send_sms", input: { to: placeholders[0], note: `for ${placeholders[1]}` } } };
    };
    const res = await gw.anthropic(key, {
      model: "claude-opus-5-5",
      max_tokens: 1000,
      stream: true,
      tools: [{ name: "send_sms", description: "Send an SMS", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: `Text ${SAMPLE.phone} and greet ${SAMPLE.name}` }],
    });
    const events = await readSse(res);
    expect(JSON.parse(anthropicStreamToolJson(events))).toEqual({ to: SAMPLE.phone, note: `for ${SAMPLE.name}` });
    expectProviderSawNoPersonalData();
  });

  it("leaves the AI's 'thinking' untouched, so its signature stays valid", async () => {
    gw.provider.reply = (text) => {
      const ph = (text.match(PLACEHOLDER_RE) ?? [])[0]!;
      return { thinking: `The user gave ${ph}.`, text: `Calling ${ph}.` };
    };
    const res = await gw.anthropic(key, {
      model: "claude-opus-5-5",
      max_tokens: 1000,
      messages: [{ role: "user", content: `Call ${SAMPLE.phone}` }],
    });
    const json: any = await res.json();
    expect(json.content[0].type).toBe("thinking");
    expect(json.content[0].thinking).toMatch(PLACEHOLDER_RE); // still hidden
    expect(json.content[0].signature).toBe("sig_fake");
    expect(json.content[1].text).toBe(`Calling ${SAMPLE.phone}.`); // restored

    // Sending that thinking block back in the next turn passes through unchanged.
    gw.provider.requests.length = 0;
    await gw.anthropic(key, {
      model: "claude-opus-5-5",
      max_tokens: 1000,
      messages: [
        { role: "user", content: `Call ${SAMPLE.phone}` },
        { role: "assistant", content: json.content },
        { role: "user", content: "Thanks" },
      ],
    });
    const replayed = gw.provider.requests[0]!.body.messages[1].content[0];
    expect(replayed).toEqual({ type: "thinking", thinking: json.content[0].thinking, signature: "sig_fake" });
  });

  it("uses KRIS's provider key, never the client's key, and forwards only allowed headers", async () => {
    await gw.anthropic(
      key,
      { model: "claude-opus-5-5", max_tokens: 10, messages: [{ role: "user", content: "hi" }] },
      { "anthropic-beta": "some-beta-2026", "x-forwarded-for": "1.2.3.4", "x-evil": "1", cookie: "a=b" },
    );
    const headers = gw.provider.requests[0]!.headers;
    expect(headers["x-api-key"]).toBe("sk-ant-real-provider-key");
    expect(headers["anthropic-version"]).toBe("2023-06-01");
    expect(headers["anthropic-beta"]).toBe("some-beta-2026");
    expect(headers["x-evil"]).toBeUndefined();
    expect(headers["x-forwarded-for"]).toBeUndefined();
    expect(headers.cookie).toBeUndefined();
    expect(JSON.stringify(headers)).not.toContain(key);
  });
});

describe("OpenAI Chat Completions API (/v1/chat/completions)", () => {
  it("hides personal data on the way out and restores it in the answer", async () => {
    const res = await gw.openai(key, {
      model: "gpt-test",
      messages: [
        { role: "system", content: `Customer: ${SAMPLE.name}, ${SAMPLE.email}` },
        { role: "user", content: [{ type: "text", text: PASSAGE }] },
      ],
      user: SAMPLE.email,
    });
    expect(res.status).toBe(200);
    const json: any = await res.json();
    expectProviderSawNoPersonalData();
    expect(json.choices[0].message.content).toBe(`Echo: ${PASSAGE}`);
    expect(gw.provider.requests[0]!.headers.authorization).toBe("Bearer sk-openai-real-provider-key");
  });

  it("covers tool definitions, tool calls (JSON inside a string) and tool results", async () => {
    await gw.openai(key, {
      model: "gpt-test",
      tools: [
        {
          type: "function",
          function: {
            name: "lookup",
            description: `Look up a customer such as ${SAMPLE.name}`,
            parameters: { type: "object", properties: { phone: { type: "string", default: SAMPLE.phone } } },
          },
        },
      ],
      messages: [
        { role: "user", content: `Find ${SAMPLE.phone}` },
        {
          role: "assistant",
          content: null,
          tool_calls: [
            { id: "call_1", type: "function", function: { name: "lookup", arguments: JSON.stringify({ phone: SAMPLE.phone, id: SAMPLE.id }) } },
          ],
        },
        { role: "tool", tool_call_id: "call_1", content: JSON.stringify({ name: SAMPLE.name, email: SAMPLE.email, account: SAMPLE.account }) },
      ],
    });
    expectProviderSawNoPersonalData();
    const sent = gw.provider.requests[0]!.body;
    // The arguments are still a valid JSON string with the same keys.
    const args = JSON.parse(sent.messages[1].tool_calls[0].function.arguments);
    expect(Object.keys(args)).toEqual(["phone", "id"]);
    expect(args.phone).toMatch(PLACEHOLDER_RE);
    expect(sent.messages[2].tool_call_id).toBe("call_1");
  });

  it("restores personal data inside tool-call arguments, keeping the JSON valid", async () => {
    gw.provider.reply = (text) => {
      const ph = (text.match(PLACEHOLDER_RE) ?? [])[0]!;
      return { tool: { name: "lookup", input: { phone: ph, note: `call "${ph}" now` } } };
    };
    const res = await gw.openai(key, { model: "gpt-test", messages: [{ role: "user", content: `Find ${SAMPLE.phone}` }] });
    const json: any = await res.json();
    const args = JSON.parse(json.choices[0].message.tool_calls[0].function.arguments);
    expect(args).toEqual({ phone: SAMPLE.phone, note: `call "${SAMPLE.phone}" now` });
  });

  it("streaming: restores placeholders split across chunks, for text and tool calls", async () => {
    for (const chunkSize of [1, 4, 9, 500]) {
      gw.provider.chunkSize = chunkSize;
      const res = await gw.openai(key, { model: "gpt-test", stream: true, messages: [{ role: "user", content: PASSAGE }] });
      const events = await readSse(res);
      expect(openaiStreamText(events)).toBe(`Echo: ${PASSAGE}`);
      for (const e of events) expect(e.raw).not.toContain("[[KG");
      expect(events[events.length - 1]!.raw).toBe("[DONE]");
    }

    gw.provider.chunkSize = 3;
    gw.provider.reply = (text) => {
      const ph = (text.match(PLACEHOLDER_RE) ?? [])[0]!;
      return { tool: { name: "lookup", input: { phone: ph } } };
    };
    const res = await gw.openai(key, { model: "gpt-test", stream: true, messages: [{ role: "user", content: `Find ${SAMPLE.phone}` }] });
    expect(JSON.parse(openaiStreamToolArgs(await readSse(res)))).toEqual({ phone: SAMPLE.phone });
    expectProviderSawNoPersonalData();
  });

  it("asks the provider for token counts when streaming, without changing what the client sees", async () => {
    const res = await gw.openai(key, { model: "gpt-test", stream: true, messages: [{ role: "user", content: "hi" }] });
    const requestId = res.headers.get("x-kris-request-id")!;
    const events = await readSse(res);
    // The gateway asked for usage...
    expect(gw.provider.requests[0]!.body.stream_options).toEqual({ include_usage: true });
    // ...but the client, who did not ask, does not receive the extra usage event.
    expect(events.some((e) => e.data?.usage)).toBe(false);
    // The audit log has the numbers.
    const entry = await waitForResponseEntry(requestId);
    expect(entry.data).toMatchObject({ input_tokens: 13, output_tokens: 5, status: 200 });

    // A client that DID ask gets the usage event.
    const res2 = await gw.openai(key, {
      model: "gpt-test",
      stream: true,
      stream_options: { include_usage: true },
      messages: [{ role: "user", content: "hi" }],
    });
    expect((await readSse(res2)).some((e) => e.data?.usage)).toBe(true);
  });
});

describe("client keys", () => {
  it("rejects a missing, malformed, unknown or revoked key, and never calls the provider", async () => {
    const body = { model: "claude-opus-5-5", max_tokens: 10, messages: [{ role: "user", content: "hi" }] };

    const none = await fetch(`${gw.url}/v1/messages`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    expect(none.status).toBe(401);
    expect(((await none.json()) as any).error.type).toBe("authentication_error");

    expect((await gw.anthropic("not-a-key", body)).status).toBe(401);
    expect((await gw.anthropic(`kg_00000000_${"0".repeat(64)}`, body)).status).toBe(401);
    expect((await gw.openai("sk-ant-real-provider-key", { model: "m", messages: [] })).status).toBe(401);

    const temp = await gw.services.clients.createKey(clientId, "test");
    expect((await gw.anthropic(temp.apiKey, body)).status).toBe(200);
    gw.provider.requests.length = 0;
    await gw.services.clients.revokeKey(temp.record.id, "test");
    expect((await gw.anthropic(temp.apiKey, body)).status).toBe(401);

    expect(gw.provider.requests).toHaveLength(0);
  });

  it("accepts the key in either header style on either endpoint", async () => {
    const body = { model: "m", max_tokens: 10, messages: [{ role: "user", content: "hi" }] };
    const viaBearer = await fetch(`${gw.url}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
      body: JSON.stringify(body),
    });
    expect(viaBearer.status).toBe(200);
  });

  it("stores only a hash: the key itself is nowhere in the database", async () => {
    const dbBytes = await readFile(gw.dbFile, "latin1");
    const wal = await readFile(`${gw.dbFile}-wal`, "latin1").catch(() => "");
    const secretPart = key.split("_")[2]!;
    expect(dbBytes + wal).not.toContain(secretPart);
  });
});

describe("attachments", () => {
  const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

  it.each([
    ["an image", { type: "image", source: { type: "base64", media_type: "image/png", data: png } }],
    ["an image by URL", { type: "image", source: { type: "url", url: "https://example.com/a.png" } }],
    ["a PDF", { type: "document", source: { type: "base64", media_type: "application/pdf", data: png } }],
    ["an uploaded file", { type: "document", source: { type: "file", file_id: "file_abc" } }],
    ["an image inside a tool result", { type: "tool_result", tool_use_id: "t1", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: png } }] }],
    ["file data hidden in a block of an unknown type", { type: "future_block", payload: { blob: "A".repeat(400) } }],
  ])("blocks %s by default (Anthropic)", async (_label, block) => {
    const res = await gw.anthropic(key, { model: "m", max_tokens: 10, messages: [{ role: "user", content: [block, { type: "text", text: "what is this?" }] }] });
    expect(res.status).toBe(403);
    const json: any = await res.json();
    expect(json.error.code).toBe("kris_guard_attachment_blocked");
    expect(gw.provider.requests).toHaveLength(0);
  });

  it.each([
    ["an image", { type: "image_url", image_url: { url: `data:image/png;base64,${png}` } }],
    ["audio", { type: "input_audio", input_audio: { data: png, format: "wav" } }],
    ["a file", { type: "file", file: { file_id: "file_abc" } }],
  ])("blocks %s by default (OpenAI)", async (_label, part) => {
    const res = await gw.openai(key, { model: "m", messages: [{ role: "user", content: [part, { type: "text", text: "what is this?" }] }] });
    expect(res.status).toBe(403);
    expect(((await res.json()) as any).error.code).toBe("kris_guard_attachment_blocked");
    expect(gw.provider.requests).toHaveLength(0);
  });

  it("allows them when the client's policy says so, still hides text around them, and records it", async () => {
    const open = await gw.addClient("Open Studio", "attachments:\n  allowed: true\n");
    const image = { type: "image", source: { type: "base64", media_type: "image/png", data: png } };
    const res = await gw.anthropic(open.apiKey, {
      model: "m",
      max_tokens: 10,
      messages: [{ role: "user", content: [image, { type: "text", text: `Send to ${SAMPLE.phone}` }] }],
    });
    expect(res.status).toBe(200);
    const sent = gw.provider.requests[0]!;
    expect(sent.body.messages[0].content[0]).toEqual(image); // passed through unchanged
    expect(sent.raw).not.toContain(SAMPLE.phone);

    const entry = await lastAudit("request");
    expect(entry.data).toMatchObject({ client_id: open.id, attachments: 1, decision: "forwarded" });
    expect(entry.data.policy_decisions).toContain("attachments_allowed_unchecked");
  });

  it("a plain-text document is not an attachment: it is read and masked", async () => {
    const res = await gw.anthropic(key, {
      model: "m",
      max_tokens: 10,
      messages: [{ role: "user", content: [{ type: "document", source: { type: "text", media_type: "text/plain", data: `Call ${SAMPLE.phone}` } }] }],
    });
    expect(res.status).toBe(200);
    expectProviderSawNoPersonalData();
  });
});

describe("personal data where it cannot be hidden", () => {
  it("blocks the request rather than send it", async () => {
    const inToolName = await gw.anthropic(key, {
      model: "m",
      max_tokens: 10,
      tools: [{ name: `call_${SAMPLE.phoneLocal.replace(/ /g, "")}`, description: "x", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: "hi" }],
    });
    expect(inToolName.status).toBe(403);
    const json: any = await inToolName.json();
    expect(json.error.code).toBe("kris_guard_unmaskable_personal_data");
    expect(JSON.stringify(json)).not.toContain("0788123456");

    const inModel = await gw.openai(key, { model: SAMPLE.email, messages: [{ role: "user", content: "hi" }] });
    expect(inModel.status).toBe(403);

    const inUnknownField = await gw.anthropic(key, { model: "m", max_tokens: 10, some_new_setting: { owner: SAMPLE.email }, messages: [{ role: "user", content: "hi" }] });
    expect(inUnknownField.status).toBe(403);

    expect(gw.provider.requests).toHaveLength(0);
    const entry = await lastAudit("request");
    expect(entry.data).toMatchObject({ decision: "blocked", reason: "unmaskable_personal_data" });
  });
});

describe("errors are safe and clear", () => {
  it("invalid JSON: a clear message that does not echo the body", async () => {
    const res = await gw.anthropic(key, `{"model": "m", "messages": [{"content": "call ${SAMPLE.phone}"`);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("not valid JSON");
    expect(text).not.toContain(SAMPLE.phone);
  });

  it("wrong content type, missing model, wrong shapes", async () => {
    const form = await fetch(`${gw.url}/v1/messages`, { method: "POST", headers: { "x-api-key": key, "content-type": "text/plain" }, body: "hello" });
    expect(form.status).toBe(400);
    expect((await gw.anthropic(key, { messages: [] })).status).toBe(400);
    expect((await gw.anthropic(key, { model: "m", messages: "nope" })).status).toBe(400);
    expect((await gw.anthropic(key, [1, 2, 3])).status).toBe(400);
    expect((await fetch(`${gw.url}/v1/unknown`)).status).toBe(404);
  });

  it("a request over the size limit is refused", async () => {
    const small = await startGateway({ env: { MAX_BODY_BYTES: "2048" } });
    try {
      const c = await small.addClient("Tiny");
      const res = await small.anthropic(c.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: "x".repeat(5000) }] });
      expect(res.status).toBe(413);
      expect(small.provider.requests).toHaveLength(0);
    } finally {
      await small.close();
    }
  });

  it("passes a provider error through without restoring anything into it", async () => {
    gw.provider.reply = (text) => ({
      status: 400,
      error: { type: "error", error: { type: "invalid_request_error", message: `bad input near ${(text.match(PLACEHOLDER_RE) ?? [])[0]}` } },
    });
    const res = await gw.anthropic(key, { model: "m", max_tokens: 10, messages: [{ role: "user", content: `Call ${SAMPLE.phone}` }] });
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("invalid_request_error");
    expect(text).not.toContain(SAMPLE.phone);
  });

  it("reports clearly when the provider cannot be reached", async () => {
    const down = await startGateway({ env: { ANTHROPIC_BASE_URL: "http://127.0.0.1:9" } });
    try {
      const c = await down.addClient("Offline");
      const res = await down.anthropic(c.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: "hi" }] });
      expect(res.status).toBe(502);
      const json: any = await res.json();
      expect(json.error.code).toBe("kris_guard_provider_unreachable");
      expect(JSON.stringify(json)).not.toContain("127.0.0.1");
    } finally {
      await down.close();
    }
  });

  it("refuses when the provider key is not configured", async () => {
    const noKey = await startGateway({ env: { OPENAI_API_KEY: "" } });
    try {
      const c = await noKey.addClient("NoKey");
      const res = await noKey.openai(c.apiKey, { model: "m", messages: [{ role: "user", content: "hi" }] });
      expect(res.status).toBe(503);
    } finally {
      await noKey.close();
    }
  });

  it("a stream that breaks half-way ends with an error event, with no half placeholder leaked", async () => {
    gw.provider.chunkSize = 4;
    gw.provider.dieAfterEvents = 6;
    const res = await gw.anthropic(key, { model: "m", max_tokens: 10, stream: true, messages: [{ role: "user", content: PASSAGE }] });
    const events = await readSse(res);
    expect(events[events.length - 1]!.event).toBe("error");
    expect(events[events.length - 1]!.data.error.code).toBe("kris_guard_provider_unreachable");
    for (const e of events) expect(e.raw).not.toContain("[[KG");
    // Whatever text did arrive is correctly restored: it is the start of the expected answer.
    const partial = anthropicStreamText(events);
    expect(`Echo: ${PASSAGE}`.startsWith(partial)).toBe(true);
  });
});

describe("client isolation", () => {
  it("one client's name list and attachment rule never apply to another client", async () => {
    const a = await gw.addClient("Client A", "personal_data:\n  names: [Kalisa]\nattachments:\n  allowed: true\n");
    const b = await gw.addClient("Client B", "personal_data:\n  names: [Ingabire]\n");
    const text = "Kalisa met Ingabire";

    await gw.anthropic(a.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: text }] });
    const seenA = gw.provider.requests[0]!.raw;
    expect(seenA).not.toContain("Kalisa");
    expect(seenA).toContain("Ingabire"); // B's list does not apply to A

    gw.provider.requests.length = 0;
    await gw.anthropic(b.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: text }] });
    const seenB = gw.provider.requests[0]!.raw;
    expect(seenB).toContain("Kalisa");
    expect(seenB).not.toContain("Ingabire");

    // A may send attachments; B, using the very same request, may not.
    const image = { type: "image", source: { type: "url", url: "https://example.com/a.png" } };
    const body = { model: "m", max_tokens: 10, messages: [{ role: "user", content: [image] }] };
    expect((await gw.anthropic(a.apiKey, body)).status).toBe(200);
    expect((await gw.anthropic(b.apiKey, body)).status).toBe(403);
  });

  it("nothing in a request can make it count as another client", async () => {
    const a = await gw.addClient("Client C", "personal_data:\n  names: [Kalisa]\n");
    const b = await gw.addClient("Client D", "attachments:\n  allowed: true\n");
    const image = { type: "image", source: { type: "url", url: "https://example.com/a.png" } };

    // Client C tries to borrow Client D's "attachments allowed" policy every way a request could.
    const res = await gw.anthropic(
      a.apiKey,
      {
        model: "m",
        max_tokens: 10,
        client_id: b.id,
        metadata: { client_id: b.id, user_id: b.id },
        messages: [{ role: "user", content: [image] }],
      },
      { "x-kris-client": b.id, "x-client-id": b.id, "x-kris-user": b.id },
    );
    expect(res.status).toBe(403);

    const entry = await lastAudit("request");
    expect(entry.data.client_id).toBe(a.id);
    expect(entry.data.key_id).toBe(a.keyId);
  });

  it("placeholders from one client's request restore nothing in another's", async () => {
    const a = await gw.addClient("Client E");
    const b = await gw.addClient("Client F");

    let stolen = "";
    gw.provider.reply = (text) => {
      stolen = (text.match(PLACEHOLDER_RE) ?? [])[0] ?? stolen;
      return { text: `Echo: ${text}` };
    };
    await gw.anthropic(a.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: `My number is ${SAMPLE.phone}` }] });
    expect(stolen).toMatch(PLACEHOLDER_RE);

    // Client F sends client E's placeholder, hoping the gateway fills in the value.
    const res = await gw.anthropic(b.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: `What is ${stolen}?` }] });
    const json: any = await res.json();
    expect(json.content[0].text).toBe(`Echo: What is ${stolen}?`);
    expect(JSON.stringify(json)).not.toContain(SAMPLE.phone);
  });

  it("a client with a missing or broken policy file is blocked, without affecting others", async () => {
    const broken = await gw.addClient("Broken", "attachments:\n  alowed: true\n"); // misspelt setting
    const res = await gw.anthropic(broken.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: "hi" }] });
    expect(res.status).toBe(403);
    expect(((await res.json()) as any).error.code).toBe("kris_guard_policy_unavailable");
    expect(gw.provider.requests).toHaveLength(0);

    expect((await gw.anthropic(key, { model: "m", max_tokens: 10, messages: [{ role: "user", content: "hi" }] })).status).toBe(200);
  });
});

describe('the "stable" placeholder option', () => {
  it("gives the same value the same placeholder on every request, so history stays identical", async () => {
    const stable = await gw.addClient("Stable Co", "personal_data:\n  placeholders: stable\n");
    const other = await gw.addClient("Other Stable", "personal_data:\n  placeholders: stable\n");
    const turn1 = { role: "user", content: `My number is ${SAMPLE.phone}` };

    const first = await gw.anthropic(stable.apiKey, { model: "m", max_tokens: 10, messages: [turn1] });
    const answer: any = await first.json();
    expect(answer.content[0].text).toBe(`Echo: My number is ${SAMPLE.phone}`);

    // Second turn: the client sends the whole (restored) history back.
    await gw.anthropic(stable.apiKey, {
      model: "m",
      max_tokens: 10,
      messages: [turn1, { role: "assistant", content: answer.content }, { role: "user", content: `Repeat ${SAMPLE.phone}` }],
    });

    const [req1, req2] = gw.provider.requests;
    // The provider sees the first message byte-for-byte unchanged between turns...
    expect(JSON.stringify(req2!.body.messages[0])).toBe(JSON.stringify(req1!.body.messages[0]));
    // ...and still never sees the real number.
    expect(req1!.raw + req2!.raw).not.toContain(SAMPLE.phone);
    const placeholder = req1!.raw.match(PLACEHOLDER_RE)![0];
    expect(req2!.raw.match(PLACEHOLDER_RE)!.every((p) => p === placeholder)).toBe(true);

    // A different client gets a different placeholder for the same number.
    gw.provider.requests.length = 0;
    await gw.anthropic(other.apiKey, { model: "m", max_tokens: 10, messages: [turn1] });
    expect(gw.provider.requests[0]!.raw.match(PLACEHOLDER_RE)![0]).not.toBe(placeholder);
  });

  it("with the default (random), the same history looks different on each request", async () => {
    const turn1 = { role: "user", content: `My number is ${SAMPLE.phone}` };
    await gw.anthropic(key, { model: "m", max_tokens: 10, messages: [turn1] });
    await gw.anthropic(key, { model: "m", max_tokens: 10, messages: [turn1] });
    const [req1, req2] = gw.provider.requests;
    expect(req1!.raw.match(PLACEHOLDER_RE)![0]).not.toBe(req2!.raw.match(PLACEHOLDER_RE)![0]);
  });
});

describe("what gets recorded", () => {
  it("records each request with its client, model, tokens and what was hidden", async () => {
    const res = await gw.anthropic(
      key,
      { model: "claude-opus-5-5", max_tokens: 10, messages: [{ role: "user", content: PASSAGE }] },
      { "x-kris-user": "user-4821" },
    );
    const requestId = res.headers.get("x-kris-request-id")!;
    await res.text();
    const response = await waitForResponseEntry(requestId);
    const request = (await auditEntries()).find((e) => e.kind === "request" && e.data.request_id === requestId)!;

    expect(request.data).toMatchObject({
      client_id: clientId,
      user_label: "user-4821",
      api: "anthropic",
      model: "claude-opus-5-5",
      stream: false,
      decision: "forwarded",
      pii_hidden: { NAME: 1, NATIONAL_ID: 1, PHONE: 2, EMAIL: 1, TIN: 1, BANK_ACCOUNT: 1 },
      attachments: 0,
    });
    expect(response.data).toMatchObject({ client_id: clientId, status: 200, input_tokens: 11, output_tokens: 7 });
    expect(typeof response.data.duration_ms).toBe("number");
  });

  it("a user label that is personal data is replaced by a stable scrambled code", async () => {
    const send = () =>
      gw.anthropic(key, { model: "m", max_tokens: 10, messages: [{ role: "user", content: "hi" }] }, { "x-kris-user": SAMPLE.email });
    await (await send()).text();
    const first = (await lastAudit("request")).data.user_label as string;
    await (await send()).text();
    const second = (await lastAudit("request")).data.user_label as string;
    expect(first).toMatch(/^anon_[0-9a-f]{16}$/);
    expect(second).toBe(first);
  });

  it("NEVER stores personal data: not in the database, not in the audit log, not in the server log", async () => {
    // Send personal data through every route first, including blocked and failing requests.
    await (await gw.anthropic(key, { model: "m", max_tokens: 10, messages: [{ role: "user", content: PASSAGE }] })).text();
    await (await gw.openai(key, { model: "m", stream: true, messages: [{ role: "user", content: PASSAGE }], user: SAMPLE.email })).text();
    await (await gw.anthropic(key, { model: SAMPLE.email, max_tokens: 10, messages: [{ role: "user", content: PASSAGE }] })).text();
    await (await gw.anthropic(key, `{"broken": "${PASSAGE}"`)).text();
    await (await gw.anthropic(key, { model: "m", max_tokens: 10, messages: [{ role: "user", content: PASSAGE }] }, { "x-kris-user": SAMPLE.phone })).text();
    await new Promise((r) => setTimeout(r, 100));

    const dbBytes = await readFile(gw.dbFile, "latin1");
    const walBytes = await readFile(`${gw.dbFile}-wal`, "latin1").catch(() => "");
    const logs = gw.logs.join("\n");
    const auditText = JSON.stringify(await auditEntries());

    expect(dbBytes.length).toBeGreaterThan(0);
    expect(logs.length).toBeGreaterThan(0);
    for (const value of [...ALL_SAMPLE_VALUES, "0788123456", "Mugisha"]) {
      expect(dbBytes).not.toContain(value);
      expect(walBytes).not.toContain(value);
      expect(logs).not.toContain(value);
      expect(auditText).not.toContain(value);
    }
    // And no placeholders either: the audit log records kinds and counts only.
    expect(auditText).not.toContain("[[KG-");
  });
});
