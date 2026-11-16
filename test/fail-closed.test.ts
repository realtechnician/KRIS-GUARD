/**
 * FAIL CLOSED: when a safety check itself breaks, the request must be blocked,
 * the provider must not be called, and the error must be clear but reveal
 * nothing.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuditEntry } from "../src/audit/log.js";
import type { Detector } from "../src/pii/types.js";
import { SAMPLE, startGateway, type TestGateway } from "./helpers/gateway.js";

let gw: TestGateway | undefined;

afterEach(async () => {
  vi.restoreAllMocks();
  await gw?.close();
  gw = undefined;
});

const BODY = { model: "m", max_tokens: 10, messages: [{ role: "user", content: `Call ${SAMPLE.phone}` }] };

async function expectBlocked(res: Response, code: string, status = 500): Promise<any> {
  expect(res.status).toBe(status);
  const json: any = await res.json();
  expect(json.error.code).toBe(code);
  // The message is generic: no stack trace, no file names, no personal data.
  const text = JSON.stringify(json);
  expect(text).not.toMatch(/\.ts|\.js|node_modules|at \w+ \(|Error:/);
  expect(text).not.toContain(SAMPLE.phone);
  expect(gw!.provider.requests).toHaveLength(0);
  return json;
}

async function auditEntries(): Promise<AuditEntry[]> {
  const out: AuditEntry[] = [];
  for await (const e of gw!.services.audit.entries()) out.push(e);
  return out;
}

describe("fail closed", () => {
  it("a detector that crashes blocks the request (both endpoints, streaming or not)", async () => {
    const crashing: Detector = () => {
      throw new Error(`boom while reading ${SAMPLE.phone}`);
    };
    gw = await startGateway({ extraDetectors: [crashing] });
    const c = await gw.addClient("Crash");

    const json = await expectBlocked(await gw.anthropic(c.apiKey, BODY), "kris_guard_check_failed");
    expect(json.error.message).toContain("Nothing was sent to the AI provider");
    await expectBlocked(await gw.anthropic(c.apiKey, { ...BODY, stream: true }), "kris_guard_check_failed");
    await expectBlocked(await gw.openai(c.apiKey, { model: "m", messages: BODY.messages }), "kris_guard_check_failed");

    // The block is recorded, and the crash message (which contained a phone number) is not in the log.
    const blocked = (await auditEntries()).filter((e) => e.kind === "request");
    expect(blocked).toHaveLength(3);
    for (const e of blocked) expect(e.data).toMatchObject({ decision: "blocked", reason: "check_failed", client_id: c.id });
    expect(gw.logs.join("\n")).not.toContain(SAMPLE.phone);
    expect(gw.logs.join("\n")).toContain("fail closed");
  });

  it("a detector that crashes only on text deep inside a tool result still blocks", async () => {
    const picky: Detector = (text) => {
      if (text.includes("TRIGGER")) throw new Error("boom");
      return [];
    };
    gw = await startGateway({ extraDetectors: [picky] });
    const c = await gw.addClient("Deep");
    const res = await gw.anthropic(c.apiKey, {
      model: "m",
      max_tokens: 10,
      messages: [
        { role: "user", content: "hello" },
        { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "x", input: {} }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: '{"a":{"b":["TRIGGER"]}}' }] }] },
      ],
    });
    await expectBlocked(res, "kris_guard_check_failed");
  });

  it("a detector that misses data on the second look blocks (masking did not fully work)", async () => {
    const faulty: Detector = (text) => {
      const i = text.indexOf("SECRET");
      return i >= 0 ? [{ type: "PHONE", start: i, end: i + 6, priority: 1 }] : [];
    };
    gw = await startGateway({ extraDetectors: [faulty] });
    const c = await gw.addClient("Faulty");
    const res = await gw.anthropic(c.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: "SECRET and SECRET" }] });
    await expectBlocked(res, "kris_guard_check_failed");
  });

  it("if the audit log cannot be written, the request is not forwarded", async () => {
    gw = await startGateway();
    const c = await gw.addClient("NoAudit");
    vi.spyOn(gw.services.audit, "append").mockRejectedValue(new Error("disk full"));
    const json = await expectBlocked(await gw.anthropic(c.apiKey, BODY), "kris_guard_audit_unavailable");
    expect(json.error.message).not.toContain("disk full");
  });

  it("if the policy cannot be loaded, the request is blocked", async () => {
    gw = await startGateway();
    const c = await gw.addClient("NoPolicy");
    vi.spyOn(gw.services.policies, "load").mockRejectedValue(new Error("EACCES: /secret/path/policy.yaml"));
    const json = await expectBlocked(await gw.anthropic(c.apiKey, BODY), "kris_guard_check_failed");
    expect(JSON.stringify(json)).not.toContain("/secret/path");
  });

  it("if the key check itself fails (database down), the request is blocked, not waved through", async () => {
    gw = await startGateway();
    const c = await gw.addClient("NoDb");
    vi.spyOn(gw.services.clients, "authenticate").mockRejectedValue(new Error("SQLITE_IOERR"));
    await expectBlocked(await gw.anthropic(c.apiKey, BODY), "kris_guard_check_failed");
  });

  it("a request nested too deeply to check is refused, and the server keeps running", async () => {
    gw = await startGateway();
    const c = await gw.addClient("Deep2");
    let nested: unknown = SAMPLE.phone;
    for (let i = 0; i < 500; i++) nested = { a: nested };
    const res = await gw.anthropic(c.apiKey, {
      model: "m",
      max_tokens: 10,
      messages: [{ role: "assistant", content: [{ type: "tool_use", id: "t", name: "x", input: nested }] }],
    });
    expect(res.status).toBe(400);
    expect(gw.provider.requests).toHaveLength(0);
    // Still healthy afterwards.
    expect((await gw.anthropic(c.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: "hi" }] })).status).toBe(200);
  });

  it("the server refuses to start with missing, short or identical secrets", async () => {
    const { loadConfig, ConfigError } = await import("../src/config.js");
    expect(() => loadConfig({})).toThrow(ConfigError);
    expect(() => loadConfig({ KRIS_GUARD_AUDIT_KEY: "short", KRIS_GUARD_SECRET: "x".repeat(40) })).toThrow(/at least 32/);
    expect(() => loadConfig({ KRIS_GUARD_AUDIT_KEY: "x".repeat(40), KRIS_GUARD_SECRET: "x".repeat(40) })).toThrow(/different/);
    // The error never prints the secret's value.
    try {
      loadConfig({ KRIS_GUARD_AUDIT_KEY: "my-short-secret", KRIS_GUARD_SECRET: "y".repeat(40) });
    } catch (err) {
      expect((err as Error).message).not.toContain("my-short-secret");
    }
  });
});
