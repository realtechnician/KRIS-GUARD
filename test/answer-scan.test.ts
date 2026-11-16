/**
 * The optional scan of the AI's ANSWER for personal data that was not in the
 * request (made up by the AI, or leaked from somewhere else).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { AuditEntry } from "../src/audit/log.js";
import { SAMPLE, readSse, startGateway, type TestGateway } from "./helpers/gateway.js";

let gw: TestGateway;
let scanKey: string;
let plainKey: string;

/** A phone number and an email that are NOT in any request below. */
const INVENTED_PHONE = "0722 555 010";
const INVENTED_EMAIL = "someone.else@example.rw";

const ask = (text: string, stream = false) => ({ model: "m", max_tokens: 50, stream, messages: [{ role: "user", content: text }] });

async function responseEntry(requestId: string): Promise<AuditEntry> {
  for (let i = 0; i < 200; i++) {
    for await (const e of gw.services.audit.entries()) {
      if (e.kind === "response" && e.data.request_id === requestId) return e;
    }
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("no response audit entry");
}

beforeAll(async () => {
  gw = await startGateway();
  scanKey = (await gw.addClient("Scan Co", `personal_data:\n  scan_answers: true\n  names: [Uwase]\n`)).apiKey;
  plainKey = (await gw.addClient("Plain Co")).apiKey; // default: scan_answers off
});

afterAll(async () => {
  await gw.close();
});

beforeEach(() => {
  gw.provider.requests.length = 0;
  gw.provider.chunkSize = 4;
  gw.provider.reply = (text) => ({ text: `Echo: ${text}` });
});

describe("answer scan", () => {
  it("flags personal data the AI introduced, in a header and in the audit log", async () => {
    gw.provider.reply = () => ({ text: `You could also call ${INVENTED_PHONE} or write to ${INVENTED_EMAIL}. Ask for Uwase.` });
    const res = await gw.anthropic(scanKey, ask("Who can help me?"));
    expect(res.status).toBe(200);
    expect(res.headers.get("x-kris-guard-warnings")).toBe("new-personal-data-in-answer");

    // The answer itself is delivered unchanged: this is a flag, not a filter.
    const json: any = await res.json();
    expect(json.content[0].text).toContain(INVENTED_PHONE);

    const entry = await responseEntry(res.headers.get("x-kris-request-id")!);
    expect(entry.data.answer_new_pii).toEqual(["EMAIL", "NAME", "PHONE"]);
    // Kinds only. The values themselves are never recorded.
    const text = JSON.stringify(entry.data);
    expect(text).not.toContain(INVENTED_PHONE);
    expect(text).not.toContain(INVENTED_EMAIL);
    expect(text).not.toContain("Uwase");
  });

  it("does NOT flag personal data that came from the request", async () => {
    const res = await gw.anthropic(scanKey, ask(`Please repeat: ${SAMPLE.phone}, ${SAMPLE.email}, ID ${SAMPLE.id}`));
    const json: any = await res.json();
    expect(json.content[0].text).toContain(SAMPLE.phone); // restored for the client as usual
    expect(res.headers.get("x-kris-guard-warnings")).toBeNull();
    const entry = await responseEntry(res.headers.get("x-kris-request-id")!);
    expect(entry.data.answer_new_pii).toBeUndefined();
  });

  it("flags new personal data inside a tool call the AI makes", async () => {
    gw.provider.reply = () => ({ tool: { name: "send_sms", input: { to: INVENTED_PHONE, text: "hi" } } });
    const anth = await gw.anthropic(scanKey, ask("Send a hello."));
    expect((await responseEntry(anth.headers.get("x-kris-request-id")!)).data.answer_new_pii).toEqual(["PHONE"]);

    const oai = await gw.openai(scanKey, { model: "m", messages: [{ role: "user", content: "Send a hello." }] });
    expect(oai.headers.get("x-kris-guard-warnings")).toBe("new-personal-data-in-answer");
    expect((await responseEntry(oai.headers.get("x-kris-request-id")!)).data.answer_new_pii).toEqual(["PHONE"]);
  });

  it("works on streamed answers, even when the new value is split across chunks", async () => {
    gw.provider.chunkSize = 3;
    gw.provider.reply = (text) => ({ text: `Echo: ${text}. Also try ${INVENTED_PHONE}.` });

    const anth = await gw.anthropic(scanKey, ask(`My number is ${SAMPLE.phone}`, true));
    await readSse(anth);
    expect((await responseEntry(anth.headers.get("x-kris-request-id")!)).data.answer_new_pii).toEqual(["PHONE"]);

    const oai = await gw.openai(scanKey, { model: "m", stream: true, messages: [{ role: "user", content: `My number is ${SAMPLE.phone}` }] });
    await readSse(oai);
    expect((await responseEntry(oai.headers.get("x-kris-request-id")!)).data.answer_new_pii).toEqual(["PHONE"]);
  });

  it("a streamed answer that only repeats request data is not flagged", async () => {
    gw.provider.chunkSize = 3;
    const res = await gw.anthropic(scanKey, ask(`My number is ${SAMPLE.phone}`, true));
    await readSse(res);
    expect((await responseEntry(res.headers.get("x-kris-request-id")!)).data.answer_new_pii).toBeUndefined();
  });

  it("is off by default", async () => {
    gw.provider.reply = () => ({ text: `Call ${INVENTED_PHONE}.` });
    const res = await gw.anthropic(plainKey, ask("Who can help me?"));
    expect(res.headers.get("x-kris-guard-warnings")).toBeNull();
    expect((await responseEntry(res.headers.get("x-kris-request-id")!)).data.answer_new_pii).toBeUndefined();
  });
});
