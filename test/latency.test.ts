/**
 * KRIS Guard must add less than 50 ms to a normal request, not counting the
 * time the AI provider itself takes.
 *
 * Measured two ways:
 *   - from outside: total time through the gateway, minus the fake provider's
 *     own (known) delay;
 *   - from inside: the "x-kris-guard-overhead-ms" header the gateway reports.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SAMPLE, startGateway, type TestGateway } from "./helpers/gateway.js";

let gw: TestGateway;
let key: string;

/** A realistic request: a system prompt, a few turns, a tool, and personal data of every kind (~6 KB). */
function normalRequest(stream = false) {
  const paragraph =
    "Uri umufasha w'ikigo cy'ubucuruzi. You help staff answer customer questions clearly and politely. " +
    "Always answer in the customer's language, keep answers short, and never invent account details. ";
  return {
    model: "claude-opus-5-5",
    max_tokens: 1024,
    stream,
    system: paragraph.repeat(12),
    tools: [
      {
        name: "lookup_customer",
        description: "Look up a customer by phone number or national ID.",
        input_schema: { type: "object", properties: { phone: { type: "string" }, id: { type: "string" } } },
      },
    ],
    messages: [
      { role: "user", content: `Mwaramutse. Umukiriya ${SAMPLE.name} (ID ${SAMPLE.idSpaced}) yahamagaye kuri ${SAMPLE.phoneLocal}.` },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "lookup_customer", input: { phone: SAMPLE.phone } }] },
      {
        role: "user",
        content: [
          {
            type: "tool_result",
            tool_use_id: "toolu_1",
            content: JSON.stringify({ name: SAMPLE.name, email: SAMPLE.email, tin: `TIN ${SAMPLE.tin}`, account: SAMPLE.account, history: paragraph.repeat(6) }),
          },
          { type: "text", text: `Please draft a reply to ${SAMPLE.email} about the payment to konti ${SAMPLE.account}. MoMo: ${SAMPLE.momo}.` },
        ],
      },
    ],
  };
}

function percentile(sorted: number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))]!;
}

beforeAll(async () => {
  gw = await startGateway({ env: { LOG_LEVEL: "silent" } });
  const c = await gw.addClient("Speedy", `personal_data:\n  names:\n    - ${SAMPLE.name}\n`);
  key = c.apiKey;
  gw.provider.reply = (text) => ({ text: `Echo: ${text}` });
  for (let i = 0; i < 30; i++) await (await gw.anthropic(key, normalRequest())).text(); // warm up
});

afterAll(async () => {
  await gw.close();
});

describe("added delay", () => {
  it("is under 50 ms for a normal request, excluding the provider's time", async () => {
    const PROVIDER_DELAY = 40;
    gw.provider.delayMs = PROVIDER_DELAY;

    const outside: number[] = [];
    const inside: number[] = [];
    for (let i = 0; i < 100; i++) {
      const t0 = performance.now();
      const res = await gw.anthropic(key, normalRequest());
      const json: any = await res.json();
      outside.push(performance.now() - t0 - PROVIDER_DELAY);
      inside.push(Number(res.headers.get("x-kris-guard-overhead-ms")));
      expect(json.content[0].text).toContain(SAMPLE.email); // it really did the work
    }
    gw.provider.delayMs = 0;
    outside.sort((a, b) => a - b);
    inside.sort((a, b) => a - b);

    const report = {
      outside_median_ms: +percentile(outside, 50).toFixed(2),
      outside_p95_ms: +percentile(outside, 95).toFixed(2),
      inside_median_ms: +percentile(inside, 50).toFixed(2),
      inside_p95_ms: +percentile(inside, 95).toFixed(2),
    };
    console.log("KRIS Guard added delay (non-streaming):", report);

    expect(report.outside_p95_ms).toBeLessThan(50);
    expect(report.inside_p95_ms).toBeLessThan(50);
  });

  it("is under 50 ms before the first streamed piece arrives", async () => {
    const times: number[] = [];
    for (let i = 0; i < 50; i++) {
      const t0 = performance.now();
      const res = await gw.anthropic(key, normalRequest(true));
      const reader = res.body!.getReader();
      await reader.read(); // first piece
      times.push(performance.now() - t0);
      while (!(await reader.read()).done) {
        /* drain */
      }
    }
    times.sort((a, b) => a - b);
    const report = { first_piece_median_ms: +percentile(times, 50).toFixed(2), first_piece_p95_ms: +percentile(times, 95).toFixed(2) };
    console.log("KRIS Guard time to first streamed piece (provider answers instantly):", report);
    expect(report.first_piece_p95_ms).toBeLessThan(50);
  });

  it("stays reasonable for a large (500 KB) request", async () => {
    const big = normalRequest();
    big.messages[0]!.content = `${big.messages[0]!.content} ${"Raporo y'ukwezi irerekana ko ibicuruzwa byiyongereye. ".repeat(9000)}`;
    const res = await gw.anthropic(key, big);
    await res.text();
    const overhead = Number(res.headers.get("x-kris-guard-overhead-ms"));
    console.log("KRIS Guard added delay for a 500 KB request:", { overhead_ms: overhead });
    expect(overhead).toBeLessThan(500);
  });
});
