/**
 * PostgreSQL is optional, so this test only runs when you point it at a
 * PostgreSQL server:
 *
 *     TEST_POSTGRES_URL=postgres://user:pass@localhost:5432/postgres npm test
 *
 * It creates a throwaway database, runs the important paths against it
 * (keys, a proxied request, audit chain, tamper detection), and deletes it.
 * Without the variable, the test is skipped and SQLite covers everything.
 */
import { randomBytes } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SAMPLE, startGateway, type TestGateway } from "./helpers/gateway.js";

const baseUrl = process.env.TEST_POSTGRES_URL;

describe.skipIf(!baseUrl)("PostgreSQL (optional)", () => {
  const dbName = `kris_guard_test_${randomBytes(4).toString("hex")}`;
  let gw: TestGateway;
  let dbUrl: string;

  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: baseUrl });
    await admin.connect();
    await admin.query(`create database ${dbName}`);
    await admin.end();
    const u = new URL(baseUrl!);
    u.pathname = `/${dbName}`;
    dbUrl = u.toString();
    gw = await startGateway({ databaseUrl: dbUrl });
  });

  afterAll(async () => {
    await gw?.close();
    const admin = new pg.Client({ connectionString: baseUrl });
    await admin.connect();
    await admin.query(`drop database if exists ${dbName} with (force)`);
    await admin.end();
  });

  it("runs the whole flow: key, masked request, restored answer, audit entries", async () => {
    expect(gw.services.db.kind).toBe("postgres");
    const c = await gw.addClient("Pg Client");
    const res = await gw.anthropic(c.apiKey, { model: "m", max_tokens: 10, messages: [{ role: "user", content: `Call ${SAMPLE.phone}` }] });
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).content[0].text).toBe(`Echo: Call ${SAMPLE.phone}`);
    expect(gw.provider.requests[0]!.raw).not.toContain(SAMPLE.phone);

    await gw.services.clients.revokeKey(c.keyId, "test");
    expect((await gw.anthropic(c.apiKey, { model: "m", max_tokens: 10, messages: [] })).status).toBe(401);
  });

  it("keeps the audit chain valid under parallel writes, and detects tampering", async () => {
    await Promise.all(Array.from({ length: 40 }, (_, i) => gw.services.audit.append("request", { request_id: `pg_${i}` })));
    const ok = await gw.services.audit.verify();
    expect(ok.ok).toBe(true);
    expect(typeof (ok as any).entries).toBe("number");

    const attacker = new pg.Client({ connectionString: dbUrl });
    await attacker.connect();
    await attacker.query(`update audit_log set data = '{"edited":true}' where seq = 5`);
    await attacker.end();
    expect(await gw.services.audit.verify()).toMatchObject({ ok: false, brokenAt: 5 });
  });
});
