/**
 * The audit log: every kind of tampering must be detected, and `verify` must
 * say exactly where the log is broken.
 *
 * The "attacker" in these tests has full read/write access to the database
 * but does NOT know the audit secret key.
 */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadCheckpoints, writeCheckpoint } from "../src/audit/checkpoint.js";
import { csvCell, exportAudit } from "../src/audit/export.js";
import { AuditLog, GENESIS_HASH, entryDigestInput } from "../src/audit/log.js";
import { run } from "../src/cli.js";
import { loadConfig, type Config } from "../src/config.js";
import { hmacHex, sha256Hex } from "../src/crypto.js";
import { createServices, type Services } from "../src/services.js";
import { TEST_AUDIT_KEY, TEST_SERVER_SECRET } from "./helpers/gateway.js";

let dir: string;
let dbFile: string;
let config: Config;
let services: Services;
let audit: AuditLog;
/** A second, direct connection to the same database file: the attacker's hands. */
let attacker: BetterSqlite3.Database;

const ATTACKER_KEY = "the-attacker-does-not-know-the-real-key-000000";

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "kris-guard-audit-"));
  dbFile = join(dir, "audit.db");
  config = loadConfig({
    KRIS_GUARD_AUDIT_KEY: TEST_AUDIT_KEY,
    KRIS_GUARD_SECRET: TEST_SERVER_SECRET,
    DATABASE_URL: `sqlite:${dbFile}`,
    POLICY_DIR: join(dir, "policies"),
    CHECKPOINT_DIR: join(dir, "checkpoints"),
  });
  services = await createServices(config);
  audit = services.audit;
  attacker = new BetterSqlite3(dbFile);
  for (let i = 1; i <= 10; i++) {
    await audit.append("request", { request_id: `req_${i}`, client_id: "atelier", model: "m", decision: "forwarded" });
  }
});

afterEach(async () => {
  vi.restoreAllMocks();
  attacker.close();
  await services.db.close();
  await rm(dir, { recursive: true, force: true });
});

const checkpointDir = () => config.checkpointDir;
const verifyWithCheckpoints = async () => audit.verify((await loadCheckpoints(TEST_AUDIT_KEY, checkpointDir())).valid);

/** What an attacker without the key can do: recompute the public hashes from entry `from` onwards. */
function rebuildChainWithoutKey(from: number): void {
  const rows = attacker.prepare("select * from audit_log where seq >= ? order by seq").all(from) as any[];
  let prev =
    from === 1 ? GENESIS_HASH : (attacker.prepare("select hash from audit_log where seq = ?").get(from - 1) as any).hash;
  for (const r of rows) {
    const hash = sha256Hex(entryDigestInput(r.seq, r.ts, r.kind, prev, r.data));
    const hmac = hmacHex(ATTACKER_KEY, hash); // the best they can do: sign with a key of their own
    attacker.prepare("update audit_log set prev_hash = ?, hash = ?, hmac = ? where seq = ?").run(prev, hash, hmac, r.seq);
    prev = hash;
  }
}

describe("an untouched log", () => {
  it("verifies as valid", async () => {
    const result = await audit.verify();
    expect(result).toMatchObject({ ok: true, entries: 10 });
  });

  it("an empty log is valid", async () => {
    attacker.prepare("delete from audit_log").run();
    expect(await audit.verify()).toMatchObject({ ok: true, entries: 0, headHash: GENESIS_HASH });
  });

  it("numbers entries 1, 2, 3... even when many are written at once", async () => {
    await Promise.all(Array.from({ length: 50 }, (_, i) => audit.append("request", { request_id: `p_${i}` })));
    const seqs = (attacker.prepare("select seq from audit_log order by seq").all() as any[]).map((r) => r.seq);
    expect(seqs).toEqual(Array.from({ length: 60 }, (_, i) => i + 1));
    expect(await audit.verify()).toMatchObject({ ok: true, entries: 60 });
  });

  it("stays correct when a second process writes to the same log", async () => {
    const other = await createServices(config);
    try {
      await Promise.all([
        ...Array.from({ length: 20 }, (_, i) => audit.append("request", { request_id: `a_${i}` })),
        ...Array.from({ length: 20 }, (_, i) => other.audit.append("admin", { action: `b_${i}` })),
      ]);
      expect(await audit.verify()).toMatchObject({ ok: true, entries: 50 });
    } finally {
      await other.db.close();
    }
  });
});

describe("tampering is detected, with the exact entry number", () => {
  it("editing an entry's details", async () => {
    const row = attacker.prepare("select data from audit_log where seq = 4").get() as any;
    attacker.prepare("update audit_log set data = ? where seq = 4").run(row.data.replace("atelier", "someone-else"));
    const result = await audit.verify();
    expect(result).toMatchObject({ ok: false, brokenAt: 4, entries: 3 });
    expect((result as any).reason).toContain("changed after it was written");
  });

  it.each(["ts", "kind"])("editing an entry's %s", async (column) => {
    attacker.prepare(`update audit_log set ${column} = ? where seq = 7`).run(column === "ts" ? "2020-01-01T00:00:00.000Z" : "admin");
    expect(await audit.verify()).toMatchObject({ ok: false, brokenAt: 7 });
  });

  it("deleting an entry from the middle", async () => {
    attacker.prepare("delete from audit_log where seq = 5").run();
    const result = await audit.verify();
    expect(result).toMatchObject({ ok: false, brokenAt: 5, entries: 4 });
    expect((result as any).reason).toContain("missing");
  });

  it("deleting an entry and renumbering the rest to hide the gap", async () => {
    attacker.prepare("delete from audit_log where seq = 5").run();
    attacker.prepare("update audit_log set seq = seq - 1 where seq > 5").run();
    expect(await audit.verify()).toMatchObject({ ok: false, brokenAt: 5 });
  });

  it("deleting the first entry", async () => {
    attacker.prepare("delete from audit_log where seq = 1").run();
    expect(await audit.verify()).toMatchObject({ ok: false, brokenAt: 1 });
  });

  it("reordering two entries", async () => {
    attacker.prepare("update audit_log set seq = 100 where seq = 3").run();
    attacker.prepare("update audit_log set seq = 3 where seq = 6").run();
    attacker.prepare("update audit_log set seq = 6 where seq = 100").run();
    expect(await audit.verify()).toMatchObject({ ok: false, brokenAt: 3 });
  });

  it("editing an entry, then rebuilding every fingerprint after it without the key", async () => {
    const row = attacker.prepare("select data from audit_log where seq = 6").get() as any;
    attacker.prepare("update audit_log set data = ? where seq = 6").run(row.data.replace("forwarded", "blocked"));
    rebuildChainWithoutKey(6);
    const result = await audit.verify();
    expect(result).toMatchObject({ ok: false, brokenAt: 6, entries: 5 });
    expect((result as any).reason).toContain("invalid signature");
  });

  it("rebuilding the WHOLE log from scratch without the key", async () => {
    attacker.prepare("update audit_log set data = replace(data, 'atelier', 'nobody')").run();
    rebuildChainWithoutKey(1);
    expect(await audit.verify()).toMatchObject({ ok: false, brokenAt: 1 });
  });

  it("adding a forged entry at the end", async () => {
    const head = attacker.prepare("select seq, hash from audit_log order by seq desc limit 1").get() as any;
    const ts = new Date().toISOString();
    const data = '{"action":"key.create","actor":"admin"}';
    const hash = sha256Hex(entryDigestInput(head.seq + 1, ts, "admin", head.hash, data));
    attacker
      .prepare("insert into audit_log (seq, ts, kind, data, prev_hash, hash, hmac) values (?, ?, ?, ?, ?, ?, ?)")
      .run(head.seq + 1, ts, "admin", data, head.hash, hash, hmacHex(ATTACKER_KEY, hash));
    expect(await audit.verify()).toMatchObject({ ok: false, brokenAt: 11, entries: 10 });
  });

  it("copying a genuine signature onto a different entry", async () => {
    const genuine = attacker.prepare("select hmac from audit_log where seq = 2").get() as any;
    attacker.prepare("update audit_log set hmac = ? where seq = 8").run(genuine.hmac);
    expect(await audit.verify()).toMatchObject({ ok: false, brokenAt: 8 });
  });

  it("a log verified with the wrong key is reported broken from the first entry", async () => {
    const wrong = new AuditLog(services.db, "a-completely-different-audit-key-000000000");
    expect(await wrong.verify()).toMatchObject({ ok: false, brokenAt: 1 });
  });
});

describe("checkpoints catch what a chain alone cannot: entries cut off the end", () => {
  it("without a checkpoint, a shortened log still looks valid (this is why checkpoints exist)", async () => {
    attacker.prepare("delete from audit_log where seq > 7").run();
    expect(await audit.verify()).toMatchObject({ ok: true, entries: 7 });
  });

  it("with a checkpoint, cutting entries off the end is detected", async () => {
    await writeCheckpoint(audit, TEST_AUDIT_KEY, checkpointDir());
    attacker.prepare("delete from audit_log where seq > 7").run();
    const result = await verifyWithCheckpoints();
    expect(result).toMatchObject({ ok: false, brokenAt: 8, entries: 7 });
    expect((result as any).reason).toContain("deleted from the end");
  });

  it("with a checkpoint, deleting the whole log is detected", async () => {
    await writeCheckpoint(audit, TEST_AUDIT_KEY, checkpointDir());
    attacker.prepare("delete from audit_log").run();
    expect(await verifyWithCheckpoints()).toMatchObject({ ok: false, brokenAt: 1, entries: 0 });
  });

  it("an intact log passes against its checkpoint, and keeps passing as it grows", async () => {
    await writeCheckpoint(audit, TEST_AUDIT_KEY, checkpointDir());
    await audit.append("request", { request_id: "later" });
    expect(await verifyWithCheckpoints()).toMatchObject({ ok: true, entries: 11, checkpointsChecked: 1 });
  });

  it("a checkpoint is a small signed file with no personal data, named after the day", async () => {
    const file = await writeCheckpoint(audit, TEST_AUDIT_KEY, checkpointDir(), new Date("2026-11-16T10:00:00Z"));
    expect(file).toMatch(/checkpoint-2026-11-16\.json$/);
    const content = JSON.parse(await readFile(file, "utf8"));
    expect(Object.keys(content).sort()).toEqual(["created_at", "date", "hash", "hmac", "seq", "version"]);
    expect(content.seq).toBe(10);
  });

  it("a forged or edited checkpoint file is rejected", async () => {
    const file = await writeCheckpoint(audit, TEST_AUDIT_KEY, checkpointDir());
    const content = JSON.parse(await readFile(file, "utf8"));
    await writeFile(file, JSON.stringify({ ...content, seq: 7 })); // attacker lowers the count to match a shortened log
    const loaded = await loadCheckpoints(TEST_AUDIT_KEY, checkpointDir());
    expect(loaded.valid).toHaveLength(0);
    expect(loaded.invalid).toHaveLength(1);
  });
});

describe("export", () => {
  it("exports every entry as JSON", async () => {
    let out = "";
    const count = await exportAudit(audit, "json", (c) => void (out += c));
    const parsed = JSON.parse(out);
    expect(count).toBe(10);
    expect(parsed).toHaveLength(10);
    expect(parsed[0]).toMatchObject({ seq: 1, kind: "request", data: { request_id: "req_1", client_id: "atelier" } });
    expect(parsed[0].hmac).toMatch(/^[0-9a-f]{64}$/);
  });

  it("exports every entry as CSV with a header row", async () => {
    let out = "";
    await exportAudit(audit, "csv", (c) => void (out += c));
    const lines = out.trimEnd().split("\n");
    expect(lines).toHaveLength(11);
    expect(lines[0]).toMatch(/^seq,ts,kind,request_id,client_id,/);
    expect(lines[1]).toMatch(/^1,[^,]+,request,req_1,atelier,/);
  });

  it("stops spreadsheet formulas and handles quotes and commas", () => {
    expect(csvCell("=HYPERLINK(\"http://evil\")")).toBe("\"'=HYPERLINK(\"\"http://evil\"\")\"");
    expect(csvCell("+250788")).toBe("'+250788");
    expect(csvCell("-1")).toBe("'-1");
    expect(csvCell("@cmd")).toBe("'@cmd");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell(null)).toBe("");
    expect(csvCell({ a: 1 })).toBe('"{""a"":1}"');
  });
});

describe("the command-line tool", () => {
  async function cli(...args: string[]): Promise<{ code: number; output: string }> {
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void lines.push(a.join(" ")));
    try {
      const code = await run(args, config, services);
      return { code, output: lines.join("\n") };
    } finally {
      spy.mockRestore();
    }
  }

  it("`audit verify` says VALID, then names the broken entry after tampering", async () => {
    await cli("audit", "checkpoint");
    const ok = await cli("audit", "verify");
    expect(ok.code).toBe(0);
    expect(ok.output).toContain("VALID: 10 entries");
    expect(ok.output).toContain("1 checkpoint file");

    attacker.prepare("update audit_log set data = '{}' where seq = 9").run();
    const broken = await cli("audit", "verify");
    expect(broken.code).toBe(1);
    expect(broken.output).toContain("BROKEN at entry 9");
  });

  it("`client add` creates the client, a policy file and a key shown once; `key revoke` stops it", async () => {
    const { mkdir } = await import("node:fs/promises");
    await mkdir(config.policyDir, { recursive: true });
    const added = await cli("client", "add", "Atelier Studio");
    expect(added.code).toBe(0);
    expect(added.output).toContain("id: atelier-studio");
    const apiKey = added.output.match(/kg_[0-9a-f]{8}_[0-9a-f]{64}/)![0];

    expect(await services.clients.authenticate(apiKey)).toMatchObject({ clientId: "atelier-studio" });
    expect((await services.policies.load("atelier-studio")).policy.attachments.allowed).toBe(false);
    expect((await cli("policy", "check", "atelier-studio")).output).toContain("OK");

    // The key is never shown again.
    const listed = await cli("key", "list");
    expect(listed.output).not.toContain(apiKey.split("_")[2]);

    const keyId = apiKey.split("_")[1]!;
    expect((await cli("key", "revoke", keyId)).code).toBe(0);
    expect(await services.clients.authenticate(apiKey)).toBeNull();

    // All of it is in the audit log, attributed to the command-line tool.
    const actions: string[] = [];
    for await (const e of audit.entries()) if (e.kind === "admin") actions.push(`${e.data.action}:${e.data.actor}`);
    expect(actions).toEqual(["client.create:cli", "key.create:cli", "key.revoke:cli"]);
    expect(await audit.verify()).toMatchObject({ ok: true });
  });

  it("`policy check` explains a broken policy file", async () => {
    const { mkdir } = await import("node:fs/promises");
    await mkdir(config.policyDir, { recursive: true });
    await cli("client", "add", "Broken Co");
    await writeFile(services.policies.fileFor("broken-co"), "attachments:\n  alowed: true\n");
    const result = await cli("policy", "check", "broken-co");
    expect(result.code).toBe(1);
    expect(result.output).toContain("BLOCKED");
    expect(result.output).toContain("alowed");
  });
});
