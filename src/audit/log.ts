/**
 * The audit log: a record of what happened that cannot be changed quietly.
 *
 * HOW IT IS PROTECTED
 *
 * Think of a paper ledger where every line also contains a fingerprint of the
 * line above it, and is then stamped with a seal only KRIS owns.
 *
 *   1. CHAIN. Each entry stores the hash (fingerprint) of the previous entry.
 *      Change, remove or swap any entry and every fingerprint after it stops
 *      matching.
 *
 *   2. SIGNATURE. Each entry is also signed (HMAC) with a secret key that
 *      lives only in the server's environment, never in the database. Someone
 *      with the database could recompute all the fingerprints after an edit,
 *      but cannot produce the signatures without the key.
 *
 *   3. NUMBERING. Entries are numbered 1, 2, 3... A gap is a deletion.
 *
 *   4. CHECKPOINTS (see checkpoint.ts). The one thing a chain cannot show by
 *      itself is entries removed from the END. A signed checkpoint file,
 *      copied off the server, records "there were N entries and the last
 *      fingerprint was X".
 *
 * WHAT GOES IN: who, when, which model, how many tokens, what kinds of data
 * were hidden, what was decided. NEVER the personal data or the prompt.
 */
import { canonicalJson, hmacHex, safeEqualHex, sha256Hex } from "../crypto.js";
import type { Db } from "../db/connect.js";

/** The "previous hash" of the very first entry. */
export const GENESIS_HASH = "0".repeat(64);

export type AuditKind = "request" | "response" | "admin" | "system";

export interface AuditEntry {
  seq: number;
  ts: string;
  kind: string;
  data: Record<string, unknown>;
  prev_hash: string;
  hash: string;
  hmac: string;
}

export type VerifyResult =
  | { ok: true; entries: number; headHash: string; checkpointsChecked: number }
  | { ok: false; entries: number; brokenAt: number; reason: string };

/** The exact text that is hashed for one entry. Field order is fixed. */
export function entryDigestInput(seq: number, ts: string, kind: string, prevHash: string, dataJson: string): string {
  return `${seq}\n${ts}\n${kind}\n${prevHash}\n${dataJson}`;
}

const PAGE = 1000;

export class AuditLog {
  /** Appends are done one at a time so two requests cannot claim the same number. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly db: Db,
    private readonly auditKey: string,
  ) {}

  /** Add one entry to the end of the log. */
  append(kind: AuditKind, data: Record<string, unknown>): Promise<AuditEntry> {
    const run = this.queue.then(
      () => this.appendNow(kind, data),
      () => this.appendNow(kind, data),
    );
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async appendNow(kind: AuditKind, data: Record<string, unknown>): Promise<AuditEntry> {
    const dataJson = canonicalJson(data);
    // Another process (for example the command-line tool) may add an entry at
    // the same moment. The entry number is the table's unique key, so the
    // database rejects a duplicate; we then simply read the new end and retry.
    for (let attempt = 0; ; attempt++) {
      const head = await this.head();
      const seq = head.seq + 1;
      const ts = new Date().toISOString();
      const hash = sha256Hex(entryDigestInput(seq, ts, kind, head.hash, dataJson));
      const hmac = hmacHex(this.auditKey, hash);
      try {
        await this.db.q
          .insertInto("audit_log")
          .values({ seq, ts, kind, data: dataJson, prev_hash: head.hash, hash, hmac })
          .execute();
        return { seq, ts, kind, data, prev_hash: head.hash, hash, hmac };
      } catch (err) {
        if (attempt >= 5) throw err;
      }
    }
  }

  /** The number and hash of the latest entry (0 and the genesis hash if the log is empty). */
  async head(): Promise<{ seq: number; hash: string }> {
    const row = await this.db.q
      .selectFrom("audit_log")
      .select(["seq", "hash"])
      .orderBy("seq", "desc")
      .limit(1)
      .executeTakeFirst();
    return row ? { seq: Number(row.seq), hash: row.hash } : { seq: 0, hash: GENESIS_HASH };
  }

  /** Read entries in order, a page at a time, so a huge log does not fill memory. */
  async *entries(): AsyncGenerator<AuditEntry> {
    let after = 0;
    for (;;) {
      const rows = await this.db.q
        .selectFrom("audit_log")
        .selectAll()
        .where("seq", ">", after)
        .orderBy("seq", "asc")
        .limit(PAGE)
        .execute();
      if (rows.length === 0) return;
      for (const r of rows) {
        let data: Record<string, unknown>;
        try {
          data = JSON.parse(r.data) as Record<string, unknown>;
        } catch {
          data = {};
        }
        yield { seq: Number(r.seq), ts: r.ts, kind: r.kind, data, prev_hash: r.prev_hash, hash: r.hash, hmac: r.hmac };
      }
      after = Number(rows[rows.length - 1]!.seq);
    }
  }

  /**
   * Check the whole log. Returns either "valid", or the number of the first
   * entry where something is wrong and what kind of problem it is.
   *
   * @param checkpoints signed checkpoints to compare against (see checkpoint.ts)
   */
  async verify(checkpoints: Array<{ seq: number; hash: string; source: string }> = []): Promise<VerifyResult> {
    let expectedSeq = 1;
    let prevHash = GENESIS_HASH;
    let count = 0;
    const wanted = new Map<number, { hash: string; source: string }>();
    for (const c of checkpoints) wanted.set(c.seq, { hash: c.hash, source: c.source });

    let after = 0;
    for (;;) {
      const rows = await this.db.q
        .selectFrom("audit_log")
        .selectAll()
        .where("seq", ">", after)
        .orderBy("seq", "asc")
        .limit(PAGE)
        .execute();
      if (rows.length === 0) break;

      for (const r of rows) {
        const seq = Number(r.seq);
        if (seq !== expectedSeq) {
          return {
            ok: false,
            entries: count,
            brokenAt: expectedSeq,
            reason: `Entry ${expectedSeq} is missing (the next entry found is number ${seq}). One or more entries were deleted.`,
          };
        }
        if (r.prev_hash !== prevHash) {
          return {
            ok: false,
            entries: count,
            brokenAt: seq,
            reason: `Entry ${seq} does not link to entry ${seq - 1}. An entry was changed, removed or put in a different order.`,
          };
        }
        const hash = sha256Hex(entryDigestInput(seq, r.ts, r.kind, r.prev_hash, r.data));
        if (hash !== r.hash) {
          return {
            ok: false,
            entries: count,
            brokenAt: seq,
            reason: `Entry ${seq} was changed after it was written (its contents no longer match its fingerprint).`,
          };
        }
        if (!safeEqualHex(hmacHex(this.auditKey, hash), r.hmac)) {
          return {
            ok: false,
            entries: count,
            brokenAt: seq,
            reason: `Entry ${seq} has an invalid signature. It was written or rebuilt without the audit secret key.`,
          };
        }
        const cp = wanted.get(seq);
        if (cp && cp.hash !== hash) {
          return {
            ok: false,
            entries: count,
            brokenAt: seq,
            reason: `Entry ${seq} does not match the checkpoint "${cp.source}". The log was rewritten after that checkpoint was made.`,
          };
        }
        prevHash = hash;
        expectedSeq = seq + 1;
        count++;
      }
      after = Number(rows[rows.length - 1]!.seq);
    }

    // A checkpoint that points beyond the end of the log means the end was cut off.
    const missing = [...wanted.entries()].filter(([seq]) => seq > count).sort((a, b) => a[0] - b[0])[0];
    if (missing) {
      return {
        ok: false,
        entries: count,
        brokenAt: count + 1,
        reason: `The checkpoint "${missing[1].source}" says the log had at least ${missing[0]} entries, but only ${count} exist. Entries were deleted from the end.`,
      };
    }

    return { ok: true, entries: count, headHash: prevHash, checkpointsChecked: checkpoints.length };
  }
}
