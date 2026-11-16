/**
 * Daily signed checkpoint files.
 *
 * A checkpoint is a tiny file that says: "On this day the audit log had N
 * entries, and the fingerprint of entry N was X", signed with the audit key.
 *
 * COPY THESE FILES SOMEWHERE ELSE (another server, cloud storage, even
 * email). They are what lets you prove later that nobody deleted the last
 * entries of the log or replaced the whole log with a shorter one. A
 * checkpoint contains no personal data and no secrets, so it is safe to copy.
 */
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, hmacHex, safeEqualHex } from "../crypto.js";
import type { AuditLog } from "./log.js";

export interface Checkpoint {
  version: 1;
  /** The UTC day this checkpoint belongs to, e.g. "2026-11-16". */
  date: string;
  created_at: string;
  /** Number of the latest entry when the checkpoint was made. */
  seq: number;
  /** Hash of that entry. */
  hash: string;
  /** Signature over the fields above. */
  hmac: string;
}

function signedPart(c: Omit<Checkpoint, "hmac">): string {
  return canonicalJson({ version: c.version, date: c.date, created_at: c.created_at, seq: c.seq, hash: c.hash });
}

/** Write (or refresh) today's checkpoint file. Returns its path. */
export async function writeCheckpoint(audit: AuditLog, auditKey: string, dir: string, now = new Date()): Promise<string> {
  const head = await audit.head();
  const body: Omit<Checkpoint, "hmac"> = {
    version: 1,
    date: now.toISOString().slice(0, 10),
    created_at: now.toISOString(),
    seq: head.seq,
    hash: head.hash,
  };
  const checkpoint: Checkpoint = { ...body, hmac: hmacHex(auditKey, signedPart(body)) };

  await mkdir(dir, { recursive: true });
  const file = join(dir, `checkpoint-${body.date}.json`);
  // Write to a temporary name first, then rename: a crash can never leave half a file.
  const tmp = `${file}.tmp`;
  await writeFile(tmp, `${JSON.stringify(checkpoint, null, 2)}\n`, { mode: 0o640 });
  await rename(tmp, file);
  return file;
}

export interface LoadedCheckpoints {
  valid: Array<{ seq: number; hash: string; source: string }>;
  /** Files that could not be read or whose signature is wrong. */
  invalid: string[];
}

/** Read every checkpoint file in a folder and check each signature. */
export async function loadCheckpoints(auditKey: string, dir: string): Promise<LoadedCheckpoints> {
  const out: LoadedCheckpoints = { valid: [], invalid: [] };
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return out; // no folder yet means no checkpoints yet
  }
  for (const name of names.sort()) {
    if (!/^checkpoint-\d{4}-\d{2}-\d{2}\.json$/.test(name)) continue;
    try {
      const c = JSON.parse(await readFile(join(dir, name), "utf8")) as Checkpoint;
      const ok =
        c.version === 1 &&
        typeof c.seq === "number" &&
        typeof c.hash === "string" &&
        typeof c.hmac === "string" &&
        safeEqualHex(hmacHex(auditKey, signedPart(c)), c.hmac);
      if (ok) out.valid.push({ seq: c.seq, hash: c.hash, source: name });
      else out.invalid.push(name);
    } catch {
      out.invalid.push(name);
    }
  }
  return out;
}

/**
 * Keep the checkpoint fresh while the server runs: once at start, then every
 * hour. The file is named after the day, so the last write of each day is
 * that day's final checkpoint.
 */
export function startCheckpointTimer(
  audit: AuditLog,
  auditKey: string,
  dir: string,
  onError: (err: unknown) => void,
): () => void {
  const tick = () => {
    writeCheckpoint(audit, auditKey, dir).catch(onError);
  };
  tick();
  const timer = setInterval(tick, 60 * 60 * 1000);
  timer.unref();
  return () => clearInterval(timer);
}
