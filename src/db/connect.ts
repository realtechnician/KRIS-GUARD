/**
 * Opens the database and creates the tables if they do not exist yet.
 *
 * We use Kysely, a "query builder": we write queries once in TypeScript and it
 * produces the right SQL for either SQLite (the default, a single file) or
 * PostgreSQL (optional, for bigger setups).
 */
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import { Kysely, PostgresDialect, SqliteDialect, sql } from "kysely";
import pg from "pg";
import type { Database } from "./schema.js";

export type DbKind = "sqlite" | "postgres";

export interface Db {
  kind: DbKind;
  q: Kysely<Database>;
  close(): Promise<void>;
}

export async function openDatabase(databaseUrl: string): Promise<Db> {
  if (databaseUrl.startsWith("postgres://") || databaseUrl.startsWith("postgresql://")) {
    // PostgreSQL returns big integers as text by default; our sequence numbers
    // are far below the limit where that matters, so read them as numbers.
    pg.types.setTypeParser(20, (v) => Number(v));
    const pool = new pg.Pool({ connectionString: databaseUrl, max: 10 });
    // If PostgreSQL restarts, idle connections break. Without this handler that
    // would crash the whole server; with it, the pool simply reconnects.
    pool.on("error", () => undefined);
    const q = new Kysely<Database>({ dialect: new PostgresDialect({ pool }) });
    const db: Db = { kind: "postgres", q, close: () => q.destroy() };
    await migrate(db);
    return db;
  }

  if (databaseUrl.startsWith("sqlite:")) {
    const file = databaseUrl.slice("sqlite:".length);
    if (file !== ":memory:") mkdirSync(dirname(resolve(file)), { recursive: true });
    const raw = new BetterSqlite3(file);
    // WAL lets readers and a writer work at the same time.
    raw.pragma("journal_mode = WAL");
    // FULL means "really on disk before we say it's saved". The audit log is
    // only worth having if entries survive a power cut.
    raw.pragma("synchronous = FULL");
    raw.pragma("busy_timeout = 5000");
    raw.pragma("foreign_keys = ON");
    const q = new Kysely<Database>({ dialect: new SqliteDialect({ database: raw }) });
    const db: Db = { kind: "sqlite", q, close: () => q.destroy() };
    await migrate(db);
    return db;
  }

  throw new Error('DATABASE_URL must start with "sqlite:" or "postgres://"');
}

async function migrate(db: Db): Promise<void> {
  const seqType = db.kind === "postgres" ? sql`bigint` : sql`integer`;

  await sql`
    create table if not exists clients (
      id text primary key,
      name text not null,
      created_at text not null
    )
  `.execute(db.q);

  await sql`
    create table if not exists api_keys (
      id text primary key,
      client_id text not null references clients(id),
      key_hash text not null unique,
      prefix text not null,
      created_at text not null,
      revoked_at text
    )
  `.execute(db.q);

  await sql`
    create table if not exists audit_log (
      seq ${seqType} primary key,
      ts text not null,
      kind text not null,
      data text not null,
      prev_hash text not null,
      hash text not null,
      hmac text not null
    )
  `.execute(db.q);
}
