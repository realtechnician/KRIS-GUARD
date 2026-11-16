/**
 * The shape of the database tables, as TypeScript types.
 *
 * NOTE what is NOT here: no prompts, no answers, no personal data, no real
 * API keys. The database only ever holds key *hashes* and audit *metadata*.
 */
export interface ClientsTable {
  /** Short id such as "atelier". Also the name of the client's policy file. */
  id: string;
  name: string;
  created_at: string;
}

export interface ApiKeysTable {
  id: string;
  client_id: string;
  /** HMAC of the key, made with a server secret. Not reversible. */
  key_hash: string;
  /** First characters of the key, so a human can tell keys apart. */
  prefix: string;
  created_at: string;
  revoked_at: string | null;
}

export interface AuditLogTable {
  /** 1, 2, 3, ... with no gaps. A gap means something was deleted. */
  seq: number;
  ts: string;
  kind: string;
  /** The entry's details as stable JSON text. Never personal data. */
  data: string;
  /** Hash of the previous entry: this is the "chain". */
  prev_hash: string;
  /** Hash of this entry (which covers prev_hash). */
  hash: string;
  /** Signature of this entry, made with the audit secret key. */
  hmac: string;
}

export interface Database {
  clients: ClientsTable;
  api_keys: ApiKeysTable;
  audit_log: AuditLogTable;
}
