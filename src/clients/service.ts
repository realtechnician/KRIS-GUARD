/**
 * Clients and their API keys.
 *
 * A "client" is one customer of KRIS (for example the Atelier app). Each
 * client gets one or more KRIS Guard API keys. A key looks like:
 *
 *     kg_3f9a1c2e_5d0c...64 hex characters...
 *        │        └─ the secret part (256 bits of randomness)
 *        └────────── a short public id, so you can tell keys apart
 *
 * HOW KEYS ARE STORED
 *
 * The key itself is shown ONCE, when it is created, and never stored. The
 * database keeps only an HMAC of it, computed with a secret that lives in the
 * server's environment. Two consequences:
 *
 *  - Someone who steals the database cannot turn the stored value back into
 *    a working key.
 *  - Someone who can WRITE to the database cannot add a key of their own,
 *    because they cannot compute the right stored value without the secret.
 *
 * A slow password hash (like the one used for the admin login) is not needed
 * here: those exist to protect short, guessable human passwords. A key with
 * 256 random bits cannot be guessed however fast the hash is.
 */
import type { AuditLog } from "../audit/log.js";
import { deriveKey, hmacHex, randomHex } from "../crypto.js";
import type { Db } from "../db/connect.js";

export interface ClientRecord {
  id: string;
  name: string;
  created_at: string;
}

export interface KeyRecord {
  id: string;
  client_id: string;
  prefix: string;
  created_at: string;
  revoked_at: string | null;
}

export interface AuthenticatedClient {
  clientId: string;
  keyId: string;
}

/** Client ids are also file names (the policy file), so they are kept strictly simple. */
export const CLIENT_ID_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;

const KEY_RE = /^kg_[0-9a-f]{8}_[0-9a-f]{64}$/;

export class ClientError extends Error {}

export function slugify(name: string): string {
  return name
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/g, "");
}

export class ClientService {
  private readonly hashKey: Buffer;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditLog,
    serverSecret: string,
  ) {
    this.hashKey = deriveKey(serverSecret, "api-key-hash");
  }

  private hash(apiKey: string): string {
    return hmacHex(this.hashKey, apiKey);
  }

  /**
   * Who does this key belong to? Returns null for anything that is not a
   * current, un-revoked key. This is the ONLY way a request gets an identity.
   */
  async authenticate(apiKey: string | undefined): Promise<AuthenticatedClient | null> {
    if (!apiKey || !KEY_RE.test(apiKey)) return null;
    const row = await this.db.q
      .selectFrom("api_keys")
      .select(["id", "client_id", "revoked_at"])
      .where("key_hash", "=", this.hash(apiKey))
      .executeTakeFirst();
    if (!row || row.revoked_at !== null) return null;
    return { clientId: row.client_id, keyId: row.id };
  }

  async createClient(name: string, actor: string, requestedId?: string): Promise<ClientRecord> {
    const cleanName = name.trim();
    if (cleanName.length === 0 || cleanName.length > 100) {
      throw new ClientError("A client name must be between 1 and 100 characters.");
    }
    const id = requestedId ?? slugify(cleanName);
    if (!CLIENT_ID_RE.test(id)) {
      throw new ClientError(
        'A client id may only contain lower-case letters, digits and hyphens (for example "atelier").',
      );
    }
    const existing = await this.db.q.selectFrom("clients").select("id").where("id", "=", id).executeTakeFirst();
    if (existing) throw new ClientError(`A client with the id "${id}" already exists.`);

    const record: ClientRecord = { id, name: cleanName, created_at: new Date().toISOString() };
    await this.db.q.insertInto("clients").values(record).execute();
    await this.audit.append("admin", { action: "client.create", actor, client_id: id });
    return record;
  }

  /** Create a key. The returned `apiKey` is the only time the real key is ever available. */
  async createKey(clientId: string, actor: string): Promise<{ apiKey: string; record: KeyRecord }> {
    const client = await this.db.q.selectFrom("clients").select("id").where("id", "=", clientId).executeTakeFirst();
    if (!client) throw new ClientError(`There is no client with the id "${clientId}".`);

    const id = randomHex(4);
    const apiKey = `kg_${id}_${randomHex(32)}`;
    const record: KeyRecord = {
      id,
      client_id: clientId,
      prefix: `kg_${id}_…`,
      created_at: new Date().toISOString(),
      revoked_at: null,
    };
    await this.db.q
      .insertInto("api_keys")
      .values({ ...record, key_hash: this.hash(apiKey) })
      .execute();
    await this.audit.append("admin", { action: "key.create", actor, client_id: clientId, key_id: id });
    return { apiKey, record };
  }

  /** Revoke a key. It stops working immediately. Returns false if there was nothing to revoke. */
  async revokeKey(keyId: string, actor: string): Promise<boolean> {
    const row = await this.db.q
      .selectFrom("api_keys")
      .select(["id", "client_id", "revoked_at"])
      .where("id", "=", keyId)
      .executeTakeFirst();
    if (!row || row.revoked_at !== null) return false;
    await this.db.q
      .updateTable("api_keys")
      .set({ revoked_at: new Date().toISOString() })
      .where("id", "=", keyId)
      .execute();
    await this.audit.append("admin", { action: "key.revoke", actor, client_id: row.client_id, key_id: keyId });
    return true;
  }

  listClients(): Promise<ClientRecord[]> {
    return this.db.q.selectFrom("clients").selectAll().orderBy("id").execute();
  }

  listKeys(clientId?: string): Promise<KeyRecord[]> {
    let q = this.db.q
      .selectFrom("api_keys")
      .select(["id", "client_id", "prefix", "created_at", "revoked_at"])
      .orderBy("created_at");
    if (clientId !== undefined) q = q.where("client_id", "=", clientId);
    return q.execute();
  }
}
