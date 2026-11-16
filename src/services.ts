/**
 * Creates the long-lived objects (database, audit log, clients, policies)
 * from the configuration. Shared by the server (index.ts) and the
 * command-line tool (cli.ts) so both always work the same way.
 */
import { AuditLog } from "./audit/log.js";
import { ClientService } from "./clients/service.js";
import type { Config } from "./config.js";
import { openDatabase, type Db } from "./db/connect.js";
import { PolicyStore } from "./policy/policy.js";

export interface Services {
  db: Db;
  audit: AuditLog;
  clients: ClientService;
  policies: PolicyStore;
}

export async function createServices(config: Config): Promise<Services> {
  const db = await openDatabase(config.databaseUrl);
  const audit = new AuditLog(db, config.auditKey);
  const clients = new ClientService(db, audit, config.serverSecret);
  const policies = new PolicyStore(config.policyDir);
  return { db, audit, clients, policies };
}
