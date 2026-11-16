#!/usr/bin/env node
/**
 * The command-line tool for administrators.
 *
 *   kris-guard client add "Atelier"        create a client, its policy file, and its first key
 *   kris-guard client list
 *   kris-guard key create <client-id>      issue another key
 *   kris-guard key list [client-id]
 *   kris-guard key revoke <key-id>         the key stops working immediately
 *   kris-guard policy init <client-id>     create a missing starter policy file
 *   kris-guard policy check <client-id>    explain what is wrong with a policy file
 *   kris-guard audit verify                is the audit log intact?
 *   kris-guard audit checkpoint            write today's signed checkpoint file now
 *   kris-guard audit export --format csv|json [--out FILE]
 *
 * It reads the same environment variables as the server. Everything it
 * changes is written to the audit log with the actor "cli".
 */
import { createWriteStream } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { finished } from "node:stream/promises";
import { parseArgs } from "node:util";
import { loadCheckpoints, writeCheckpoint } from "./audit/checkpoint.js";
import { exportAudit } from "./audit/export.js";
import { ClientError } from "./clients/service.js";
import { ConfigError, loadConfig, type Config } from "./config.js";
import { parsePolicy } from "./policy/policy.js";
import { createServices, type Services } from "./services.js";

const ACTOR = "cli";

const HELP = `KRIS Guard command-line tool

  client add <name> [--id <id>]     Create a client, a starter policy file and a first API key
  client list                       List clients
  key create <client-id>            Create another API key for a client
  key list [client-id]              List keys (never shows the keys themselves)
  key revoke <key-id>               Revoke a key
  policy init <client-id>           Create the starter policy file for a client if it is missing
  policy check <client-id>          Check a client's policy file and explain any mistake
  audit verify                      Check the audit log has not been tampered with
  audit checkpoint                  Write today's signed checkpoint file
  audit export --format csv|json [--out <file>]
`;

function printKey(apiKey: string): void {
  console.log("");
  console.log("  API key (shown ONLY this once; store it somewhere safe):");
  console.log("");
  console.log(`      ${apiKey}`);
  console.log("");
}

/** Returns the process exit code: 0 = fine, 1 = a problem. */
export async function run(argv: string[], config: Config, services: Services): Promise<number> {
  const { positionals, values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      id: { type: "string" },
      format: { type: "string" },
      out: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  const [group, action, arg] = positionals;
  const { clients, audit, policies } = services;

  if (values.help || !group) {
    console.log(HELP);
    return 0;
  }

  if (group === "client" && action === "add") {
    if (!arg) throw new ClientError('Give the client a name, for example: client add "Atelier"');
    await mkdir(config.policyDir, { recursive: true });
    const client = await clients.createClient(arg, ACTOR, values.id);
    console.log(`Created client "${client.name}" with id: ${client.id}`);
    try {
      const policy = await policies.writeStarter(client.id, client.name);
      console.log(policy.created ? `Policy file created: ${policy.file}` : `Policy file already existed: ${policy.file}`);
    } catch {
      // Usually a permissions problem on the policy folder. The client is
      // created but stays BLOCKED until a policy file exists (fail closed).
      console.log(`WARNING: could not write the policy file ${policies.fileFor(client.id)}`);
      console.log("  This client's requests are BLOCKED until that file exists.");
      console.log(`  Make the policy folder writable (see README, 'Troubleshooting'), then run: policy init ${client.id}`);
    }
    const key = await clients.createKey(client.id, ACTOR);
    printKey(key.apiKey);
    return 0;
  }

  if (group === "client" && action === "list") {
    const list = await clients.listClients();
    if (list.length === 0) console.log("No clients yet.");
    for (const c of list) console.log(`${c.id}\t${c.name}\tcreated ${c.created_at}`);
    return 0;
  }

  if (group === "key" && action === "create") {
    if (!arg) throw new ClientError("Give the client id, for example: key create atelier");
    const key = await clients.createKey(arg, ACTOR);
    console.log(`Created key ${key.record.id} for client ${arg}.`);
    printKey(key.apiKey);
    return 0;
  }

  if (group === "key" && action === "list") {
    const list = await clients.listKeys(arg);
    if (list.length === 0) console.log("No keys.");
    for (const k of list) {
      const state = k.revoked_at ? `REVOKED ${k.revoked_at}` : "active";
      console.log(`${k.id}\t${k.client_id}\t${k.prefix}\tcreated ${k.created_at}\t${state}`);
    }
    return 0;
  }

  if (group === "key" && action === "revoke") {
    if (!arg) throw new ClientError("Give the key id (see: key list), for example: key revoke 3f9a1c2e");
    const done = await clients.revokeKey(arg, ACTOR);
    console.log(done ? `Key ${arg} is revoked. It no longer works.` : `No active key with the id "${arg}".`);
    return done ? 0 : 1;
  }

  if (group === "policy" && action === "init") {
    if (!arg) throw new ClientError("Give the client id, for example: policy init atelier");
    const client = (await clients.listClients()).find((c) => c.id === arg);
    if (!client) throw new ClientError(`There is no client with the id "${arg}".`);
    await mkdir(config.policyDir, { recursive: true });
    const policy = await policies.writeStarter(client.id, client.name);
    console.log(policy.created ? `Policy file created: ${policy.file}` : `Policy file already exists (left unchanged): ${policy.file}`);
    return 0;
  }

  if (group === "policy" && action === "check") {
    if (!arg) throw new ClientError("Give the client id, for example: policy check atelier");
    const file = policies.fileFor(arg);
    try {
      const policy = parsePolicy(await readFile(file, "utf8"));
      console.log(`OK: ${file} is valid.`);
      console.log(`  attachments allowed: ${policy.attachments.allowed}`);
      console.log(`  names to hide: ${policy.personal_data.names.length}`);
      console.log(`  placeholders: ${policy.personal_data.placeholders}`);
      return 0;
    } catch (err) {
      console.log(`PROBLEM: ${file} cannot be used. This client's requests are being BLOCKED.`);
      console.log((err as Error).message);
      return 1;
    }
  }

  if (group === "audit" && action === "verify") {
    const checkpoints = await loadCheckpoints(config.auditKey, config.checkpointDir);
    for (const name of checkpoints.invalid) {
      console.log(`WARNING: checkpoint file ${name} is unreadable or its signature is wrong. It was ignored.`);
    }
    const result = await audit.verify(checkpoints.valid);
    if (result.ok) {
      console.log(`VALID: ${result.entries} entries, none changed, removed or reordered.`);
      console.log(`  Checked against ${result.checkpointsChecked} checkpoint file(s) in ${config.checkpointDir}.`);
      if (result.checkpointsChecked === 0) {
        console.log("  NOTE: with no checkpoint files, entries deleted from the END of the log cannot be detected.");
      }
      return checkpoints.invalid.length === 0 ? 0 : 1;
    }
    console.log(`BROKEN at entry ${result.brokenAt}.`);
    console.log(`  ${result.reason}`);
    console.log(`  Entries before number ${result.brokenAt} (${result.entries} of them) are intact.`);
    return 1;
  }

  if (group === "audit" && action === "checkpoint") {
    const file = await writeCheckpoint(audit, config.auditKey, config.checkpointDir);
    console.log(`Checkpoint written: ${file}`);
    console.log("Copy this file somewhere off this server.");
    return 0;
  }

  if (group === "audit" && action === "export") {
    const format = values.format;
    if (format !== "csv" && format !== "json") throw new ClientError("Choose a format: --format csv  or  --format json");
    if (values.out) {
      const stream = createWriteStream(values.out, { mode: 0o640 });
      const count = await exportAudit(audit, format, (chunk) => {
        stream.write(chunk);
      });
      stream.end();
      await finished(stream);
      console.log(`Exported ${count} entries to ${values.out}`);
    } else {
      await exportAudit(audit, format, (chunk) => {
        process.stdout.write(chunk);
      });
    }
    return 0;
  }

  console.log(HELP);
  return 1;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(HELP); // help works even before the settings are filled in
    return;
  }
  let config: Config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }
  const services = await createServices(config);
  let code = 1;
  try {
    code = await run(process.argv.slice(2), config, services);
  } catch (err) {
    if (err instanceof ClientError) console.error(err.message);
    else throw err;
  } finally {
    await services.db.close();
  }
  process.exit(code);
}

// Only run when started directly (not when a test imports this file).
const startedDirectly = process.argv[1] !== undefined && /cli\.(js|ts)$/.test(process.argv[1]);
if (startedDirectly) {
  main().catch((err: unknown) => {
    console.error("Command failed:", err instanceof Error ? err.name : "error");
    process.exit(1);
  });
}
