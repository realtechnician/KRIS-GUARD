/**
 * The program's starting point: `node dist/index.js`.
 *
 * Reads the settings, opens the database, starts the web server, and keeps
 * the daily audit checkpoint up to date.
 */
import { mkdir } from "node:fs/promises";
import { startCheckpointTimer, writeCheckpoint } from "./audit/checkpoint.js";
import { ConfigError, loadConfig } from "./config.js";
import { describeErrorSafely } from "./errors.js";
import { buildApp } from "./server.js";
import { createServices } from "./services.js";

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }

  await mkdir(config.policyDir, { recursive: true });
  const services = await createServices(config);
  const app = buildApp({ config, ...services });

  if (!config.anthropicApiKey) app.log.warn("ANTHROPIC_API_KEY is not set: /v1/messages will refuse requests");
  if (!config.openaiApiKey) app.log.warn("OPENAI_API_KEY is not set: /v1/chat/completions will refuse requests");

  await services.audit.append("system", { action: "server.start" });
  const stopCheckpoints = startCheckpointTimer(services.audit, config.auditKey, config.checkpointDir, (err) =>
    app.log.error({ err: describeErrorSafely(err) }, "could not write audit checkpoint"),
  );

  await app.listen({ host: config.host, port: config.port });

  let stopping = false;
  const shutdown = async (signal: string) => {
    if (stopping) return;
    stopping = true;
    app.log.info({ signal }, "shutting down");
    stopCheckpoints();
    try {
      await app.close(); // waits for requests in progress
      await services.audit.append("system", { action: "server.stop" });
      await writeCheckpoint(services.audit, config.auditKey, config.checkpointDir);
      await services.db.close();
    } catch (err) {
      app.log.error({ err: describeErrorSafely(err) }, "error during shutdown");
    }
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err: unknown) => {
  console.error("KRIS Guard failed to start:", describeErrorSafely(err));
  process.exit(1);
});
