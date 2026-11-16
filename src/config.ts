/**
 * Reads settings from environment variables.
 *
 * Secrets live ONLY here (in memory, read from the environment). They are
 * never written to the database, a log, or a response.
 *
 * KRIS Guard refuses to start if a secret is missing or too short. A gateway
 * that quietly runs with a weak signing key would give a false sense of safety.
 */
import { z } from "zod";

const secret = (name: string) =>
  z
    .string({ error: `${name} is required` })
    .min(32, `${name} must be at least 32 characters. Generate one with: openssl rand -hex 32`);

const EnvSchema = z.object({
  /** Signs every audit-log entry. If this leaks, audit entries can be forged. */
  KRIS_GUARD_AUDIT_KEY: secret("KRIS_GUARD_AUDIT_KEY"),
  /** Protects stored client keys (and, later, admin sessions). */
  KRIS_GUARD_SECRET: secret("KRIS_GUARD_SECRET"),

  /** KRIS's own provider keys. A provider with no key is simply unavailable. */
  ANTHROPIC_API_KEY: z.string().min(1).optional(),
  OPENAI_API_KEY: z.string().min(1).optional(),

  /** Where requests are forwarded. Fixed here; a request can never change it. */
  ANTHROPIC_BASE_URL: z.url().default("https://api.anthropic.com"),
  OPENAI_BASE_URL: z.url().default("https://api.openai.com"),

  /** "sqlite:<path>" or "postgres://user:pass@host/db". */
  DATABASE_URL: z.string().default("sqlite:./data/kris-guard.db"),

  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),

  POLICY_DIR: z.string().default("./config/policies"),
  CHECKPOINT_DIR: z.string().default("./data/checkpoints"),

  /** Largest request body accepted, in bytes (default 5 MB). */
  MAX_BODY_BYTES: z.coerce.number().int().min(1024).default(5 * 1024 * 1024),
  /** How long to wait for the provider to start answering, in milliseconds. */
  UPSTREAM_TIMEOUT_MS: z.coerce.number().int().min(1000).default(120_000),

  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "silent"]).default("info"),
});

export interface Config {
  auditKey: string;
  serverSecret: string;
  anthropicApiKey: string | undefined;
  openaiApiKey: string | undefined;
  anthropicBaseUrl: string;
  openaiBaseUrl: string;
  databaseUrl: string;
  host: string;
  port: number;
  policyDir: string;
  checkpointDir: string;
  maxBodyBytes: number;
  upstreamTimeoutMs: number;
  logLevel: "fatal" | "error" | "warn" | "info" | "debug" | "silent";
}

export class ConfigError extends Error {}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  // Treat empty strings as "not set" so `FOO=` in a .env file behaves sensibly.
  const cleaned: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (typeof v === "string" && v.trim() !== "") cleaned[k] = v.trim();
  }

  const parsed = EnvSchema.safeParse(cleaned);
  if (!parsed.success) {
    // Only variable NAMES and rules are printed, never values.
    const problems = parsed.error.issues.map((i) => `  - ${i.message}`).join("\n");
    throw new ConfigError(`KRIS Guard cannot start. Fix these settings:\n${problems}`);
  }
  const e = parsed.data;

  if (e.KRIS_GUARD_AUDIT_KEY === e.KRIS_GUARD_SECRET) {
    throw new ConfigError(
      "KRIS Guard cannot start. KRIS_GUARD_AUDIT_KEY and KRIS_GUARD_SECRET must be different values.",
    );
  }

  return {
    auditKey: e.KRIS_GUARD_AUDIT_KEY,
    serverSecret: e.KRIS_GUARD_SECRET,
    anthropicApiKey: e.ANTHROPIC_API_KEY,
    openaiApiKey: e.OPENAI_API_KEY,
    anthropicBaseUrl: e.ANTHROPIC_BASE_URL.replace(/\/+$/, ""),
    openaiBaseUrl: e.OPENAI_BASE_URL.replace(/\/+$/, ""),
    databaseUrl: e.DATABASE_URL,
    host: e.HOST,
    port: e.PORT,
    policyDir: e.POLICY_DIR,
    checkpointDir: e.CHECKPOINT_DIR,
    maxBodyBytes: e.MAX_BODY_BYTES,
    upstreamTimeoutMs: e.UPSTREAM_TIMEOUT_MS,
    logLevel: e.LOG_LEVEL,
  };
}
