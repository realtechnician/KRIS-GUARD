/**
 * Client policies: one YAML file per client, in the policy folder.
 *
 *     config/policies/atelier.yaml
 *
 * The file name is the client id. A request is ALWAYS judged by the policy of
 * the client its key belongs to; nothing in the request can pick a different
 * file.
 *
 * FAIL CLOSED: if a client's policy file is missing, unreadable, or contains
 * anything this version does not understand (including a misspelt setting),
 * that client's requests are blocked until it is fixed. A half-understood
 * policy is more dangerous than no service.
 *
 * Phase 1 understands the settings below. Phase 2 adds models, spending
 * limits, size limits, blocked topics and more.
 */
import { readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { CLIENT_ID_RE } from "../clients/service.js";
import { GuardError } from "../errors.js";
import { MAX_NAMES, createNameDetector } from "../pii/detectors/names.js";
import type { Detector } from "../pii/types.js";

const PolicySchema = z.strictObject({
  attachments: z
    .strictObject({
      /** May requests contain images, files or PDFs? They cannot be checked for personal data. */
      allowed: z.boolean().default(false),
    })
    .default({ allowed: false }),

  personal_data: z
    .strictObject({
      /** Names to hide. KRIS Guard does not recognise names by itself. */
      names: z.array(z.string().min(1).max(200)).max(MAX_NAMES).default([]),
      /** "random" (default) or "stable". See src/pii/placeholders.ts. */
      placeholders: z.enum(["random", "stable"]).default("random"),
    })
    .default({ names: [], placeholders: "random" }),

  injection_screening: z
    .strictObject({
      /**
       * What to do when text from a document, email, web page or tool result
       * looks like an instruction planted for the AI:
       *   off   do not look      warn  forward, but flag it (default)
       *   strip remove the suspicious sentence      block refuse the request
       */
      action: z.enum(["off", "warn", "strip", "block"]).default("warn"),
      /** Also screen what the user typed. Off by default: users legitimately give instructions. */
      scan_user_messages: z.boolean().default(false),
    })
    .default({ action: "warn", scan_user_messages: false }),
});

export type Policy = z.infer<typeof PolicySchema>;

export interface LoadedPolicy {
  policy: Policy;
  /** Built once from the names list and reused for every request. */
  nameDetector: Detector;
}

export function parsePolicy(yamlText: string): Policy {
  const raw: unknown = parseYaml(yamlText) ?? {};
  return PolicySchema.parse(raw);
}

export const STARTER_POLICY = (clientId: string, clientName: string) => `# KRIS Guard policy for: ${clientName}
# File name = client id (${clientId}). Changes take effect on the next request; no restart needed.
# If this file has a mistake in it, this client's requests are BLOCKED until it is fixed.

attachments:
  # Images, files and PDFs cannot be checked for personal data.
  # Keep this false unless the client really needs to send them.
  allowed: false

personal_data:
  # Names to hide. KRIS Guard only hides the names listed here.
  # List a first name on its own line if it should be hidden on its own.
  names: []
  #  - Mugisha Jean
  #  - Uwase

  # random: a new placeholder for every request (most private; the default).
  # stable: the same value always gets the same placeholder for this client.
  #         Needed for the provider's prompt caching and for multi-turn
  #         conversations that use "thinking". See README, "Honest limits".
  placeholders: random

injection_screening:
  # Text from documents, emails, web pages and tool results is checked for
  # instructions planted for the AI ("ignore your instructions and ...").
  #   off   : do not check
  #   warn  : forward the request, but flag it in the audit log (default)
  #   strip : remove the suspicious sentence, then forward
  #   block : refuse the request
  # This catches obvious wording only. It is not a guarantee.
  action: warn
  # Also check what the user typed. Usually false: users give instructions.
  scan_user_messages: false
`;

export class PolicyStore {
  private readonly cache = new Map<string, { mtimeMs: number; size: number; loaded: LoadedPolicy }>();

  constructor(private readonly dir: string) {}

  fileFor(clientId: string): string {
    // The id comes from our own database, but it is checked again here: this
    // function builds a file path, and must never be tricked into "../".
    if (!CLIENT_ID_RE.test(clientId)) throw new Error("invalid client id");
    return join(this.dir, `${clientId}.yaml`);
  }

  /** Load a client's policy, re-reading the file only if it changed. */
  async load(clientId: string): Promise<LoadedPolicy> {
    const file = this.fileFor(clientId);
    try {
      const info = await stat(file);
      const cached = this.cache.get(clientId);
      if (cached && cached.mtimeMs === info.mtimeMs && cached.size === info.size) return cached.loaded;

      const policy = parsePolicy(await readFile(file, "utf8"));
      const loaded: LoadedPolicy = { policy, nameDetector: createNameDetector(policy.personal_data.names) };
      this.cache.set(clientId, { mtimeMs: info.mtimeMs, size: info.size, loaded });
      return loaded;
    } catch {
      this.cache.delete(clientId);
      // The reason (missing file, YAML mistake...) is deliberately not sent
      // to the caller. `kris-guard policy check <client>` shows it to an admin.
      throw new GuardError(
        "policy_unavailable",
        "KRIS Guard has no valid policy for this client, so the request was blocked. Ask the KRIS administrator to check the client's policy file.",
      );
    }
  }

  /** Create the starter policy file for a new client. Does not overwrite an existing file. */
  async writeStarter(clientId: string, clientName: string): Promise<{ file: string; created: boolean }> {
    const file = this.fileFor(clientId);
    try {
      await writeFile(file, STARTER_POLICY(clientId, clientName), { flag: "wx", mode: 0o640 });
      return { file, created: true };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") return { file, created: false };
      throw err;
    }
  }
}
