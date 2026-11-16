/**
 * Errors that are safe to show to a caller.
 *
 * RULE: a GuardError message must NEVER contain personal data, raw request
 * text, or internal details (file paths, SQL, stack traces). It may say what
 * kind of thing was refused and where in the request it was (for example
 * "messages[2].content[0]"), because positions are not personal data.
 *
 * Anything that is NOT a GuardError is treated as an unexpected failure and is
 * turned into a generic "blocked" answer (this is what "fail closed" means).
 */
export type GuardErrorCode =
  | "unauthorized"
  | "invalid_request"
  | "request_too_large"
  | "policy_unavailable"
  | "attachment_blocked"
  | "unmaskable_personal_data"
  | "check_failed"
  | "audit_unavailable"
  | "provider_not_configured"
  | "provider_unreachable"
  | "provider_timeout";

const STATUS: Record<GuardErrorCode, number> = {
  unauthorized: 401,
  invalid_request: 400,
  request_too_large: 413,
  policy_unavailable: 403,
  attachment_blocked: 403,
  unmaskable_personal_data: 403,
  check_failed: 500,
  audit_unavailable: 500,
  provider_not_configured: 503,
  provider_unreachable: 502,
  provider_timeout: 504,
};

export class GuardError extends Error {
  readonly code: GuardErrorCode;
  readonly status: number;

  constructor(code: GuardErrorCode, safeMessage: string) {
    super(safeMessage);
    this.name = "GuardError";
    this.code = code;
    this.status = STATUS[code];
  }
}

/** The one message used whenever something unexpected goes wrong. */
export function failClosedError(): GuardError {
  return new GuardError(
    "check_failed",
    "KRIS Guard could not complete its safety checks, so the request was blocked. Nothing was sent to the AI provider.",
  );
}

/**
 * Describe an unknown error for the server log WITHOUT its message.
 * Error messages from JSON parsers and libraries can quote pieces of the
 * input, and the input may contain personal data. We keep only the error's
 * type, its code, and where in our code it happened.
 */
export function describeErrorSafely(err: unknown): Record<string, unknown> {
  if (err instanceof GuardError) {
    return { name: err.name, code: err.code };
  }
  if (err instanceof Error) {
    const frames = (err.stack ?? "")
      .split("\n")
      .filter((line) => line.trimStart().startsWith("at "))
      .slice(0, 6)
      .map((line) => line.trim());
    const code = (err as { code?: unknown }).code;
    return {
      name: err.name,
      code: typeof code === "string" || typeof code === "number" ? code : undefined,
      frames,
    };
  }
  return { name: "NonError" };
}
