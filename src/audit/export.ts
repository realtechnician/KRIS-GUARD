/**
 * Export the audit log as CSV (opens in Excel) or JSON.
 */
import type { AuditEntry, AuditLog } from "./log.js";

/** Columns pulled out of each entry's details. Everything is also kept in the last "data" column. */
const DATA_COLUMNS = [
  "request_id",
  "client_id",
  "key_id",
  "user_label",
  "api",
  "model",
  "stream",
  "decision",
  "reason",
  "pii_hidden",
  "injection",
  "attachments",
  "status",
  "input_tokens",
  "output_tokens",
  "cost_usd",
  "actor",
  "action",
] as const;

const HEADER = ["seq", "ts", "kind", ...DATA_COLUMNS, "data", "prev_hash", "hash", "hmac"];

/**
 * Make one CSV cell.
 *
 * Besides the usual quoting, a cell that starts with = + - or @ gets a
 * leading apostrophe. Spreadsheet programs treat such cells as FORMULAS, and
 * a client-chosen value (like a user label) must not be able to run one when
 * you open the export.
 */
export function csvCell(value: unknown): string {
  let s: string;
  if (value === undefined || value === null) s = "";
  else if (typeof value === "object") s = JSON.stringify(value);
  else s = String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function csvRow(e: AuditEntry): string {
  const cells: unknown[] = [e.seq, e.ts, e.kind];
  for (const col of DATA_COLUMNS) cells.push(e.data[col]);
  cells.push(e.data, e.prev_hash, e.hash, e.hmac);
  return cells.map(csvCell).join(",");
}

/** Write the whole log to `write`, piece by piece. */
export async function exportAudit(
  audit: AuditLog,
  format: "csv" | "json",
  write: (chunk: string) => void | Promise<void>,
): Promise<number> {
  let count = 0;
  if (format === "csv") {
    await write(`${HEADER.join(",")}\n`);
    for await (const e of audit.entries()) {
      await write(`${csvRow(e)}\n`);
      count++;
    }
    return count;
  }
  await write("[\n");
  for await (const e of audit.entries()) {
    await write(`${count === 0 ? "" : ",\n"}  ${JSON.stringify(e)}`);
    count++;
  }
  await write("\n]\n");
  return count;
}
