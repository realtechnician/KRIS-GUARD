# KRIS Guard: Progress

| Step | Status |
|---|---|
| Step 0: threat model and plan | Done |
| **Phase 1: core proxy, personal-data protection, audit log** | **Done, waiting for your OK** |
| Phase 2: client policies, planted-instruction screening, cost, rate limits | **Partly done**: item 9 (screening and the answer scan) is built and tested. Items 7, 8 and 10 are not started. |
| Phase 3: admin page, `/health` report, LEARN.md | Not started |

---

## Phase 1

### What was asked, and where it is

| # | Requirement | Where | Status |
|---|---|---|---|
| 1 | `/v1/messages` and `/v1/chat/completions`, with streaming | `src/proxy/` | Done |
| 1 | Forward with KRIS's provider keys from environment variables | `src/config.ts`, `src/proxy/handler.ts` | Done |
| 1 | Per-client keys, stored hashed, revocable | `src/clients/service.ts` | Done |
| 2 | Personal data protection on every text field (system, messages, tool definitions, tool calls, tool results) | `src/pii/walk.ts`, `src/proxy/anthropic.ts`, `src/proxy/openai.ts` | Done |
| 2 | Detect national ID, phone/MoMo, bank account, email, TIN, listed names | `src/pii/detectors/` | Done; formats marked [VERIFY] |
| 3 | Unique random placeholders that cannot clash with normal text | `src/pii/placeholders.ts` | Done |
| 3 | Placeholder map only in memory, for one request | `src/pii/masker.ts` | Done; tested by searching the database and logs |
| 3 | Restore in the answer, including placeholders split across stream chunks | `src/pii/stream-restorer.ts` | Done |
| 3 | A damaged placeholder stays hidden; never guess | `src/pii/placeholders.ts` | Done |
| 4 | Images, files, PDFs blocked unless the policy allows | `src/proxy/handler.ts`, `src/policy/policy.ts` | Done |
| 5 | Fail closed | `src/proxy/handler.ts`, `src/errors.ts` | Done |
| 6 | Audit log: every request, never personal data | `src/audit/log.ts` | Done (cost is recorded as empty until Phase 2 adds prices) |
| 6 | Hash-chained and HMAC-signed | `src/audit/log.ts` | Done |
| 6 | Daily signed checkpoint file | `src/audit/checkpoint.ts` | Done |
| 6 | `verify` reports valid or exactly where it is broken | `src/cli.ts` | Done |
| 6 | Export to CSV and JSON | `src/audit/export.ts` | Done |

### Tests

`npm test`: **250 passing** (162 at the end of Phase 1, plus 88 for item 9),
all offline against a fake provider. 2 more (PostgreSQL)
are skipped unless a PostgreSQL server is supplied; they pass when one is.

| Your test requirement | Test file | Result |
|---|---|---|
| Every personal-data type hidden and restored, tricky formats | `test/detectors.test.ts`, `test/masking.test.ts` | Pass |
| Kinyarwanda and English mixed text | `test/detectors.test.ts`, `test/proxy.test.ts` | Pass |
| Data inside tool calls | `test/proxy.test.ts` | Pass |
| Placeholders split across stream chunks | `test/masking.test.ts` (every cut position), `test/proxy.test.ts` (chunk sizes 1 to 500, and arbitrary network cuts) | Pass |
| Fail closed when checking breaks | `test/fail-closed.test.ts` | Pass |
| Attachments rule | `test/proxy.test.ts` | Pass |
| Audit: editing, deleting, reordering, rebuilding without the key | `test/audit.test.ts` | Pass, each with the exact entry number |
| Client isolation | `test/proxy.test.ts` | Pass (for what exists in Phase 1: keys, policies, name lists, placeholders) |
| Added delay under 50 ms | `test/latency.test.ts` | Pass: see below |

Policy rules (models, spending, size, topics, "may not leave Rwanda"),
injection screening and the admin page are Phase 2 and 3; their tests come
with them.

**Measured delay added by KRIS Guard** (a realistic 6 KB request with a
system prompt, a tool call, a tool result and every kind of personal data;
both audit entries written to disk):

| Measurement | Median | 95th percentile |
|---|---|---|
| Reported by the gateway itself | 1.9 ms | 2.9 ms |
| Measured from outside, minus the provider's time | 5.6 ms | 8.3 ms |
| Time to first streamed piece | 6.1 ms | 8.0 ms |

A 500 KB request added about 42 ms. These are from one development machine;
a slow disk will be slower, because each audit entry is forced to disk.

**Do the tests really test?** I broke three protections on purpose (masking
off, signature check off, stream hold-back off) and confirmed the tests
failed each time, then restored the code.

### Also checked

- **Docker**: the image builds, and I ran the container with the same
  hardening as `docker-compose.yml` (non-root user, read-only filesystem, all
  capabilities dropped). Inside it: created a client with the command-line
  tool, sent requests with personal data (plain and streamed), confirmed the
  fake provider received only placeholders, ran `audit verify` and
  `audit export`, and stopped it cleanly.
- **PostgreSQL**: `test/postgres.test.ts` passes against a real PostgreSQL 16.
- **Dependencies**: 6 runtime libraries (fastify, kysely, better-sqlite3, pg,
  zod, yaml), all pinned to exact versions. `npm audit` reports 0 known
  vulnerabilities.

### Not checked: please be aware

- **No request has been sent to the real Anthropic or OpenAI.** All tests use
  the fake provider. The request and streaming formats follow the published
  API descriptions, but the first real call is still a first.
- `docker compose up` itself was not run here (the sandbox needs proxy
  settings that a normal machine does not). The image build, the container
  run with the same options, and `docker compose config` were.
- `npm audit signatures` (checks packages were not altered in transit) could
  not download its data in this sandbox. Run it once on your machine.
- The Rwandan formats marked **[VERIFY]**: national ID layout, mobile and
  landline prefixes, TIN format and its Kinyarwanda wording, bank account
  formats. See `THREAT_MODEL.md` section 8.

### Decisions I made that you should know about

1. **A second placeholder option, "stable".** You asked for random
   placeholders, and that is the default. While checking the current
   Anthropic API I found that random placeholders make a conversation's
   earlier messages look different on every turn. Current Anthropic models
   can *reject* a conversation whose history changed when the AI's "thinking"
   is sent back, and prompt caching stops working from the first hidden value.
   So each client's policy can choose `placeholders: stable` (the same value
   always gets the same placeholder for that client). The trade-off is in
   `README.md` under "Honest limits". **You decide per client; nothing changes
   unless you set it.**
2. **The AI's "thinking" text is not restored.** It is signed by the
   provider; changing it would break later turns.
3. **Two audit entries per request**: one before forwarding, one after.
4. **A missing or invalid policy file blocks that client** rather than
   falling back to defaults.
5. **Personal data in a field that cannot be replaced** (a tool name, a model
   name) blocks the request.
6. **A user label that looks like personal data** is stored as a scrambled
   code, so the audit log stays free of personal data.
7. **Unauthenticated requests are logged but not written to the audit log**,
   so an outsider cannot fill the log with junk. Rate limiting comes in Phase 2.
8. A minimal `/health` (just "ok") exists now because Docker needs it. The
   full health report is still Phase 3.

### Known gaps until Phase 2

No rate limiting, no spending limits, no model allow-list, no request-size
limit per client (there is one global limit), no planted-instruction
screening, no retries. **Do not expose Phase 1 to the open internet.**

---

## Next: Phase 2 (on your OK)

Full policy file (allowed models, monthly spending limit, max request size,
blocked words/topics, action on personal data, "may leave Rwanda"), the price
table and cost tracking, planted-instruction screening as a replaceable
module, the optional scan of the answer, rate limiting, timeouts, retries
with backoff.

---

## Phase 2 so far

Done at the end of the Phase 1 session, at your request to use the remaining
time on the hardest part. **Phase 2 is NOT complete; do not treat it as a
finished phase.**

| # | Requirement | Status |
|---|---|---|
| 9 | Planted-instruction screening, rule-based, replaceable module | Done: `src/injection/detector.ts` (the interface and warn/strip/block), `src/injection/rules.ts` (the rules) |
| 9 | Per client: warn, strip or block | Done: `injection_screening` in the policy file; default `warn` |
| 9 | Applied to documents, emails, web pages, tool results | Done: marked in `src/proxy/anthropic.ts` and `openai.ts` with `untrusted(...)` |
| 9 | Optional scan of the answer for new personal data | Done: `personal_data.scan_answers` in the policy (default off); `newPiiIn` in `src/proxy/handler.ts` |
| 7 | Allowed models, spending limit, max size, blocked words, action on personal data, attachments, "may leave Rwanda" | Attachments only (Phase 1). **The rest not started** |
| 8 | Price table and cost | **Not started** |
| 10 | Rate limiting, timeouts, retries, error wording | A provider timeout exists (Phase 1). **The rest not started** |

Tests: `test/injection.test.ts` (30 attack examples caught, 25 ordinary
business sentences not flagged, the three actions, speed on hostile input)
and `test/injection-proxy.test.ts` (end to end, both APIs, which text is and
is not screened, nothing sensitive recorded, a crashing detector blocks).

`test/answer-scan.test.ts` covers the answer scan: new data flagged (plain,
tool calls, streamed and split across chunks), request data not flagged, off
by default, only the KINDS recorded.

Things to know:
- The answer scan flags; it does not change or block the answer. For a
  streamed answer the flag is in the audit log only (the headers have already
  been sent by then).
- The Kinyarwanda rule is marked [VERIFY]; I am not confident of the wording.
- The default is `warn`, so existing clients keep working and get flagged.
- The system prompt and tool definitions are never screened (the client's
  developers wrote them). What the user typed is screened only if the policy
  sets `scan_user_messages: true`.
- In-memory detector swap: pass `injectionDetector` to `buildApp`.

---

## Handoff notes for Phases 2 and 3 (design decisions and traps)

Written at the end of the Phase 1 session so the work can continue without
re-deriving these. Each point is something that is easy to get subtly wrong.

### How Phase 1 is wired (read these first)

- `src/proxy/handler.ts` is the whole request flow, steps numbered 1 to 8.
  New Phase 2 checks go between step 2 (policy loaded) and step 5 (audit
  entry). Throw a `GuardError`; `sendError` records and answers it.
- Every string in a request goes through exactly one of MASK / FREEFORM /
  CHECK / OPAQUE (`src/pii/walk.ts`). Keep that invariant.
- `record` in the handler becomes the audit entry. **Never put request text
  in it.** `test/proxy.test.ts` ("NEVER stores personal data") searches the
  database, the WAL file and the logs for sample values: extend that test for
  every new feature.
- New error kinds: add to `GuardErrorCode` and `STATUS` in `src/errors.ts`.
- Policy schema is `z.strictObject` (a misspelt key blocks the client). When
  adding fields, also update `STARTER_POLICY`, the README policy section and
  `DEFAULT_POLICY` in `test/helpers/gateway.ts`.

### Phase 2

**Policy enforcement**
- *Allowed models*: check right after the policy loads, before masking.
  Exact names plus an optional trailing `*`. Empty list should mean "none
  allowed" (fail closed), not "all allowed".
- *Max request size*: compare `Buffer.byteLength(parsed.raw)`, not
  `.length` (characters are not bytes for Kinyarwanda/French text).
- *Blocked words/topics*: match on the ORIGINAL text, before masking, with
  the same word-folding as `src/pii/detectors/names.ts` (reuse
  `createNameDetector` on the word list: it already does case, accents and
  whole-word matching). Record the index of the rule that matched, never the
  surrounding text.
- *Action on personal data* (`hide` / `block` / `allow`): give `Masker` a
  mode. `block` = `find()` and throw if anything is found. `allow` = count
  the kinds for the audit log but return the text unchanged; in this mode
  `checkOnly` must not block.
- *May leave Rwanda = false*: block when (a) action is `allow` and anything
  was found, or (b) the request has attachments (they cannot be checked), or
  (c) residual detection fires. In `hide` mode `Masker.mask` already
  re-checks its own output, so (c) is in place.

**Cost and spending limits**
- Keep money as whole numbers (micro-dollars). Floating-point sums drift.
- Price table `config/prices.yaml`: per model, per million tokens: input,
  output, cache read, cache write. `Usage` in `src/proxy/adapter.ts` already
  carries all four counts.
- A model with no price while a spending limit is set: block (fail closed).
- Do NOT compute monthly spend by scanning audit JSON on each request. Add a
  small `usage` table (client_id, month, cost, tokens) updated in `finish()`.
  The audit log stays the record; the table is the fast counter. A test
  should confirm the two agree.
- Check the limit before forwarding. Several simultaneous requests can
  overshoot slightly; this is documented in THREAT_MODEL.md section 6.
- A stream that breaks half-way: Anthropic reports input tokens in
  `message_start`, so partial cost is known. OpenAI reports usage only in the
  last event, so a broken OpenAI stream has unknown cost: record it as
  unknown and flag it, do not record zero.
- `handler.ts` writes `cost_usd: null` today; fill it in `finish()`.

**Planted-instruction screening** (started: see `src/injection/`)
- Untrusted text = tool results, text documents, search results, provider
  tool results, OpenAI `role: "tool"` messages. Optionally user messages.
  The system prompt and tool definitions are the client developer's own.
- Screen BEFORE masking (rules need the real words), strip before masking.
- Log and audit rule ids and counts only. The matched text may be personal data.
- The "strip" marker must not itself trigger a detector.

**Scan of the answer for new personal data**: done (see "Phase 2 so far").

**Rate limits, timeouts, retries**
- Token bucket per key id, in memory. Also limit failed-key attempts per IP
  in the `onRequest` hook in `src/server.ts`. Behind a reverse proxy the IP
  is only right if Fastify's `trustProxy` is set: make it a setting.
- Retry only when NOTHING has been sent to the client yet, only on
  connection errors and 429/500/502/503/529, honour `retry-after` (capped),
  and stop at an overall deadline. Never retry once a stream has started.
- Provider error bodies are currently passed through unchanged (they contain
  placeholders at most). Requirement 10 may want them mapped to generic text.

### Phase 3

- Serve the admin page from a SECOND Fastify instance on its own port, bound
  to 127.0.0.1 by default, so it shares no routes with the proxy.
- Password: HMAC it with `deriveKey(secret, "admin-password")`, THEN scrypt
  (N=2^17, r=8, p=1) with a random salt. The HMAC step is what stops someone
  with database write access from swapping in a hash they made themselves.
- Sessions: 32 random bytes in a cookie (`HttpOnly`, `SameSite=Strict`,
  `Secure`, `__Host-` prefix); store only an HMAC of it. Idle and absolute expiry.
- CSRF: a per-session token in every form, plus an `Origin` header check.
- Login limits: per IP and per username, with growing delays.
- Every admin action: `audit.append("admin", { action, actor: username })`.
  `ClientService` methods already take an `actor`.
- HTML: escape every value; send a strict Content-Security-Policy
  (`default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'`).
  Client names are attacker-influenced text.
- First admin is created by the command-line tool, never a default password.
- "Recent blocks": audit rows store details as JSON text. Either filter in
  code over the last N rows, or add indexed columns. Do not use SQL `LIKE`
  on the JSON for anything a client can influence.
- `/health` should check the database answers and report the audit head
  number, without revealing versions or paths to unauthenticated callers.
