# KRIS Guard: Progress

| Step | Status |
|---|---|
| Step 0: threat model and plan | Done |
| **Phase 1: core proxy, personal-data protection, audit log** | **Done, waiting for your OK** |
| Phase 2: client policies, planted-instruction screening, cost, rate limits | Not started |
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

`npm test`: **162 passing**, all offline against a fake provider. 2 more
(PostgreSQL) are skipped unless a PostgreSQL server is supplied; they pass
when one is.

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
