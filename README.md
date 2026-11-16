# KRIS Guard

A self-hosted AI safety gateway for KRIS studio.

Client apps send their AI requests to KRIS Guard instead of straight to the AI
provider. KRIS Guard hides personal data, forwards the request with KRIS's own
provider key, puts the personal data back in the answer, and keeps a record
that cannot be changed quietly.

```
 Client app            KRIS Guard                         AI provider
 (e.g. Atelier)                                           (Anthropic / OpenAI)

 "Call 0788 123 456" ─►  check key, apply policy
                         hide personal data          ─►  "Call [[KG-PHONE-QZKW...]]"
                         write audit entry
 "Calling            ◄─  restore personal data       ◄─  "Calling [[KG-PHONE-QZKW...]]"
  0788 123 456"          write audit entry
```

> **Status: Phase 1 of 3.** See [PROGRESS.md](PROGRESS.md) for what is built
> and what is not yet. In short: the proxy, personal-data protection and audit
> log work today. Spending limits, model allow-lists, planted-instruction
> screening, rate limiting (Phase 2) and the admin page (Phase 3) do not exist
> yet. **Until Phase 2, do not expose KRIS Guard to the open internet.**

Read [THREAT_MODEL.md](THREAT_MODEL.md) for what it defends against and why.

---

## What it does today

- **Two endpoints** that behave like the real ones, including streaming:
  - `POST /v1/messages` (Anthropic Messages API)
  - `POST /v1/chat/completions` (OpenAI Chat Completions API)
- **Hides personal data in every text field**: system prompt, messages, tool
  definitions, tool calls and tool results. Detects Rwandan national IDs,
  phone and MoMo numbers, emails, TINs, bank accounts, and names you list.
- **Restores it in the answer**, also inside tool calls, also when a
  placeholder is split across streamed pieces.
- **Blocks attachments** (images, files, PDFs) unless a client's policy allows them.
- **Fails closed**: if any check breaks, the request is blocked, not waved through.
- **Per-client API keys**, stored only as hashes, revocable instantly.
- **Audit log**: every request, hash-chained and signed, with a daily signed
  checkpoint, a `verify` command, and CSV/JSON export. It never contains
  personal data or prompts.

---

## Run it with Docker

You need Docker with the Compose plugin.

**1. Create your settings file**

```bash
cp .env.example .env
```

Generate two secrets (run this twice, and paste one result into each of
`KRIS_GUARD_AUDIT_KEY` and `KRIS_GUARD_SECRET` in `.env`):

```bash
openssl rand -hex 32
```

Then put KRIS's provider keys in `ANTHROPIC_API_KEY` and/or `OPENAI_API_KEY`.

**2. Let the container write policy files**

The container runs as an unprivileged user (number 1000), which needs to
write into the policy folder:

```bash
sudo chown -R 1000:1000 config/policies
```

**3. Start it**

```bash
docker compose up -d --build
```

**4. Check it is alive**

```bash
curl http://127.0.0.1:8080/health
```

You should see `{"status":"ok"}`.

By default it listens only on the machine itself (`127.0.0.1:8080`). To serve
apps on other machines, put an HTTPS reverse proxy in front (see
[HTTPS](#https) below). Without HTTPS, keys and personal data would cross the
network unprotected.

---

## Add a client

```bash
docker compose exec kris-guard kris-guard client add "Atelier"
```

This creates the client (id `atelier`), a starter policy file at
`config/policies/atelier.yaml`, and an API key. **The key is shown once.**
Copy it into the client app's settings; KRIS Guard keeps only a hash.

Other commands:

```bash
docker compose exec kris-guard kris-guard client list
```

```bash
docker compose exec kris-guard kris-guard key create atelier
```

```bash
docker compose exec kris-guard kris-guard key list
```

```bash
docker compose exec kris-guard kris-guard key revoke <key-id>
```

A revoked key stops working immediately.

---

## Point an app at it (for example Atelier)

Change two things in the app: the **address** and the **key**. Nothing else.

**Anthropic SDK (TypeScript)**

```ts
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({
  baseURL: "https://guard.kris.example", // KRIS Guard, not api.anthropic.com
  apiKey: process.env.KRIS_GUARD_KEY,    // the kg_... key, not an Anthropic key
});

const message = await client.messages.create(
  {
    model: "claude-opus-5-5",
    max_tokens: 1024,
    messages: [{ role: "user", content: "Andikira Mugisha kuri 0788 123 456" }],
  },
  { headers: { "x-kris-user": "user-4821" } }, // optional: which of your users this is
);
```

**Anthropic SDK (Python)**

```python
import os
from anthropic import Anthropic

client = Anthropic(base_url="https://guard.kris.example", api_key=os.environ["KRIS_GUARD_KEY"])
```

**OpenAI SDK** (note the `/v1` at the end)

```ts
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "https://guard.kris.example/v1",
  apiKey: process.env.KRIS_GUARD_KEY,
});
```

**Plain HTTP**

```bash
curl http://127.0.0.1:8080/v1/messages \
  -H "x-api-key: $KRIS_GUARD_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"claude-opus-5-5","max_tokens":200,"messages":[{"role":"user","content":"Hamagara 0788 123 456"}]}'
```

The `x-kris-user` header is optional. It is recorded in the audit log so usage
can be broken down per user. Use an id like `user-4821`, not a name or email;
if it looks like personal data, KRIS Guard stores a scrambled code instead.

---

## Client policies

One file per client: `config/policies/<client-id>.yaml`. Edits apply on the
next request; no restart.

```yaml
attachments:
  # Images, files and PDFs cannot be checked for personal data.
  allowed: false

personal_data:
  # KRIS Guard only hides the names listed here.
  names:
    - Mugisha Jean
    - Uwase
  # random (default) or stable. See "Honest limits".
  placeholders: random
```

If the file is missing or has a mistake (even a misspelt setting), that
client's requests are **blocked** until it is fixed. To see what is wrong:

```bash
docker compose exec kris-guard kris-guard policy check atelier
```

---

## The audit log

Every request produces two entries: one before it is forwarded (who, which
model, what kinds of data were hidden, the decision) and one after (status,
token counts). Blocked requests produce one entry with the reason.

**Check it has not been tampered with**

```bash
docker compose exec kris-guard kris-guard audit verify
```

It prints `VALID`, or `BROKEN at entry N` with what is wrong.

**Checkpoints: copy them off the server**

While running, KRIS Guard writes a small signed file each day to
`/data/checkpoints/` inside the container. It records how many entries
existed and the fingerprint of the last one. This is the only thing that can
prove later that entries were not deleted from the *end* of the log.

Copy the files somewhere else every day (another server, cloud storage):

```bash
docker compose cp kris-guard:/data/checkpoints ./checkpoint-backup
```

A checkpoint contains no personal data and no secrets.

**Export**

```bash
docker compose exec kris-guard kris-guard audit export --format csv > audit.csv
```

```bash
docker compose exec kris-guard kris-guard audit export --format json > audit.json
```

---

## When a request is refused

Errors use the same shape as the provider's, so client libraries understand
them. The `code` tells you why:

| Code | Meaning |
|---|---|
| `kris_guard_unauthorized` | Missing, wrong or revoked key |
| `kris_guard_attachment_blocked` | The request contains an image, file or PDF and the policy does not allow them |
| `kris_guard_unmaskable_personal_data` | Personal data in a field that cannot be replaced (a tool name, a model name, an id) |
| `kris_guard_policy_unavailable` | The client's policy file is missing or invalid |
| `kris_guard_check_failed` | A safety check itself failed; the request was blocked to be safe |
| `kris_guard_audit_unavailable` | The request could not be recorded, so it was not sent |
| `kris_guard_invalid_request` / `kris_guard_request_too_large` | The request is malformed or too big |
| `kris_guard_provider_unreachable` / `_timeout` / `_not_configured` | A problem reaching the AI provider |

Every answer carries an `x-kris-request-id` header. Quote it when asking the
KRIS administrator about a refused request; it identifies the audit entries.

---

## HTTPS

KRIS Guard speaks plain HTTP and expects an HTTPS reverse proxy in front.
With [Caddy](https://caddyserver.com), the whole configuration is:

```
guard.kris.example {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

`flush_interval -1` passes streamed answers through piece by piece instead of
holding them back.

---

## Honest limits

What KRIS Guard cannot do. Please read this before trusting it with real data.

**Personal data it will miss**

- **Names not on the client's list.** There is no automatic name recognition.
- **Unusual spellings**: a phone number written in words, digits separated by
  unusual characters, or text deliberately disguised.
- **Other identifying details**: addresses, dates of birth, job titles,
  descriptions of a person. Only the listed kinds are detected.
- **A TIN with no word like "TIN" or "NIF" near it.** A bare 9-digit number is
  usually an amount of money, so it is only treated as a TIN with such a word.
- **Bank accounts** are the weakest detector. Rwanda has no single account
  format. Short account numbers with no banking word nearby are missed.
- **Anything inside an attachment**, if the policy allows attachments.
- **MoMoPay merchant codes** are not detected (MoMo *numbers* are: they are phone numbers).

**Formats marked [VERIFY] in the code** could not be confirmed from an
official source: the national ID layout, the list of mobile prefixes, landline
prefixes, the TIN format, and bank account formats. The detectors are written
to depend on as little unconfirmed detail as possible, but check them against
real examples.

**False alarms** happen too: a long order number or a timestamp may be hidden
as if it were a bank account. This is harmless (the value is restored in the
answer) but the AI cannot read that value while answering.

**Placeholders, caching and "thinking"**

- With `placeholders: random` (the default), the same phone number gets a new
  placeholder in every request. That is the most private choice, but it means
  a conversation's earlier messages look different to the provider on every
  turn. Two consequences on current Anthropic models: prompt caching stops
  saving money from the first hidden value onwards, and conversations that
  replay the AI's "thinking" blocks can be **rejected by the provider** once
  the history contains hidden values.
- `placeholders: stable` fixes both by always giving the same value the same
  placeholder for that client. The cost: the provider can tell that two
  requests mention the same (still unknown) value.
- The AI's "thinking" text is **not** restored; any placeholders in it stay
  hidden. Changing it would break the provider's signature on it.
- If the AI alters a placeholder (drops a bracket, changes a letter), that
  value stays hidden in the answer. KRIS Guard never guesses.

**Tool calls**

- When the AI asks the app to run a tool, KRIS Guard restores real values in
  the tool call (the tool could not work otherwise). If a planted instruction
  tricked the AI into calling "send email" with a customer's details, KRIS
  Guard will not know. **Apps must confirm sensitive actions with a person.**
- Tools the *provider* runs (web search, code execution) receive placeholders,
  not real values, so they cannot use hidden data. Their results come back
  from the provider and are not scanned.

**Other**

- Whole numbers above 9,007,199,254,740,991 lose precision when a request is
  re-written (a limit of JSON in JavaScript). Send very long numbers as text.
- "Tamper-proof" means tamper-**evident**: changes to the audit log are
  detected, not prevented. Entries deleted after your last off-server
  checkpoint cannot be proven missing.
- Someone who fully controls the server can read data in memory and the
  secrets. KRIS Guard cannot defend against that.
- Phase 1 has **no** rate limiting, spending limits, model allow-list or
  planted-instruction screening. Those arrive in Phase 2.

---

## Developing and testing

Requires Node.js 22.12 or newer.

```bash
npm ci
```

```bash
npm test
```

All tests run offline against a fake AI provider (`test/helpers/fake-provider.ts`).

To also test the optional PostgreSQL support, point the tests at a PostgreSQL
server (a throwaway database is created and removed):

```bash
TEST_POSTGRES_URL=postgres://user:pass@localhost:5432/postgres npm test
```

Other commands:

```bash
npm run typecheck
```

```bash
npm run audit:deps
```

To use PostgreSQL in production instead of SQLite, see the comments in
`docker-compose.yml` and `.env.example`.

### Project layout

```
src/
  index.ts        starts the server
  cli.ts          the kris-guard command-line tool
  config.ts       reads settings; refuses to start with weak secrets
  server.ts       web server, routes, safe error answers
  proxy/          the request flow (handler.ts) and one adapter per provider
  pii/            detectors, placeholders, masking, streamed restoring
  audit/          the chained, signed log; checkpoints; export
  clients/        clients and API keys
  policy/         per-client policy files
  db/             database tables and connection
test/             offline tests and the fake provider
config/policies/  one YAML file per client
```

A full beginner's tour of the code (LEARN.md) comes with Phase 3.

---

## Troubleshooting

**`client add` warns it could not write the policy file.** The container's
user cannot write to `config/policies`. Run
`sudo chown -R 1000:1000 config/policies`, then
`docker compose exec kris-guard kris-guard policy init <client-id>`.
Until the file exists, that client's requests are blocked.

**Every request for one client returns `policy_unavailable`.** Run
`kris-guard policy check <client-id>`; it prints the mistake.

**The server exits at once.** Read its first log lines
(`docker compose logs kris-guard`). It names any missing or too-short secret.

**Streaming arrives all at once.** The reverse proxy is buffering. For Caddy
use `flush_interval -1`; for nginx use `proxy_buffering off;`.
