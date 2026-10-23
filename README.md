# opencti-mcp-server

Read-only MCP server for [OpenCTI](https://github.com/OpenCTI-Platform/opencti). It is the threat-intelligence
backend for [talon-analyst](https://github.com/socfortress/talon-analyst), SOCFortress's AI SOC analyst, and
works with any MCP client.

It answers the questions an analyst asks of OpenCTI during triage: is this hash, IP, domain, URL or email
known, how is it scored, which indicators and reports mention it. It never writes to OpenCTI.

Supported OpenCTI versions: **6.9** and **7.x**. Every GraphQL document the server sends is validated against
the schemas of 6.9.29 and 7.261023.1 in CI.

## Tools

All tools are annotated read-only (`readOnlyHint`, not destructive, idempotent).

| Tool | Purpose |
|---|---|
| `lookup_observable(value, type?)` | Exact, case-insensitive lookup of an observable. `type` is detected when omitted: a hash by its length (MD5, SHA-1, SHA-256, SHA-512), IPv4, IPv6, URL, email or domain (a detected domain also matches Hostname observables). Returns each match with score, labels, markings, author, `updated_at`, hashes, up to 5 linked indicators (compact) and 5 reports (`id`, `name`, `published`), with their totals. |
| `search_indicators(value?, search?, min_score?, observable_type?, pattern_type?, include_revoked=false, first=10, after?)` | Indicators by exact `value` (the indicator's name, or a quoted literal in its pattern), fuzzy `search` (discovery only), minimum score, main observable type or pattern type. Revoked indicators are excluded by default. Page with `after` = `next_cursor`. |
| `get_indicator(id)` | One indicator: pattern, score, validity, kill chain phases, observable values, external references, up to 10 observables and 5 reports. |
| `get_observable(id, relations=false)` | One observable with external references, up to 5 indicators and 5 reports; with `relations=true`, also up to 20 relationships (newest first). |
| `observable_indicators(id, first=10)` | The indicators linked to an observable, in full. |

`type` takes one of `md5`, `sha1`, `sha256`, `sha512`, `ipv4`, `ipv6`, `domain`, `hostname`, `url` and
`email`. Ids are an OpenCTI id (a UUID) or a STIX id (`<type>--<uuid>`). `first` is capped by
`OPENCTI_MAX_FIRST`.

Every result carries `withheld` (see [TLP ceiling](#tlp-ceiling)). List results carry `total` (OpenCTI's own
count, before the TLP filter), `returned` and `has_more`. Example, with synthetic data:

```json
{"query":{"value":"malicious.example.com","type":"domain","observable_types":["Domain-Name","Hostname"]},
 "total":1,"returned":1,"withheld":1,"withheld_reason":"marked above TLP:AMBER+STRICT","has_more":false,
 "observables":[{"id":"…","standard_id":"domain-name--…","type":"Domain-Name","value":"malicious.example.com",
   "score":70,"markings":["TLP:CLEAR"],"labels":["phishing"],"created_by":"Example Feed","updated_at":"…",
   "indicators":[{"id":"…","name":"malicious.example.com","pattern":"[domain-name:value = 'malicious.example.com']",
     "pattern_type":"stix","score":80,"detection":true,"revoked":false,"valid_until":"…","markings":["TLP:CLEAR"]}],
   "indicators_total":2,
   "reports":[{"id":"…","name":"Example campaign report","published":"…","markings":["TLP:CLEAR"]}],
   "reports_total":1}]}
```

## TLP ceiling

`OPENCTI_MAX_TLP` (default `TLP:AMBER+STRICT`) is the highest TLP the server returns. Any object marked above
it is dropped from the output and counted in `withheld`, at every level: an observable, an indicator, a
report or observable nested inside another result, and a relationship whose own marking or either end is
above the ceiling. A requested object that is itself above the ceiling comes back as
`{"indicator": null, "withheld": 1, ...}`.

- Only markings whose `definition_type` is `TLP` count. PAP markings share order numbers with TLP (on a
  default install PAP:RED has the same order as TLP:AMBER+STRICT) and are never read as TLP.
- A TLP marking's rank is the higher of its `x_opencti_order` and its standard name's rank
  (CLEAR/WHITE 1, GREEN 2, AMBER 3, AMBER+STRICT 4, RED 5). A renamed or reordered marking cannot slip under
  the ceiling, and an unknown TLP marking ordered above it (say a custom `TLP:BLACK`) is withheld. A TLP
  marking with neither a known name nor an order is withheld.
- Unmarked objects are visible.

The ceiling is defence in depth. The first control is the service account's own allowed markings
(below): OpenCTI never returns what the account cannot see.

## Security model

- **Read-only by construction.** The server sends only the fixed queries in
  [`queries.py`](src/opencti_mcp_server/queries.py). There are no mutations and no raw-GraphQL tool, and a
  test checks every document is a single query.
- **Values are variables.** Caller input becomes GraphQL variables only: ids, cursors, search text, and the
  values of FilterGroup filters with one key each. Nothing is spliced into a document, so quotes or GraphQL
  syntax in a value stay data.
- **Exact lookups are filters.** `value` and `hashes.<alg>` with `eq`, which OpenCTI matches
  case-insensitively. `search` is OpenCTI's fuzzy keyword search, kept for discovery.
- **Input validation.** Ids must be a UUID or `<type>--<uuid>`; `type`, `observable_type` and `pattern_type`
  are allow-lists; values are length-bounded and refused if they contain control or zero-width characters;
  `first` is capped by `OPENCTI_MAX_FIRST`.
- **Untrusted third-party text.** OpenCTI content comes from feeds. Every string is stripped of control,
  zero-width and bidi-override characters; descriptions are capped at 500 characters, patterns at 1000,
  labels at 20 per object; the output is compact JSON capped at `MCP_MAX_OUTPUT_CHARS` (default 20 000).
  When items are dropped to fit, the result carries
  `truncated: {list, returned_items, original_items, original_chars}`.
- **Fail closed.** OpenCTI reports failures as HTTP 200 with an `errors` array, sometimes beside partial
  `data`. Any `errors` entry fails the whole call.
- **Secrets.** `OPENCTI_TOKEN` is a secret setting: never logged, never returned, and redacted if OpenCTI
  ever echoes it in an error. httpx's per-request logging is off, so the OpenCTI address stays out of
  routine logs.
- **Authenticated transport.** The HTTP transport refuses to start without `MCP_AUTH_TOKEN` (which must
  differ from `OPENCTI_TOKEN`) and requires `Authorization: Bearer <token>` (constant-time compare) on every
  path except `GET /healthz`.

### Errors

Errors are MCP tool errors (`isError`). Their text is `Error executing tool <name>: ` followed by one of
these stable prefixes:

| Prefix | Meaning |
|---|---|
| `not found:` | No object with that id (OpenCTI returned `null`) |
| `bad request:` | Invalid arguments, or OpenCTI rejected the query (`GRAPHQL_VALIDATION_FAILED`, `BAD_USER_INPUT`, ...) |
| `opencti refused the request:` | `AUTH_REQUIRED` (bad or expired token) or `FORBIDDEN_ACCESS` |
| `opencti unavailable or timed out` | Connection failure, timeout, or HTTP 502/503/504 |
| `opencti error:` | Anything else OpenCTI reported |

OpenCTI's error code follows the message in brackets, e.g. `(FORBIDDEN_ACCESS)`. A lookup that matches
nothing is not an error: it returns an empty list.

## OpenCTI service account

Run the server with a dedicated, read-only OpenCTI account. Never use an admin token or any account with
"Bypass all capabilities".

**OpenCTI 7.x**

1. *Settings > Security > Roles*: create a role, e.g. `MCP read-only`, with only:
   - **Access knowledge** (no sub-capabilities: not Create / Update, Delete, Upload, Import or Enrichment);
   - **API usage with authorization headers > Allow token usage**.

   Never grant **Bypass all capabilities**.
2. *Settings > Security > Groups*: create a group, e.g. `MCP read-only`, with that role only. Set its
   **Allowed markings** to TLP:AMBER+STRICT at most (that is, TLP:CLEAR, TLP:GREEN, TLP:AMBER and
   TLP:AMBER+STRICT, plus any PAP or statement markings you want visible), and leave **Auto new markings**
   off so a new marking is not granted automatically.
3. *Settings > Security > Users*: create a **Service account**, e.g. `svc-opencti-mcp`, in that group only.
4. Create an API token for it and set it as `OPENCTI_TOKEN`.

**Token expiry on 7.x.** OpenCTI 7 tokens are created with a duration (30, 60, 90 or 365 days, or
unlimited) and stop working at their `expires_at`. An expired token makes every tool fail with
`opencti refused the request: ... (AUTH_REQUIRED)`, and `/readyz` returns 503. Pick a finite duration, note
the expiry date, and rotate before it: create a new token on the service account, update `OPENCTI_TOKEN`,
restart the server, check `/readyz`, then revoke the old token.

**OpenCTI 6.9.** The same group and markings, with a role holding only **Access knowledge**. A 6.9 user has
one API token, shown on its profile, with no expiry.

## Running

```bash
cp .env.example .env    # set OPENCTI_URL, OPENCTI_TOKEN and MCP_AUTH_TOKEN
uv sync
uv run opencti-mcp-server --transport http   # or --transport stdio (default)
```

Docker:

```bash
docker build -t opencti-mcp-server .
docker run --env-file .env -p 127.0.0.1:8000:8000 opencti-mcp-server
```

The image runs as a non-root user and has a healthcheck on `/healthz`. Released images are published from
`v*` tags as `ghcr.io/socfortress/opencti-mcp-server:X.Y.Z` (also `sha-<commit>` and `latest`), for
linux/amd64 and linux/arm64 with SBOM and provenance, by `.github/workflows/publish.yml`.
`scripts/check_image.sh IMAGE` runs the same image checks locally.

Health:

- `GET /healthz`: open, shallow (`{"status":"ok","version":"0.1.0"}`), for container healthchecks.
- `GET /readyz`: behind the bearer token. Runs `query { about { version } me { name } }` and returns
  `{"status":"ok","opencti_version":"…","authenticated":true}`, or 503 with the error. The user's name and
  capabilities are not returned.

From Pydantic AI (as talon-analyst does):

```python
from pydantic_ai.mcp import MCPToolset

opencti = MCPToolset("http://opencti-mcp:8000/mcp", id="opencti", headers={"Authorization": f"Bearer {token}"})
async with opencti:
    result = await opencti.direct_call_tool("lookup_observable", {"value": "203.0.113.7"})
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OPENCTI_URL` | `http://localhost:8080` | OpenCTI base URL (`/graphql` is appended) |
| `OPENCTI_TOKEN` | — | API token of the read-only service account (required) |
| `OPENCTI_VERIFY_TLS` / `OPENCTI_CA_CERT` | `true` / — | TLS verification, and a CA bundle for a private CA |
| `OPENCTI_TIMEOUT` | 30 | Seconds per request |
| `OPENCTI_MAX_TLP` | `TLP:AMBER+STRICT` | TLP ceiling: `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT` or `TLP:RED` |
| `OPENCTI_MAX_FIRST` | 50 | Max page size (`first`) |
| `MCP_MAX_OUTPUT_CHARS` | 20000 | Output cap per call |
| `MCP_AUTH_TOKEN` | — | Bearer token for MCP clients (required for HTTP; not the OpenCTI token) |
| `MCP_SERVER_HOST` / `MCP_SERVER_PORT` | `127.0.0.1` / `8000` | Bind address; `--host` / `--port` override |
| `MCP_ALLOWED_HOSTS` | — | Host header allow-list; enables DNS-rebinding protection |

## Tests

```bash
uv run pytest            # offline: tools against a mock OpenCTI, guards, TLP, errors, auth, contract tests
uv run ruff check src scripts tests && uv run ruff format --check src scripts tests
```

The contract tests (`tests/test_contract.py`) validate every document against OpenCTI's own SDL for 6.9.29
and 7.261023.1, vendored in `tests/schema/` (Apache-2.0, see `NOTICE`), with graphql-core.

Live tests are opt-in and read-only. They pick values from listing queries at run time, print counts and
versions only, and refuse to send anything but a query:

```bash
OPENCTI_LIVE=1 OPENCTI_LIVE_ENV_FILE=/path/to/opencti.env uv run pytest -m live -s
```

The env file holds `OPENCTI_URL` and `OPENCTI_TOKEN`; keep it outside the repository (`.env*` is
gitignored). `OPENCTI_EXPECT_VERSION` asserts the platform version.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
