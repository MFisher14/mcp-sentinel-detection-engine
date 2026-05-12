# mcp-sentinel-detection-engine

[![CI](https://github.com/MFisher14/mcp-sentinel-detection-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/MFisher14/mcp-sentinel-detection-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![GitHub Issues](https://img.shields.io/github/issues/MFisher14/mcp-sentinel-detection-engine.svg)](https://github.com/MFisher14/mcp-sentinel-detection-engine/issues)

> **Status: Alpha — v0.1.0 (May 2026).** Tool surface and config schema
> may change before v1.0. See
> [GitHub Milestones](https://github.com/MFisher14/mcp-sentinel-detection-engine/milestones)
> for the v0.2 / v0.3 / v0.4 plan.

## Table of contents

- [Why an MCP server, not just a CLI?](#why-an-mcp-server-not-just-a-cli)
- [Quickstart (offline)](#quickstart-offline)
- [Tools](#tools)
- [Prerequisites (Azure — required only for live query execution)](#prerequisites-azure--required-only-for-live-query-execution)
- [Installation](#installation)
- [Configuration](#configuration)
- [Security design](#security-design)
- [Scope & Design Philosophy](#scope--design-philosophy)
- [Development](#development)
- [Roadmap](#roadmap)

An [MCP](https://modelcontextprotocol.io/) server that exposes a Sigma →
KQL → Microsoft Sentinel Terraform pipeline as tools Claude and other
MCP clients can drive. Companion to
[`mcp-defender-xdr`](https://github.com/MFisher14/mcp-defender-xdr) —
hunt there, ship detections from here. It lets a detection engineer (or
an agent on their behalf) take a Sigma rule, convert it to KQL targeting
the Log Analytics schema, statically validate the columns it touches,
optionally test-run it against a live Sentinel workspace, and emit an
`azurerm_sentinel_alert_rule_scheduled` Terraform block — all in natural
language inside Claude. The server runs locally over stdio,
authenticates as one or more Azure App Registrations via OAuth 2.0
**certificate** client credentials, supports a single tenant or many,
and treats every input and every upstream response as untrusted.

> **v0.1 status:** Sigma → KQL via pySigma's `pysigma-backend-kusto`
> with the `azure_monitor` pipeline, static column validation against a
> bundled Log Analytics schema snapshot, live KQL dry-run against a
> Sentinel workspace with certificate-based auth, and Terraform emission
> for `azurerm_sentinel_alert_rule_scheduled`.

---

## Why an MCP server, not just a CLI?

`sigma-cli`, `pySigma`, `uncoder.io`, and `SigmaToARM` already convert Sigma 
to KQL. The conversion is the easy part. The hard part — the part a detection 
engineer actually does — is the loop around it:

1. **Disambiguate the target table.** `pysigma-backend-kusto` auto-maps 
   Windows logsources to `SecurityEvent`, but cloud logsources (`SigninLogs`, 
   `AuditLogs`, `OfficeActivity`, `AzureActivity`, `CommonSecurityLog`, 
   `Syslog`) need an explicit `target_table` choice. An agent can ask 
   follow-up questions; a CLI can't.
2. **Catch the column typo before Sentinel does.** `validate_kql_against_schema` 
   checks the generated KQL against a bundled Log Analytics schema snapshot 
   and proposes corrections (`AccontName` → `AccountName`, `Account`). That's 
   a conversation, not a flag.
3. **Smoke-test on live data, read-only.** `dry_run_kql` runs the converted 
   query against an actual workspace with a 10-row cap and a 60-second 
   timeout. The agent sees the rows and decides whether the rule is right.
4. **Emit reviewable Terraform.** `generate_sentinel_terraform` produces an 
   `azurerm_sentinel_alert_rule_scheduled` resource with ATT&CK metadata, 
   ISO-8601 frequency/period, and HCL-injection-safe escaping — ready for 
   `terraform plan` in a separate, write-credentialed pipeline.

Each tool is a small, pure function. The **agent** is the orchestrator. The 
server's job is to make every step (a) safe to expose to a model — see 
[`THREAT_MODEL.md`](THREAT_MODEL.md) — and (b) auditable on stderr.

---

## Quickstart (offline)

The conversion, validation, and Terraform-emission tools are pure
functions — you can drive the full Sigma → KQL → Terraform loop from
Claude Desktop **without any Azure credentials**. Only `dry_run_kql`
needs a tenant.

```bash
git clone https://github.com/MFisher14/mcp-sentinel-detection-engine.git
cd mcp-sentinel-detection-engine
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

Point Claude Desktop at the server using the no-credentials snippet in
[`examples/README.md`](examples/README.md), restart the client, and run
any of the bundled demo prompts — the five rows in that file cover all
four tools end-to-end against the seven example rules in `examples/sigma/`.

---

## Tools

All four tools accept an optional `tenant` parameter, but only
`dry_run_kql` actually uses it — the other three are pure functions and
need no Azure auth. The semantics are the same as the Defender XDR
companion:

- **omitted** → the configured `default` tenant.
- **`"contoso"`** (or any configured key) → that specific tenant.
- **`"*"`** → fan out across every configured tenant (only meaningful
  for `dry_run_kql`). Bounded concurrency (5 by default). Returns
  labelled per-tenant results; one failing tenant does not poison the
  rest.

### `convert_sigma_to_kql`

**Input**

```json
{
  "sigma_yaml": "title: Failed Network Logon\nid: 36e037c4-...\nlogsource: {product: windows, service: security}\ndetection: {selection: {EventID: 4625, LogonType: 3}, condition: selection}\nlevel: medium\n",
  "target_table": null
}
```

Either `sigma_yaml` (inline YAML) **or** `sigma_path` (absolute path)
must be supplied — not both. `target_table` is optional but required
for logsources outside the `azure_monitor` pipeline's built-in Windows
mappings (`signinlogs`, `auditlogs`, `officeactivity`, `azureactivity`,
`commonsecuritylog`, `syslog`).

**Output**

```json
{
  "queries": [
    {
      "kql": "SecurityEvent\n| where EventID == 4625 and LogonType == 3",
      "target_table": "SecurityEvent",
      "warnings": []
    }
  ],
  "metadata": {"query_count": 1, "target_tables": ["SecurityEvent"]}
}
```

Pure function. No Azure auth required.

### `validate_kql_against_schema`

**Input**

```json
{
  "query": "SecurityEvent | where AccontName == 'admin'",
  "table": "SecurityEvent"
}
```

**Output**

```json
{
  "valid": false,
  "table": "SecurityEvent",
  "unknown_columns": ["AccontName"],
  "suggestions": {"AccontName": ["AccountName", "Account"]},
  "metadata": {"schema_column_count": 41, "referenced_column_count": 1}
}
```

Offline check against the bundled Log Analytics schema snapshot. No
Azure auth required. v0.2 will offer live schema fetching via the Log
Analytics metadata API.

### `dry_run_kql`

**Input**

```json
{
  "query": "SecurityEvent | where EventID == 4625",
  "timespan": "PT1H",
  "row_limit": 10,
  "tenant": "contoso"
}
```

**Output** (single-tenant — truncated)

```json
{
  "columns": [{"name": "TimeGenerated", "type": "datetime"}],
  "rows": [["2026-05-12T09:14:22Z"]],
  "metadata": {
    "row_count": 1,
    "column_count": 1,
    "workspace_id": "...",
    "timespan": "PT1H"
  }
}
```

**Output** (`tenant: "*"` — truncated)

```json
{
  "fan_out": true,
  "tenants": ["contoso", "fabrikam"],
  "results": [
    {"tenant": "contoso", "result": {"rows": [...], "metadata": {...}}},
    {"tenant": "fabrikam", "error": {"code": "rate_limited", "message": "..."}}
  ]
}
```

Read-only by construction: queries are capped at `row_limit` ≤ 10 and a
60-second server timeout, and queries longer than 10,000 chars or
containing destructive KQL control verbs (`.drop`, `.alter`, `.ingest`,
`.external_table`, `.purge`, …) are rejected before any HTTP call.

### `generate_sentinel_terraform`

**Input**

```json
{
  "query": "SecurityEvent | where EventID == 4625",
  "metadata": {
    "name": "failed_logon_burst",
    "display_name": "Failed Logon Burst",
    "description": "Detect bursts of failed Windows network logons.",
    "severity": "High",
    "query_frequency": "PT1H",
    "query_period": "PT1H",
    "trigger_operator": "GreaterThan",
    "trigger_threshold": 10,
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110", "T1110.001"]
  }
}
```

**Output**

```json
{
  "terraform_hcl": "resource \"azurerm_sentinel_alert_rule_scheduled\" \"failed_logon_burst\" { ... }\n",
  "metadata": {
    "rule_name": "failed_logon_burst",
    "severity": "High",
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110", "T1110.001"]
  }
}
```

`name` must be a Terraform-safe identifier
(`[A-Za-z_][A-Za-z0-9_-]{0,255}`); `severity` ∈
{`High`, `Medium`, `Low`, `Informational`}; ISO 8601 durations for
`query_frequency` / `query_period` / `suppression_duration`; MITRE
ATT&CK tactic names (`InitialAccess`, `Execution`, ...) and technique
IDs (`T1059`, `T1059.001`, ...). The emitted HCL references
`var.log_analytics_workspace_id` so the same module can be applied to
any workspace, and the resource GUID is derived server-side from a
stable namespace UUID — caller-supplied strings are never interpolated
unquoted. Pure function. No Azure auth required.

---

## Prerequisites (Azure — required only for live query execution)

The Quickstart above works without any of the steps in this section.
Set up the following **only** if you want to exercise `dry_run_kql`
against a real Sentinel workspace.

1. An Azure tenant with Microsoft Sentinel enabled on a Log Analytics
   workspace.
2. An [Azure App Registration](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
   per tenant, with the following **role assignment at the Log
   Analytics workspace scope** (not API permission — Sentinel data plane
   uses RBAC):

   | Role                          | Scope             | Why                                                       |
   | ----------------------------- | ----------------- | --------------------------------------------------------- |
   | `Microsoft Sentinel Reader`   | Workspace         | Run read-only KQL via the Log Analytics query API         |
   | *(equivalent built-in)*       | Workspace         | `Microsoft.OperationalInsights/workspaces/query/read`     |

   The role is **read-only**. The App Registration does **not** need
   any API permission grant — token acquisition uses the static scope
   `https://api.loganalytics.io/.default`.

3. A certificate per App Registration. Generate one with OpenSSL:

   ```bash
   # 1. Generate cert + key.
   openssl req -x509 -newkey rsa:2048 \
     -keyout key.pem -out cert.pem \
     -days 365 -nodes \
     -subj "/CN=mcp-sentinel-detection-engine"

   # 2. Bundle into a PFX (use a strong passphrase in production).
   openssl pkcs12 -export \
     -out app-cert.pfx \
     -inkey key.pem -in cert.pem \
     -password pass:""

   # 3. Upload cert.pem (the public half) to the App Registration:
   #    Azure portal → App Registration → "Certificates & secrets"
   #      → "Certificates" → "Upload certificate".
   ```

4. The **Log Analytics workspace ID (GUID)** for each tenant you wire
   in. Azure portal → Log Analytics workspace → *Overview* → *Workspace
   ID*.

5. Python 3.11+. We recommend [`uv`](https://docs.astral.sh/uv/).

---

## Installation

### With `uvx`

```bash
uvx --from mcp-sentinel-detection-engine mcp-sentinel-detection-engine
```

### With `pip`

```bash
pip install mcp-sentinel-detection-engine
mcp-sentinel-detection-engine
```

### From source (development)

```bash
git clone https://github.com/MFisher14/mcp-sentinel-detection-engine.git
cd mcp-sentinel-detection-engine
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

---

## Configuration

### Single tenant (development / small deployments)

Set these environment variables (or a `.env` file based on
[`.env.example`](./.env.example)):

| Variable                          | Required | Description                                                |
| --------------------------------- | -------- | ---------------------------------------------------------- |
| `AZURE_TENANT_ID`                 | yes      | Azure AD directory (tenant) ID.                            |
| `AZURE_CLIENT_ID`                 | yes      | App Registration client ID.                                |
| `AZURE_CERT_PATH`                 | yes      | Absolute path to the PFX (PKCS#12) bundle.                 |
| `SENTINEL_WORKSPACE_ID`           | yes      | Log Analytics workspace GUID for `dry_run_kql`.            |
| `AZURE_CERT_PASSPHRASE`           | no       | Passphrase for the PFX. Omit if unencrypted.               |
| `LOGANALYTICS_API_BASE`           | no       | Override the Log Analytics query API base URL.             |
| `MCP_SENTINEL_LOG_LEVEL`          | no       | Audit log level. Default `INFO`.                           |

The server validates that the PFX file exists and that
`SENTINEL_WORKSPACE_ID` is a GUID at startup, and fails fast with exit
code 2 if any required variable is missing or malformed.

The default Log Analytics query endpoint is `https://api.loganalytics.io`
and you should not need to override it. The `LOGANALYTICS_API_BASE`
escape hatch exists for sovereign-cloud deployments
(`api.loganalytics.us`, `api.loganalytics.azure.cn`, ...).

### Multi tenant (production)

Set `MCP_SENTINEL_TENANTS_FILE` to the absolute path of a JSON config
file. When that variable is set, the single-tenant `AZURE_*` /
`SENTINEL_WORKSPACE_ID` variables above are ignored. See
[`tenants.example.json`](./tenants.example.json) for the schema. The
file **must** be `chmod 0600` (owner read/write only) on POSIX; the
server refuses to load any looser permissions.

```json
{
  "default": "contoso",
  "tenants": {
    "contoso": {
      "tenant_id": "11111111-1111-1111-1111-111111111111",
      "client_id": "22222222-2222-2222-2222-222222222222",
      "cert_path": "/secrets/contoso.pfx",
      "cert_passphrase_env": "CONTOSO_CERT_PASS",
      "workspace_id": "55555555-5555-5555-5555-555555555555"
    },
    "fabrikam": {
      "tenant_id": "33333333-3333-3333-3333-333333333333",
      "client_id": "44444444-4444-4444-4444-444444444444",
      "cert_path": "/secrets/fabrikam.pfx",
      "workspace_id": "66666666-6666-6666-6666-666666666666"
    }
  }
}
```

Two passphrase patterns are supported per tenant; pick **one**:

- **`cert_passphrase_env`** *(recommended)* — names an environment
  variable that holds the passphrase. The on-disk file never contains the
  secret.
- **`cert_passphrase`** — inline literal. Convenient with `sops`/`age`
  but emits a warning to the audit log. Don't commit it.

### Claude Desktop / Claude Code

Add to your MCP client's config (Claude Desktop:
`claude_desktop_config.json`; Claude Code: `~/.claude.json`).

#### Single tenant

```json
{
  "mcpServers": {
    "sentinel-detection-engine": {
      "command": "uvx",
      "args": ["--from", "mcp-sentinel-detection-engine", "mcp-sentinel-detection-engine"],
      "env": {
        "AZURE_TENANT_ID": "00000000-0000-0000-0000-000000000000",
        "AZURE_CLIENT_ID": "00000000-0000-0000-0000-000000000000",
        "AZURE_CERT_PATH": "/Users/me/.config/mcp-sentinel-detection-engine/app-cert.pfx",
        "SENTINEL_WORKSPACE_ID": "00000000-0000-0000-0000-000000000000"
      }
    }
  }
}
```

#### Multi tenant

```json
{
  "mcpServers": {
    "sentinel-detection-engine": {
      "command": "uvx",
      "args": ["--from", "mcp-sentinel-detection-engine", "mcp-sentinel-detection-engine"],
      "env": {
        "MCP_SENTINEL_TENANTS_FILE": "/etc/mcp-sentinel-detection-engine/tenants.json",
        "CONTOSO_CERT_PASS": "..."
      }
    }
  }
}
```

For the no-credentials offline path (three of the four tools work without
Azure), see [`examples/README.md`](examples/README.md#quickstart-with-claude-desktop).

---

## Security design

**OAuth scopes.** Only one Azure data-plane scope is requested:
`https://api.loganalytics.io/.default`. The Sentinel rule API surface
(create/update/delete) is *not* called by this server — rule deployment
happens out-of-band via `terraform apply` under a separate identity
with elevated permissions, kept off the LLM-facing host.

**Certificate-based auth.** Authentication uses an X.509 certificate
rather than a client secret. The PFX private key never leaves the host;
only the public certificate is uploaded to Azure. Tokens are acquired
via MSAL's certificate-based client-credentials flow, cached in memory
per `(tenant_key, scope)`, and refreshed 60 s before expiry. Nothing is
written to disk.

**Multi-tenant isolation.** Each tenant has its own MSAL app instance,
its own cache entry, and its own bound Log Analytics workspace ID. A
fan-out across N tenants is N parallel calls with N distinct bearer
tokens against N distinct workspace URLs; per-tenant results are
labelled with the *server-provided* `tenant` key (never derived from
upstream JSON).

**Tenants config (when used).** Must be `chmod 0600`. Passphrases are
referenced from environment variables, not stored inline by default.
Workspace IDs are validated as GUIDs at load time. Unknown tenant
lookups never echo the caller-provided key in the error message —
preventing the validator from being used as a tenant-existence oracle.

**Audit log (stderr, JSON lines).**

| Logged                                                | Not logged                  |
| ----------------------------------------------------- | --------------------------- |
| Tool name, timestamp, target tenant(s)                | OAuth access token          |
| Validated/sanitized parameters                        | Certificate passphrase      |
| Duration, success/failure, error code on failure      | PFX file contents           |
| Result *counts* (rows, columns, queries)              | Raw upstream response body  |
| KQL query text (so hunts are reviewable)              | HTTP headers, correlation IDs |
| Per-tenant outcomes during fan-out                    | Returned row contents       |

stdout is reserved for the MCP stdio protocol.

For the full analysis, see [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## Scope & Design Philosophy

`mcp-sentinel-detection-engine` is purpose-built for **detection
engineering** — taking a Sigma rule and shepherding it through
conversion, validation, and Terraform emission. The v0.1.x surface
intentionally includes:

- Converting Sigma rules to Sentinel KQL via pySigma + `azure_monitor`
  pipeline
- Static schema validation against a bundled snapshot
- Read-only live workspace dry-run
- Terraform HCL emission for `azurerm_sentinel_alert_rule_scheduled`

**Out of scope** for v0.1.x and the foreseeable roadmap:

- `terraform apply` — emission only. The apply is a human-gated step
  in a separate pipeline with its own credentials.
- Sentinel rule create / update / delete via the management API.
- Incident triage, alert investigation, threat hunting against
  Sentinel data. Those belong in the companion server
  [`mcp-defender-xdr`](https://github.com/MFisher14/mcp-defender-xdr),
  which has a complementary read-only surface focused on hunting and
  investigation rather than rule authoring. The two servers compose:
  hunt in Defender XDR, then ship a Sigma rule via this server.
- Detection-as-code Git workflow integration (`v0.3`).
- HTTP/SSE transport (`v0.2`); v0.1 is stdio-only.

Keeping the LLM-facing surface read-only against Azure means a
compromise of the model or its prompt cannot cause state changes in
your Sentinel tenant.

---

## Development

```bash
uv pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest --cov --cov-fail-under=80
```

CI runs on every push and PR to `main` against Python 3.11 and 3.12.

---

## Roadmap

See [GitHub Milestones](https://github.com/MFisher14/mcp-sentinel-detection-engine/milestones)
for the current scope of v0.2, v0.3, and future releases.
