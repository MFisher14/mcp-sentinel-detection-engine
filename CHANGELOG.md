# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Known transitive vulnerability in `diskcache` (≤5.6.3, CVE-2025-69872):
  pickle-based serialisation can enable RCE for an attacker who already
  has local write access to the cache directory. Pulled in via
  `pysigma`'s parsed-rule cache. No fixed upstream version is published.
  The pip-audit CI job allow-lists this CVE explicitly; revisit when a
  fix lands or `pysigma` migrates off `diskcache`. Tracked for v0.2.

## [0.1.0] - 2026-05-12

Initial release. An MCP server, stdio-only, exposing the Sigma → KQL →
validate → Terraform detection-engineering loop as four tools. Three of
the four are pure functions, so the full authoring loop runs with **no
Azure credentials**; only `dry_run_kql` needs a tenant.

### Added

#### Tools

- **`convert_sigma_to_kql`** — convert a Sigma rule to Sentinel KQL via
  pySigma and `pysigma-backend-kusto`'s `azure_monitor` pipeline. Accepts
  either inline `sigma_yaml` or a `sigma_path` (exactly one, never both).
  Windows logsources auto-map to `SecurityEvent`; cloud logsources
  (`signinlogs`, `auditlogs`, `officeactivity`, `azureactivity`,
  `commonsecuritylog`, `syslog`) take an explicit `target_table`. Returns
  every generated query with its resolved target table and any backend
  warnings. Pure function — no Azure auth.
- **`validate_kql_against_schema`** — statically check the columns a query
  references against a bundled Log Analytics schema snapshot (13 tables,
  captured 2026-05-12). Returns `valid`, the `unknown_columns` list, and
  `difflib`-derived `suggestions` for each miss (`LogonTpye` →
  `LogonType`), so a typo is caught before it costs a workspace
  round-trip. Pure function — no Azure auth. v0.2 will fetch the live
  schema via the Log Analytics metadata API.
- **`dry_run_kql`** — smoke-test a query against a real Sentinel
  workspace, read-only by construction: `row_limit` capped at 10, a
  60-second server timeout, queries over 10,000 chars rejected, and
  destructive KQL control verbs (`.drop`, `.alter`, `.ingest`,
  `.external_table`, `.purge`, …) refused before any HTTP call. The only
  tool that needs Azure credentials.
- **`generate_sentinel_terraform`** — emit an
  `azurerm_sentinel_alert_rule_scheduled` block from a validated query
  plus rule metadata (severity, ISO-8601 frequency/period, trigger
  operator and threshold, MITRE ATT&CK tactics and techniques). The HCL
  references `var.log_analytics_workspace_id` so one module applies to any
  workspace, and the resource GUID is derived server-side from a stable
  namespace UUID rather than caller input. Emission only — `terraform
  apply` stays a human-gated step under separate credentials. Pure
  function — no Azure auth.

#### Tenancy and auth

- MSAL certificate client-credentials authentication (X.509, not a client
  secret), with an in-memory per-`(tenant_key, scope)` token cache
  refreshed 60 s before expiry. Nothing written to disk.
- Single-tenant configuration via `AZURE_*` / `SENTINEL_WORKSPACE_ID`
  environment variables, or multi-tenant via a `chmod 0600` JSON config
  file. Startup fails fast with exit code 2 on a missing or malformed
  variable.
- Multi-tenant fan-out (`tenant: "*"`) with bounded concurrency, default
  5. Results are labelled with the server-side tenant key, never one
  derived from an upstream response, and one failing tenant does not
  poison the rest.

#### Safety and observability

- Every tool input is parsed and validated before use; HCL emission
  escapes caller-supplied strings against injection.
- JSON-lines audit log on stderr recording tool name, tenant, sanitised
  parameters, duration, outcome, and result counts — never tokens,
  passphrases, certificate contents, or returned row data. stdout is
  reserved for the MCP stdio protocol.
- 405-line threat model (`THREAT_MODEL.md`) covering T1–T7 with named
  code locations and the test cases that exercise each mitigation.

#### Examples and quality

- Seven example Sigma rules under `examples/sigma/` covering each
  `azure_monitor` pipeline mapping, including an adversarial rule that
  carries a prompt-injection payload, zero-width spaces, and a bidi
  override as the demo asset for threat-model T1.
- 143 tests at 86% coverage; `ruff` and `mypy --strict` clean on Python
  3.11 and 3.12.

[Unreleased]: https://github.com/MFisher14/mcp-sentinel-detection-engine/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MFisher14/mcp-sentinel-detection-engine/releases/tag/v0.1.0
