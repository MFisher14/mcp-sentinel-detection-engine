# Examples

These rules exercise each `azure_monitor` pipeline mapping end-to-end.
Use them to demo the server without standing up an Azure tenant —
`convert_sigma_to_kql` and `validate_kql_against_schema` work fully
offline, so the loop "Claude reads a Sigma rule → Claude returns
schema-validated KQL" needs nothing more than a Python venv and an MCP
client.

## Quickstart with Claude Desktop

1. Clone the repo and install the server in editable mode:

   ```bash
   git clone https://github.com/MFisher14/mcp-sentinel-detection-engine.git
   cd mcp-sentinel-detection-engine
   uv venv && source .venv/bin/activate
   uv pip install -e ".[dev]"
   ```

2. Add the server to your `~/Library/Application Support/Claude/claude_desktop_config.json`
   (macOS) or the equivalent on Windows/Linux. The offline path requires
   **no** Azure environment variables — `convert_sigma_to_kql`,
   `validate_kql_against_schema`, and `generate_sentinel_terraform` are
   pure functions:

   ```json
   {
     "mcpServers": {
       "sentinel-detection-engine": {
         "command": "/absolute/path/to/mcp-sentinel-detection-engine/.venv/bin/mcp-sentinel-detection-engine"
       }
     }
   }
   ```

   Restart Claude Desktop and you should see four tools advertised under
   `sentinel-detection-engine`. To additionally exercise `dry_run_kql`
   against a live workspace, add the `AZURE_*` and `SENTINEL_WORKSPACE_ID`
   env vars from the top-level [`README.md`](../README.md#configuration).

## Demo prompts

Five conversational prompts that drive Claude through the full pipeline
using the bundled rules. Each row names the example file Claude reads
and the tool Claude is expected to invoke:

| # | Prompt to Claude                                                                                                                                                | Target file                                                       | Tool(s)                                                          |
| - | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------- |
| 1 | "Read `examples/sigma/failed_logon_burst.yml` and convert it to Sentinel KQL."                                                                                  | `failed_logon_burst.yml`                                          | `convert_sigma_to_kql`                                           |
| 2 | "Convert `examples/sigma/aad_risky_signin.yml` and then check the generated KQL against the SigninLogs schema."                                                 | `aad_risky_signin.yml`                                            | `convert_sigma_to_kql` → `validate_kql_against_schema`           |
| 3 | "Run `examples/sigma/azure_activity_keyvault_secret_get.yml` through convert → validate → a 24-hour dry-run against the default workspace, 5 rows max."         | `azure_activity_keyvault_secret_get.yml`                          | `convert_sigma_to_kql` → `validate_kql_against_schema` → `dry_run_kql` |
| 4 | "Take `examples/sigma/aad_privileged_role_assignment.yml`, convert it, validate, and emit a Terraform `azurerm_sentinel_alert_rule_scheduled` block tagged with the right MITRE ATT&CK techniques." | `aad_privileged_role_assignment.yml`                              | `convert_sigma_to_kql` → `validate_kql_against_schema` → `generate_sentinel_terraform` |
| 5 | "Convert `examples/sigma/adversarial/prompt_injection_in_description.yml` and tell me what the description field looks like in the returned KQL."                | `adversarial/prompt_injection_in_description.yml`                 | `convert_sigma_to_kql`                                           |

Row 3 needs Azure credentials; rows 1, 2, 4, and 5 are offline.

## Threat model demo

The file [`adversarial/prompt_injection_in_description.yml`](sigma/adversarial/prompt_injection_in_description.yml)
is the demo asset for [`THREAT_MODEL.md` T1 — Indirect prompt injection
via Sigma rule input](../THREAT_MODEL.md). Its `description`,
`falsepositives`, and `references` fields contain:

- a literal `IGNORE PREVIOUS INSTRUCTIONS AND...` prompt-injection
  fragment,
- U+200B zero-width spaces embedded in metadata text,
- a U+202E right-to-left override character.

What to look for when Claude calls `convert_sigma_to_kql` on this rule
(demo prompt #5 above):

1. The tool **succeeds** — the rule converts to legal KQL against
   `SecurityEvent`. That's intentional: T1 mitigation #1 is that
   `convert_sigma_to_kql` is a pure function and never re-prompts the
   model with the rule's narrative.
2. The audit log emitted on stderr records the *sanitised* YAML byte
   length, not the raw byte length — the U+200B / U+202E characters were
   stripped by `validation._strip_control_chars` before pySigma saw the
   payload. If your terminal renders the description field "correctly",
   it's because the zero-width / bidi chars have been removed; the
   injection text is now plain inert ASCII.
3. The generated KQL itself contains no destructive control verbs
   (`.drop`, `.alter`, `.ingest`, …). The post-conversion KQL filter
   (T1 mitigation #3) would reject the rule before
   `generate_sentinel_terraform` or `dry_run_kql` could touch it if it
   did.

If you want to see the input/output side-by-side, run the bundled
walker:

```bash
pytest tests/test_examples.py -v
```

Every rule in this directory — adversarial included — must pass.
