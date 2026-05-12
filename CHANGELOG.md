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

### Added

- Initial release. Four MCP tools: `convert_sigma_to_kql`,
  `validate_kql_against_schema`, `dry_run_kql`, `generate_sentinel_terraform`.
- pySigma + `pysigma-backend-kusto` (`azure_monitor` pipeline) for Sigma → KQL
  conversion.
- MSAL certificate-credentials authentication with per-tenant token cache.
- Multi-tenant fan-out with bounded concurrency.
- HCL-injection-safe Terraform emission for `azurerm_sentinel_alert_rule_scheduled`.
- 405-line threat model (`THREAT_MODEL.md`) covering T1–T7 with named code
  locations and test cases.
- 135 tests, 86% coverage. `ruff` + `mypy --strict` clean.

[Unreleased]: https://github.com/MFisher14/mcp-sentinel-detection-engine/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MFisher14/mcp-sentinel-detection-engine/releases/tag/v0.1.0
