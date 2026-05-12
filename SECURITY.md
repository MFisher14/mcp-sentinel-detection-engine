# Security Policy

`mcp-sentinel-detection-engine` is a security tool. We take vulnerability
reports seriously and aim to acknowledge and remediate them quickly.
Thank you for taking the time to disclose responsibly.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

Older pre-release versions are not supported. Always upgrade to the
latest 0.1.x before reporting.

## Reporting a vulnerability

Please use one of the channels below. **Do not** open a public GitHub
issue for security reports.

1. **GitHub Private Vulnerability Reporting** (preferred):
   [Open a private report](https://github.com/MFisher14/mcp-sentinel-detection-engine/security/advisories/new).
   Keeps the report end-to-end on GitHub and links cleanly to a future
   security advisory.
2. **Email**: `mbf@maximusfisher.com` with subject prefix
   `[security] mcp-sentinel-detection-engine`.

PGP is not currently offered; use the GitHub channel if you need
transport encryption.

### What to include

- A clear description of the vulnerability and its impact.
- A minimal reproducer (proof-of-concept Sigma rule, KQL, config, or
  steps).
- Affected version(s) — output of `mcp-sentinel-detection-engine
  --version` or the installed package version.
- Suggested remediation, if you have one.

### Response targets

- **Acknowledgement**: within 72 hours.
- **Initial assessment**: within 7 days.
- **Fix or mitigation timeline**: communicated with the initial
  assessment.

These are commitments for a solo maintainer; we aim to beat them.

## Coordinated disclosure

- Default disclosure window is **90 days** from acknowledgement, or on
  release of a fix — whichever comes first.
- Researchers will be credited in the release notes and the GitHub
  Security Advisory unless they request otherwise.

## Out of scope

The following are explicitly out of scope and should be reported
elsewhere:

- Vulnerabilities in the upstream **Azure Log Analytics query API**,
  **Microsoft Sentinel**, **pySigma**, or the
  **`pysigma-backend-kusto`** translator — report to
  [MSRC](https://msrc.microsoft.com/) or the relevant upstream project.
- Attacks requiring an already-compromised local user account on the
  host machine. This is acknowledged as a residual risk in the threat
  model (see [`THREAT_MODEL.md`](./THREAT_MODEL.md) actor A3 — host
  co-tenant).
- Social-engineering attacks against the maintainer.
- Findings from automated scanners with no demonstrated exploit path.

## Threat model

For a full enumeration of in-scope threats, attacker capabilities, and
existing mitigations, see [`THREAT_MODEL.md`](./THREAT_MODEL.md). New
reports are most useful when they map to (or expand) a threat in that
document.
