# Recording the pipeline demo

The asset this directory holds is the one thing the README cannot say in
prose: the full **Sigma → KQL → validate → Terraform** loop running in
Claude Desktop, start to finish, **with no Azure credentials**. Three of
the four tools are pure functions, so the whole demo is reproducible on
any machine with a clone and a Python 3.11+ venv — no tenant, no
workspace, no certificate.

- **Asset:** `docs/demo/sentinel-detection-loop.gif`
- **Runtime:** about 50–70 seconds at a readable pace
- **Rules used:** `examples/sigma/failed_logon_burst.yml` (bundled)

---

## 1. Setup

Install from source and wire the server into Claude Desktop with the
no-credentials snippet:

```bash
git clone https://github.com/MFisher14/mcp-sentinel-detection-engine.git
cd mcp-sentinel-detection-engine
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pwd   # note this absolute path — the script below needs it
```

```json
{
  "mcpServers": {
    "sentinel-detection-engine": {
      "command": "/absolute/path/to/mcp-sentinel-detection-engine/.venv/bin/mcp-sentinel-detection-engine"
    }
  }
}
```

Restart Claude Desktop. You should see four tools under
`sentinel-detection-engine`. Deliberately set **no** `AZURE_*` variables
— an empty `env` is the point of the demo.

Before recording, start a **fresh chat** so no prior context is visible,
and confirm the loop once off-camera. `convert_sigma_to_kql` reads the
rule file itself, server-side, so you do **not** need a filesystem MCP
server — but `sigma_path` must be **absolute**.

---

## 2. Script

Four turns. Type each prompt verbatim, substituting your clone's
absolute path for `<REPO>`. Wait for each tool card to finish rendering
before typing the next one.

### Turn 1 — convert

> Convert the Sigma rule at
> `<REPO>/examples/sigma/failed_logon_burst.yml` to Sentinel KQL.

Claude calls **`convert_sigma_to_kql`**. Expect exactly:

```kusto
SecurityEvent
| where EventID == 4625 and LogonType == 3
```

The rule's Windows logsource auto-maps to `SecurityEvent`, so no
`target_table` is needed — worth saying aloud in a voiced version.

### Turn 2 — validate, and catch the typo

The misspelling is the point of this beat: `LogonTpye` for `LogonType`.

> I hand-edited that query and I think I fluffed a column name. Validate
> this against the SecurityEvent schema:
> `SecurityEvent | where EventID == 4625 and LogonTpye == 3`

Claude calls **`validate_kql_against_schema`**. Expect:

```json
{
  "valid": false,
  "table": "SecurityEvent",
  "unknown_columns": ["LogonTpye"],
  "suggestions": {"LogonTpye": ["LogonType"]},
  "metadata": {"schema_column_count": 42, "referenced_column_count": 2}
}
```

This is the money frame: the typo is caught and the correction proposed
offline, against the bundled schema snapshot, with no workspace
round-trip.

### Turn 3 — confirm the fix

> Fix it and re-validate.

Expect `"valid": true` with an empty `unknown_columns`. Short beat, but
it closes the loop — without it the viewer only sees a failure.

### Turn 4 — emit Terraform

> Now emit the Terraform for the corrected query. Call it
> `failed_logon_burst`, severity Medium, run it every 10 minutes over a
> 10-minute window, fire above 5 hits, and tag it with the ATT&CK tactic
> and techniques from the original rule.

Claude calls **`generate_sentinel_terraform`**. Expect an
`azurerm_sentinel_alert_rule_scheduled` block:

```hcl
resource "azurerm_sentinel_alert_rule_scheduled" "failed_logon_burst" {
  log_analytics_workspace_id = var.log_analytics_workspace_id
  name                       = "451cffdc-964c-56d3-8595-ff4a5897f187"
  display_name               = "Failed Network Logon Burst"
  severity                   = "Medium"
  query_frequency            = "PT10M"
  query_period               = "PT10M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 5
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110", "T1110.001"]
  query                      = <<-EOT
    SecurityEvent
    | where EventID == 4625 and LogonType == 3
  EOT
}
```

The rule GUID is derived server-side from a stable namespace UUID hashed
against the rule name, so it reproduces byte-for-byte on any machine —
handy, because it means the recording matches what a viewer gets.

End the recording on this block. Let it sit on screen for ~2 seconds so
the last frame is readable in the GIF's paused state.

---

## 3. Capture

**Record video first, convert to GIF second.** Direct-to-GIF screen
recorders produce files several times larger at the same visual quality.

### Window and legibility

GitHub renders README images at roughly **880 px** wide and does not let
the reader zoom. Legibility at that width is the whole constraint:

| Setting            | Value                                                        |
| ------------------ | ------------------------------------------------------------ |
| Capture region     | Just the Claude Desktop chat pane — crop the OS chrome away  |
| Capture size       | 1280×800 logical px (a Retina/HiDPI grab is fine, it downscales cleanly) |
| Claude Desktop zoom| **Cmd/Ctrl-+ two or three times.** Overshoot rather than under |
| Appearance         | Either theme; dark hides JPEG-ish GIF banding slightly better |
| Hide               | Notifications, other tabs, anything with your name or a tenant ID in it |

Sanity check before you invest in a take: screenshot one frame, scale it
to 880 px wide, and read it at 100%. If the KQL is a struggle, raise the
zoom and redo it — no amount of encoding rescues text that is too small.

### Recording

```bash
# macOS — Cmd-Shift-5, "Record Selected Portion", or headless:
screencapture -v -R 0,0,1280,800 /tmp/demo-raw.mov

# Linux (X11 or XWayland)
ffmpeg -f x11grab -framerate 30 -video_size 1280x800 -i :0.0+0,0 /tmp/demo-raw.mp4
```

Record at 30 fps and drop frames during encoding — it is far easier than
recovering smoothness from a choppy source.

### Trim the dead air

Model latency between turns is the single biggest driver of file size.
Cut every gap down to about a second:

```bash
# Keep 4s-52s, then cut the two longest thinking pauses.
ffmpeg -i /tmp/demo-raw.mov -ss 4 -to 52 -c copy /tmp/demo-trimmed.mp4
```

A tighter alternative to hand-trimming: speed the whole thing up ~1.5×
with `-filter:v "setpts=PTS/1.5"` and leave the reading beats alone.

---

## 4. Encode the GIF

Two-pass palette generation. A single-pass `ffmpeg -i in.mp4 out.gif`
uses a fixed 216-colour web palette and looks visibly worse at a *larger*
size:

```bash
# Pass 1 — build a palette from the actual frames.
ffmpeg -i /tmp/demo-trimmed.mp4 \
  -vf "fps=10,scale=1000:-1:flags=lanczos,palettegen=max_colors=128:stats_mode=diff" \
  -y /tmp/palette.png

# Pass 2 — apply it.
ffmpeg -i /tmp/demo-trimmed.mp4 -i /tmp/palette.png \
  -lavfi "fps=10,scale=1000:-1:flags=lanczos[v];[v][1:v]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle" \
  -y docs/demo/sentinel-detection-loop.gif

# Squeeze further — usually another 30-50%, with no visible loss at --lossy=60.
gifsicle -O3 --lossy=60 --colors 128 \
  docs/demo/sentinel-detection-loop.gif \
  -o docs/demo/sentinel-detection-loop.gif

ls -lh docs/demo/sentinel-detection-loop.gif
```

Why these values:

- **`fps=10`** — screen text has no motion blur to hide judder, and 10
  fps reads fine for typing and card reveals. 8 is acceptable; below that
  the cursor stutters distractingly.
- **`scale=1000`** — slightly above GitHub's ~880 px render width, so the
  downscale stays sharp on HiDPI displays without paying for 1280.
- **`max_colors=128`** — a chat UI is flat colour and text. 128 is
  generous; try 96 if you are over budget.
- **`stats_mode=diff`** — weights the palette toward the pixels that
  actually change, which for a mostly-static chat pane is the text.
- **`dither=bayer:bayer_scale=3`** — ordered dithering compresses far
  better than the default Floyd–Steinberg, which adds per-frame noise
  that inflates a GIF badly.

### Staying under 10 MB

Budget target is **≤ 8 MB**, leaving headroom under GitHub's 10 MB
rendering limit. In descending order of effect:

| If you are over  | Do this first                                             |
| ---------------- | --------------------------------------------------------- |
| by a lot (>15 MB)| Trim harder — cut latency gaps, not content                |
| moderately       | `fps=10` → `8`                                             |
| moderately       | `--lossy=60` → `80`                                        |
| slightly         | `max_colors=128` → `96`                                    |
| last resort      | `scale=1000` → `880`                                       |

Drop resolution last: it is the one lever that directly costs legibility,
which is the thing the asset exists to provide.

If you cannot get under budget without the text going soft, split it into
two GIFs (convert+validate, then Terraform) rather than shipping one
unreadable file. An `.mp4` uploaded through GitHub's web composer is
another option, but it will not render in a cloned or mirrored README,
which is why the committed asset is a GIF.

---

## 5. Placement and embed

Commit the GIF to `docs/demo/sentinel-detection-loop.gif` — beside this
guide, out of the repository root.

It is embedded near the top of [`README.md`](../../README.md), directly
above the table of contents:

```markdown
## Demo

![Claude Desktop driving convert_sigma_to_kql, validate_kql_against_schema, and generate_sentinel_terraform against a bundled Sigma rule, with no Azure credentials configured](docs/demo/sentinel-detection-loop.gif)

*Sigma → KQL → schema validation → Terraform, driven from Claude Desktop
against the bundled `examples/sigma/failed_logon_burst.yml`.
`validate_kql_against_schema` catches the misspelled `LogonTpye` and
proposes `LogonType` offline; `generate_sentinel_terraform` emits the
`azurerm_sentinel_alert_rule_scheduled` block. **No Azure credentials** —
three of the four tools are pure functions. Reproduce it with
[the recording script](docs/demo/README.md).*
```

Use a repo-relative path, not a `raw.githubusercontent.com` URL, so the
image survives forks and shows up in local Markdown previews. Keep the
alt text descriptive: it is what screen-reader users and anyone with
images disabled get instead of the entire demo.
