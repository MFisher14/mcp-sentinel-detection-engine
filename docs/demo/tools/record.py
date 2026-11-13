"""Drive a real interactive Claude Code session in a pty and record it as asciicast v2."""
import json, os, sys, time
import pexpect

out_path, prompt = sys.argv[1], sys.argv[2]
W, H = 110, int(os.environ.get("REC_H", "46"))
env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
env.update(TERM="xterm-256color", COLUMNS=str(W), LINES=str(H))
cmd = [
    "--mcp-config", sys.argv[3], "--strict-mcp-config",
    "--allowedTools", "mcp__sentinel__convert_sigma_to_kql", "mcp__sentinel__validate_kql_against_schema",
    "mcp__sentinel__dry_run_kql", "mcp__sentinel__generate_sentinel_terraform", "Read",
    "--disallowedTools", "Bash", "--verbose",
]
child = pexpect.spawn("claude", cmd, env=env, dimensions=(H, W), encoding="utf-8", cwd=sys.argv[4])
events = []
start = time.time()

def pump(seconds, until_idle=None):
    end = time.time() + seconds
    last = time.time()
    while time.time() < end:
        try:
            data = child.read_nonblocking(65536, timeout=0.05)
            events.append([time.time() - start, "o", data]); last = time.time()
        except pexpect.TIMEOUT:
            if until_idle and time.time() - last > until_idle:
                return
        except pexpect.EOF:
            return

pump(8, until_idle=3)
for ch in prompt:
    child.send(ch); pump(0.02)
pump(0.5)
child.send("\r")
pump(300, until_idle=12)
child.sendcontrol("c"); pump(1); child.sendcontrol("c"); pump(2)
header = {"version": 2, "width": W, "height": H, "timestamp": int(start),
          "env": {"TERM": "xterm-256color", "SHELL": "/bin/zsh"}}
with open(out_path, "w") as f:
    f.write(json.dumps(header) + "\n")
    for e in events:
        f.write(json.dumps(e) + "\n")
print("events", len(events), "duration", round(events[-1][0], 1))
