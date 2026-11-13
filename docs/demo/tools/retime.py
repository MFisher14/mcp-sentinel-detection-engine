"""Compress the prompt-typing span of a cast, then hold on the finished prompt.

usage: retime.py in.cast out.cast TYPE_START SUBMIT TYPE_SECONDS HOLD_SECONDS

Events in [TYPE_START, SUBMIT) are squeezed into TYPE_SECONDS; the event at
SUBMIT (Claude echoing the sent prompt) lands HOLD_SECONDS after the last
keystroke, and everything after it shifts by the same amount.
"""
import json, sys

src, dst = sys.argv[1], sys.argv[2]
start, submit, type_s, hold_s = map(float, sys.argv[3:7])
lines = open(src).read().splitlines()
evs = [json.loads(l) for l in lines[1:]]
typing = [e for e in evs if start <= e[0] < submit]
span = typing[-1][0] - start
scale = type_s / span
new_submit = start + type_s + hold_s
shift = new_submit - submit
for e in evs:
    if start <= e[0] < submit:
        e[0] = round(start + (e[0] - start) * scale, 4)
    elif e[0] >= submit:
        e[0] = round(e[0] + shift, 4)
with open(dst, "w") as f:
    f.write(lines[0] + "\n")
    for e in evs:
        f.write(json.dumps(e) + "\n")
print(f"typing {span:.1f}s -> {type_s}s, hold {hold_s}s, total {evs[-1][0]:.1f}s")
